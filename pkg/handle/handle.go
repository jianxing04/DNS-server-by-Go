package handle

import (
	"DNS-server-by-Go/pkg/database"
	"DNS-server-by-Go/pkg/metrics"
	"DNS-server-by-Go/pkg/security"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

const (
	MaxDNSPacketSize = 512
	JobQueueSize     = 1_000
	MinWorkers       = 5
	MaxWorkers       = 100_000
	IdleTimeout      = 10 * time.Minute
)

var (
	jobQueue      chan *Request
	activeWorkers int32
	bufferPool    = sync.Pool{
		New: func() any { buf := make([]byte, MaxDNSPacketSize); return &buf },
	}
	upstreamList = []string{
		"127.0.0.1:8079",
		// "8.8.8.8:53",
		// "8.8.4.4:53",
		// "1.1.1.1:53",
		// "1.0.0.1:53",
	}
	upstreamAddrs []*net.UDPAddr // 预解析的上游地址池
	requestGroup  singleflight.Group
)

// ================= 初始化与预处理 =================
func init() {
	// 预先解析所有上游 UDP 地址，避免每次请求时产生昂贵的系统调用
	for _, addr := range upstreamList {
		if u, err := net.ResolveUDPAddr("udp", addr); err == nil {
			upstreamAddrs = append(upstreamAddrs, u)
		}
	}
}

// ================= 并发竞速模型与底层响应 =================
type racingResult struct {
	raw []byte
	err error
}

// 封装收到的请求，含客户端地址
type Request struct {
	Data   []byte
	Length int
	Addr   *net.UDPAddr
}

func InitWorkerPool(conn *net.UDPConn) {
	jobQueue = make(chan *Request, JobQueueSize)
	for i := 0; i < MinWorkers; i++ {
		spawnWorker(conn)
	}
}

func GetFromPool() *[]byte {
	return bufferPool.Get().(*[]byte)
}

func PutToPool(buf *[]byte) {
	bufferPool.Put(buf)
}

// 向工作队列派发请求
func DispatchRequest(req *Request, conn *net.UDPConn) {
	select {
	case jobQueue <- req:
	default:
		if atomic.LoadInt32(&activeWorkers) < MaxWorkers {
			spawnWorker(conn)
			jobQueue <- req
		} else {
			// 【优化】记录过载导致的丢包
			metrics.IncBlocked("Overload")
			PutToPool(&req.Data)
		}
	}
}

func spawnWorker(conn *net.UDPConn) {
	atomic.AddInt32(&activeWorkers, 1)
	go func() {
		defer atomic.AddInt32(&activeWorkers, -1)

		// 【优化】使用复用的 Timer，避免 time.After() 导致的严重内存泄漏
		idleTimer := time.NewTimer(IdleTimeout)
		defer idleTimer.Stop()

		for {
			select {
			case req := <-jobQueue:
				processRequest(req, conn)

				// 安全地重置 Timer
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C: // 排空 channel 防止阻塞
					default:
					}
				}
				idleTimer.Reset(IdleTimeout)

			case <-idleTimer.C:
				// 闲置超时，主动缩容（保留最低数量的 Worker）
				if atomic.LoadInt32(&activeWorkers) > MinWorkers {
					return
				}
				// 若达到底线，则重置定时器继续存活
				idleTimer.Reset(IdleTimeout)
			}
		}
	}()
}

// ================= 核心处理：三道防线与中继 =================
func processRequest(req *Request, conn *net.UDPConn) {
	// 1. 记录总请求数和处理耗时
	metrics.IncQuery()
	startTime := time.Now()
	defer func() {
		metrics.ObserveDuration(time.Since(startTime).Seconds())
	}()

	defer PutToPool(&req.Data) // 统一使用包封装的方法

	var parser dnsmessage.Parser
	header, err := parser.Start(req.Data[:req.Length])
	if err != nil {
		return
	}
	question, err := parser.Question()
	if err != nil {
		return
	}

	rules := security.GlobalRules.Load().(*security.SecurityRules)

	// ================= 防线 1: 客户端 IP =================
	// 直接获取 4 字节 IP 切片，彻底消灭字符串转换开销
	if clientIP4 := req.Addr.IP.To4(); clientIP4 != nil {
		if rules.ClientIPBlocker.MatchBytes(clientIP4) {
			metrics.IncBlocked("ClientIP")
			return
		}
	}

	// ================= 防线 2: 请求域名 =================
	domainLower := strings.ToLower(question.Name.String())
	database.RecordDomainAccess(domainLower)
	if _, exists := rules.DomainBlocker[domainLower]; exists {
		metrics.IncBlocked("Domain")
		sendBlockedResponse(conn, req.Addr, header, question)
		return
	}

	cacheKey := fmt.Sprintf("%s_%d", question.Name.String(), question.Type)
	idHigh, idLow := req.Data[0], req.Data[1]

	// ================= L1 缓存 =================
	if cachedRaw, err := database.LocalCache.Get([]byte(cacheKey)); err == nil {
		metrics.IncCacheHit("L1")
		fastRelay(conn, req.Addr, cachedRaw, idHigh, idLow)
		return
	}

	// ================= 回源与 L2 (无全局锁的完美版) =================
	result, err, shared := requestGroup.Do(cacheKey, func() (interface{}, error) {
		ctxRedis, cancelRedis := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancelRedis()
		if redisRaw, err := database.GetRedis(ctxRedis, cacheKey); err == nil {
			return redisRaw, nil
		}
		return queryUpstreamWithRacing(req.Data[:req.Length])
	})

	if err == nil {
		rawResp := result.([]byte)

		// 判断是谁命中的，用于打点
		if shared {
			metrics.IncCacheHit("L1") // 被 Singleflight 拦截，算作内存态 L1
		} else {
			metrics.IncCacheHit("Miss")
		}

		// ================= 防线 3: 目标 IP =================
		if security.IsTargetIPBlocked(rawResp, rules.TargetIPBlocker) {
			metrics.IncBlocked("TargetIP")
			sendBlockedResponse(conn, req.Addr, header, question)
			return
		}

		fastRelay(conn, req.Addr, rawResp, idHigh, idLow)
		if !shared {
			select {
			case database.CacheWriteQueue <- database.CacheWriteTask{Key: cacheKey, Raw: rawResp, TTL: 60 * time.Second}:
			default:
			}
		}
	}
}

func queryUpstreamWithRacing(reqData []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	resCh := make(chan racingResult, len(upstreamAddrs))

	// 【优化】遍历预解析的地址池
	for _, targetAddr := range upstreamAddrs {
		go func(target *net.UDPAddr) {
			raw, err := querySingleUpstream(ctx, target, reqData)
			resCh <- racingResult{raw, err}
		}(targetAddr)
	}

	var lastErr error
	for i := 0; i < len(upstreamAddrs); i++ {
		select {
		case res := <-resCh:
			if res.err == nil {
				return res.raw, nil
			}
			lastErr = res.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func querySingleUpstream(ctx context.Context, targetAddr *net.UDPAddr, reqData []byte) ([]byte, error) {
	// 【优化】直接使用已解析的 targetAddr 拨号
	uConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return nil, err
	}
	defer uConn.Close()

	deadline, _ := ctx.Deadline()
	uConn.SetDeadline(deadline)

	_, err = uConn.Write(reqData)
	if err != nil {
		return nil, err
	}

	respData := make([]byte, MaxDNSPacketSize)
	n, _, err := uConn.ReadFromUDP(respData)
	if err != nil {
		return nil, err
	}

	var parser dnsmessage.Parser
	_, err = parser.Start(respData[:n])
	if err != nil {
		return nil, fmt.Errorf("invalid response")
	}
	return respData[:n], nil
}

func fastRelay(conn *net.UDPConn, clientAddr *net.UDPAddr, rawResp []byte, idHigh byte, idLow byte) {
	reply := make([]byte, len(rawResp))
	copy(reply, rawResp)
	reply[0] = idHigh
	reply[1] = idLow
	conn.WriteToUDP(reply, clientAddr)
}

func sendBlockedResponse(conn *net.UDPConn, clientAddr *net.UDPAddr, reqHeader dnsmessage.Header, question dnsmessage.Question) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: reqHeader.ID, Response: true, OpCode: reqHeader.OpCode, RCode: dnsmessage.RCodeSuccess,
	})
	builder.StartQuestions()
	builder.Question(question)
	builder.StartAnswers()
	builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{0, 0, 0, 0}})
	respBytes, _ := builder.Finish()
	conn.WriteToUDP(respBytes, clientAddr)
}
