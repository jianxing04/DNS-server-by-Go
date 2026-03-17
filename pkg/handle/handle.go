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
	JobQueueSize     = 10_000
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

	// 🔪 【核心优化 2】：Socket 对象池，彻底消灭 DialUDP 系统调用
	socketPool = sync.Pool{
		New: func() any {
			// 预先监听一个随机本地端口，常驻内存复用
			conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			return conn
		},
	}

	upstreamList = []string{
		//"127.0.0.1:8079", // Mock 上游
		"114.114.114.114:53",
		"8.8.8.8:53",
		"1.1.1.1:53",
		"223.5.5.5:53",
	}
	upstreamAddrs []*net.UDPAddr
	requestGroup  singleflight.Group
)

// ================= 初始化与预处理 =================
func init() {
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

// 🔪 【核心优化 1】：完全非阻塞的主干道分发器
func DispatchRequest(req *Request, conn *net.UDPConn) {
	select {
	case jobQueue <- req:
	default:
		// 队列满了，尝试扩容
		if atomic.LoadInt32(&activeWorkers) < MaxWorkers {
			spawnWorker(conn)
		}
		// 扩容后，再次【非阻塞】尝试入队。如果还是满的，果断丢包保全主协程！
		select {
		case jobQueue <- req:
		default:
			metrics.IncBlocked("Overload")
			PutToPool(&req.Data)
		}
	}
}

func spawnWorker(conn *net.UDPConn) {
	atomic.AddInt32(&activeWorkers, 1)
	go func() {
		defer atomic.AddInt32(&activeWorkers, -1)

		idleTimer := time.NewTimer(IdleTimeout)
		defer idleTimer.Stop()

		for {
			select {
			case req := <-jobQueue:
				processRequest(req, conn)

				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(IdleTimeout)

			case <-idleTimer.C:
				if atomic.LoadInt32(&activeWorkers) > MinWorkers {
					return
				}
				idleTimer.Reset(IdleTimeout)
			}
		}
	}()
}

// ================= 核心处理：三道防线与中继 =================
func processRequest(req *Request, conn *net.UDPConn) {
	metrics.IncQuery()
	startTime := time.Now()
	defer func() {
		metrics.ObserveDuration(time.Since(startTime).Seconds())
	}()
	defer PutToPool(&req.Data)

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

	if clientIP4 := req.Addr.IP.To4(); clientIP4 != nil {
		if rules.ClientIPBlocker.MatchBytes(clientIP4) {
			metrics.IncBlocked("ClientIP")
			return
		}
	}

	domainLower := strings.ToLower(question.Name.String())
	database.RecordDomainAccess(domainLower)
	if _, exists := rules.DomainBlocker[domainLower]; exists {
		metrics.IncBlocked("Domain")
		sendBlockedResponse(conn, req.Addr, header, question)
		return
	}

	cacheKey := fmt.Sprintf("%s_%d", question.Name.String(), question.Type)
	idHigh, idLow := req.Data[0], req.Data[1]

	if cachedRaw, err := database.LocalCache.Get([]byte(cacheKey)); err == nil {
		metrics.IncCacheHit("L1")
		fastRelay(conn, req.Addr, cachedRaw, idHigh, idLow)
		return
	}

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

		if shared {
			metrics.IncCacheHit("L1")
		} else {
			metrics.IncCacheHit("Miss")
		}

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
				// 🔪 【核心优化 3】：静默降级，如果不加这一行，建议你在 database 里把 CacheWriteQueue 长度开到 50000
			}
		}
	}
}

func queryUpstreamWithRacing(reqData []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	resCh := make(chan racingResult, len(upstreamAddrs))

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
	// 🔪 使用池化 Socket 发送请求
	uConn := socketPool.Get().(*net.UDPConn)
	defer socketPool.Put(uConn) // 用完务必还回去

	deadline, _ := ctx.Deadline()
	uConn.SetDeadline(deadline)

	_, err := uConn.WriteToUDP(reqData, targetAddr)
	if err != nil {
		return nil, err
	}

	// 🔪 复用内存池接收响应，减少 GC
	respData := GetFromPool()
	defer PutToPool(respData)

	n, _, err := uConn.ReadFromUDP(*respData)
	if err != nil {
		return nil, err
	}

	var parser dnsmessage.Parser
	_, err = parser.Start((*respData)[:n])
	if err != nil {
		return nil, fmt.Errorf("invalid response")
	}

	// 拷贝一份数据返回，因为 respData 马上要归还给 Pool
	finalResp := make([]byte, n)
	copy(finalResp, (*respData)[:n])
	return finalResp, nil
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
