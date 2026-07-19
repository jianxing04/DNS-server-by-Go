package handle

import (
	"DNS-server-by-Go/pkg/config"
	"DNS-server-by-Go/pkg/database"
	"DNS-server-by-Go/pkg/metrics"
	"DNS-server-by-Go/pkg/security"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

const (
	MaxDNSPacketSize = 512
)

var (
	jobQueue      chan *Request
	activeWorkers int32
	workerCfg     config.WorkerConfig

	bufferPool = sync.Pool{
		New: func() any {
			buf := make([]byte, MaxDNSPacketSize)
			return &buf
		},
	}

	relayPool = sync.Pool{
		New: func() any {
			buf := make([]byte, MaxDNSPacketSize)
			return buf
		},
	}

	socketPool     chan *net.UDPConn
	socketPoolSize int

	upstreamAddrs   []*net.UDPAddr
	upstreamTimeout time.Duration
	requestGroup    singleflight.Group
)

func InitSocketPool(size int) {
	socketPoolSize = size
	socketPool = make(chan *net.UDPConn, size)
	for i := 0; i < size/2; i++ {
		conn, err := createSocket()
		if err != nil {
			panic(fmt.Sprintf("预创建 Socket 失败: %v", err))
		}
		socketPool <- conn
	}
}

func createSocket() (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	conn.SetReadBuffer(4096)
	conn.SetWriteBuffer(4096)
	return conn, nil
}

func getSocket() *net.UDPConn {
	select {
	case conn := <-socketPool:
		return conn
	default:
		conn, err := createSocket()
		if err != nil {
			return nil
		}
		return conn
	}
}

func putSocket(conn *net.UDPConn) {
	select {
	case socketPool <- conn:
	default:
		conn.Close()
	}
}

func SetUpstreams(servers []string, timeout time.Duration) {
	upstreamAddrs = nil
	for _, addr := range servers {
		if u, err := net.ResolveUDPAddr("udp", addr); err == nil {
			upstreamAddrs = append(upstreamAddrs, u)
		}
	}
	upstreamTimeout = timeout
}

// ================= 并发竞速模型与底层响应 =================
type upstreamResult struct {
	raw  []byte
	aIPs [][4]byte
}

type racingResult struct {
	raw  []byte
	aIPs [][4]byte
	err  error
}

type Request struct {
	Data   []byte
	Length int
	Addr   *net.UDPAddr
}

var requestPool = sync.Pool{
	New: func() any { return &Request{} },
}

func GetRequest() *Request {
	return requestPool.Get().(*Request)
}

func PutRequest(req *Request) {
	*req = Request{}
	requestPool.Put(req)
}

func InitWorkerPool(conn *net.UDPConn, cfg config.WorkerConfig) {
	workerCfg = cfg
	jobQueue = make(chan *Request, cfg.JobQueueSize)
	for i := 0; i < cfg.MinWorkers; i++ {
		spawnWorker(conn)
	}
}

func GetFromPool() *[]byte {
	return bufferPool.Get().(*[]byte)
}

func PutToPool(buf *[]byte) {
	bufferPool.Put(buf)
}

func DispatchRequest(req *Request, conn *net.UDPConn) {
	select {
	case jobQueue <- req:
	default:
		if atomic.LoadInt32(&activeWorkers) < int32(workerCfg.MaxWorkers) {
			spawnWorker(conn)
		}
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

		idleTimeout := workerCfg.IdleTimeoutDuration()
		idleTimer := time.NewTimer(idleTimeout)
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
				idleTimer.Reset(idleTimeout)

			case <-idleTimer.C:
				if atomic.LoadInt32(&activeWorkers) > int32(workerCfg.MinWorkers) {
					return
				}
				idleTimer.Reset(idleTimeout)
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
	defer PutRequest(req)

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

	nameStr := question.Name.String()
	domainLower := strings.ToLower(nameStr)
	database.RecordDomainAccess(domainLower)
	if _, exists := rules.DomainBlocker[domainLower]; exists {
		metrics.IncBlocked("Domain")
		sendBlockedResponse(conn, req.Addr, header, question)
		return
	}

	cacheKey := nameStr + "_" + strconv.Itoa(int(question.Type))
	idHigh, idLow := req.Data[0], req.Data[1]

	if cachedRaw, err := database.LocalCache.Get([]byte(cacheKey)); err == nil {
		metrics.IncCacheHit("L1")
		fastRelay(conn, req.Addr, cachedRaw, idHigh, idLow)
		return
	}

	result, err, shared := requestGroup.Do(cacheKey, func() (any, error) {
		ctxRedis, cancelRedis := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancelRedis()
		if redisRaw, err := database.GetRedis(ctxRedis, cacheKey); err == nil {
			return redisRaw, nil
		}
		return queryUpstreamWithRacing(req.Data[:req.Length])
	})

	if err == nil {
		var rawResp []byte

		switch v := result.(type) {
		case *upstreamResult:
			rawResp = v.raw
			for _, ip := range v.aIPs {
				if rules.TargetIPBlocker.MatchBytes(ip[:]) {
					metrics.IncBlocked("TargetIP")
					sendBlockedResponse(conn, req.Addr, header, question)
					return
				}
			}
		case []byte:
			rawResp = v
			if security.IsTargetIPBlocked(rawResp, rules.TargetIPBlocker) {
				metrics.IncBlocked("TargetIP")
				sendBlockedResponse(conn, req.Addr, header, question)
				return
			}
		default:
			return
		}

		if shared {
			metrics.IncCacheHit("L1")
		} else {
			metrics.IncCacheHit("Miss")
		}

		fastRelay(conn, req.Addr, rawResp, idHigh, idLow)
		if !shared {
			database.SetCache(cacheKey, rawResp, 60*time.Second)
		}
	}
}

func queryUpstreamWithRacing(reqData []byte) (*upstreamResult, error) {
	deadline := time.Now().Add(upstreamTimeout)
	resCh := make(chan racingResult, len(upstreamAddrs))

	for _, targetAddr := range upstreamAddrs {
		go func(target *net.UDPAddr) {
			res, err := querySingleUpstream(deadline, target, reqData)
			if err != nil {
				resCh <- racingResult{err: err}
				return
			}
			resCh <- racingResult{raw: res.raw, aIPs: res.aIPs}
		}(targetAddr)
	}

	timer := time.NewTimer(upstreamTimeout)
	defer timer.Stop()

	var lastErr error
	for i := 0; i < len(upstreamAddrs); i++ {
		select {
		case res := <-resCh:
			if res.err == nil {
				return &upstreamResult{raw: res.raw, aIPs: res.aIPs}, nil
			}
			lastErr = res.err
		case <-timer.C:
			return nil, fmt.Errorf("upstream timeout")
		}
	}
	return nil, lastErr
}

func querySingleUpstream(deadline time.Time, targetAddr *net.UDPAddr, reqData []byte) (*upstreamResult, error) {
	uConn := getSocket()
	if uConn == nil {
		return nil, fmt.Errorf("获取 Socket 失败")
	}
	defer putSocket(uConn)

	uConn.SetDeadline(deadline)

	_, err := uConn.WriteToUDP(reqData, targetAddr)
	if err != nil {
		return nil, err
	}

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

	// 在验证解析的同时提取 A 记录 IP，避免后续二次解析
	var aIPs [][4]byte
	parser.SkipAllQuestions()
	for {
		ah, err := parser.AnswerHeader()
		if err != nil {
			break
		}
		if ah.Type == dnsmessage.TypeA {
			if res, err := parser.AResource(); err == nil {
				aIPs = append(aIPs, res.A)
			}
		}
		parser.SkipAnswer()
	}

	finalResp := make([]byte, n)
	copy(finalResp, (*respData)[:n])
	return &upstreamResult{raw: finalResp, aIPs: aIPs}, nil
}

func fastRelay(conn *net.UDPConn, clientAddr *net.UDPAddr, rawResp []byte, idHigh byte, idLow byte) {
	reply := relayPool.Get().([]byte)
	if len(reply) < len(rawResp) {
		reply = make([]byte, len(rawResp))
	}
	n := copy(reply, rawResp)
	reply[0] = idHigh
	reply[1] = idLow
	conn.WriteToUDP(reply[:n], clientAddr)
	relayPool.Put(reply)
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
