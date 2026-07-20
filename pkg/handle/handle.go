package handle

import (
	"DNS-server-by-Go/pkg/config"
	"DNS-server-by-Go/pkg/database"
	"DNS-server-by-Go/pkg/metrics"
	"DNS-server-by-Go/pkg/security"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

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

	responseBufPool = sync.Pool{
		New: func() any {
			return make([]byte, MaxDNSPacketSize)
		},
	}

	socketPool     chan *net.UDPConn
	socketPoolSize int

	upstreamAddrs      []*net.UDPAddr
	upstreamTimeout    time.Duration
	requestGroup       singleflight.Group
	racingResultChPool = sync.Pool{
		New: func() any {
			ch := make(chan racingResult, 64)
			return &ch
		},
	}
	racingQueryID atomic.Uint64
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
	raw     []byte
	aIPs    [][4]byte
	ownsRaw bool
}

func (r *upstreamResult) Release() {
	if r != nil && r.ownsRaw && r.raw != nil {
		responseBufPool.Put(r.raw[:cap(r.raw)])
		r.raw = nil
	}
}

type racingResult struct {
	queryID uint64
	raw     []byte
	aIPs    [][4]byte
	err     error
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
	bufPtr := bufferPool.Get().(*[]byte)
	if len(*bufPtr) < MaxDNSPacketSize {
		*bufPtr = make([]byte, MaxDNSPacketSize)
	}
	return bufPtr
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
			metrics.IncBlockedOverload()
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

const maxDNSNameLen = 255

func toLowerASCII(b []byte) {
	for i := range b {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
}

func writeUint16(b []byte, v uint16) int {
	if v == 0 {
		b[0] = '0'
		return 1
	}
	var tmp [5]byte
	n := len(tmp)
	for v > 0 {
		n--
		tmp[n] = byte('0' + v%10)
		v /= 10
	}
	return copy(b, tmp[n:])
}

// encodeCacheKey 将 DNS 域名转为小写，并拼接 "_<type>" 作为缓存 key。
// keyBuf 需要至少 nameLen+6 字节；返回小写域名字符串（用于 map 查找）和缓存 key 长度。
func encodeCacheKey(name dnsmessage.Name, qType dnsmessage.Type, keyBuf []byte) (domainLower string, keyLen int) {
	nameLen := int(name.Length)
	copy(keyBuf, name.Data[:nameLen])
	lowerBytes := keyBuf[:nameLen]
	toLowerASCII(lowerBytes)

	domainLower = string(lowerBytes)

	keyBuf[nameLen] = '_'
	keyLen = nameLen + 1
	keyLen += writeUint16(keyBuf[keyLen:], uint16(qType))
	return
}

// ================= 核心处理：三道防线与中继 =================
func processRequest(req *Request, conn *net.UDPConn) {
	metrics.IncQuery()
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
			metrics.IncBlockedClient()
			return
		}
	}

	var keyBuf [maxDNSNameLen + 6]byte
	domainLower, cacheKeyLen := encodeCacheKey(question.Name, question.Type, keyBuf[:])
	if _, exists := rules.DomainBlocker[domainLower]; exists {
		metrics.IncBlockedDomain()
		sendBlockedResponse(conn, req.Addr, req.Data[:req.Length], header)
		return
	}

	cacheKeyBytes := keyBuf[:cacheKeyLen]
	idHigh, idLow := req.Data[0], req.Data[1]

	// ===== L1 快速路径：跳过 time.Now() 与 duration 指标 =====
	if cachedRaw, err := database.LocalCache.Get(cacheKeyBytes); err == nil {
		metrics.IncCacheHitL1()
		fastRelay(conn, req.Addr, cachedRaw, idHigh, idLow, true)
		return
	}

	// ===== 慢路径：启动计时 =====
	startTime := time.Now()

	// 零拷贝构建 cacheKey string：keyBuf 为栈上数组，在 singleflight 返回前不会被覆盖
	cacheKey := unsafe.String(unsafe.SliceData(cacheKeyBytes), cacheKeyLen)

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
			if v.ownsRaw && !shared {
				defer v.Release()
			}
			for _, ip := range v.aIPs {
				if rules.TargetIPBlocker.MatchBytes(ip[:]) {
					metrics.IncBlockedTarget()
					sendBlockedResponse(conn, req.Addr, req.Data[:req.Length], header)
					return
				}
			}
		case []byte:
			rawResp = v
			if security.IsTargetIPBlocked(rawResp, rules.TargetIPBlocker) {
				metrics.IncBlockedTarget()
				sendBlockedResponse(conn, req.Addr, req.Data[:req.Length], header)
				return
			}
		default:
			return
		}

		if shared {
			metrics.IncCacheHitL1()
		} else {
			metrics.IncCacheHitMiss()
		}

		database.RecordDomainAccess(domainLower)
		fastRelay(conn, req.Addr, rawResp, idHigh, idLow, false)
		if !shared {
			database.SetCache(cacheKey, rawResp, 60*time.Second)
		}
	}

	metrics.ObserveDuration(time.Since(startTime).Seconds())
}

func getRacingResultCh() chan racingResult {
	chPtr := racingResultChPool.Get().(*chan racingResult)
	var ch chan racingResult
	if chPtr == nil {
		ch = make(chan racingResult, 64)
	} else {
		ch = *chPtr
		for len(ch) > 0 {
			<-ch
		}
	}
	return ch
}

func putRacingResultCh(ch chan racingResult) {
	for len(ch) > 0 {
		<-ch
	}
	racingResultChPool.Put(&ch)
}

func queryUpstreamWithRacing(reqData []byte) (*upstreamResult, error) {
	qid := racingQueryID.Add(1)
	deadline := time.Now().Add(upstreamTimeout)
	resCh := getRacingResultCh()
	ctx, cancel := context.WithCancel(context.Background())

	for _, targetAddr := range upstreamAddrs {
		go func(target *net.UDPAddr) {
			res, err := querySingleUpstream(deadline, target, reqData)
			select {
			case <-ctx.Done():
				return
			default:
			}
			if err != nil {
				resCh <- racingResult{queryID: qid, err: err}
				return
			}
			resCh <- racingResult{queryID: qid, raw: res.raw, aIPs: res.aIPs}
		}(targetAddr)
	}

	timer := time.NewTimer(upstreamTimeout)
	defer timer.Stop()

	var lastErr error
	for i := 0; i < len(upstreamAddrs); i++ {
		select {
		case res := <-resCh:
			if res.queryID != qid {
				i--
				continue
			}
			if res.err == nil {
				cancel()
				putRacingResultCh(resCh)
				return &upstreamResult{raw: res.raw, aIPs: res.aIPs}, nil
			}
			lastErr = res.err
		case <-timer.C:
			cancel()
			putRacingResultCh(resCh)
			return nil, fmt.Errorf("upstream timeout")
		}
	}
	cancel()
	putRacingResultCh(resCh)
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

	finalBuf := responseBufPool.Get().([]byte)
	if len(finalBuf) < n {
		finalBuf = make([]byte, n)
	}
	copy(finalBuf, (*respData)[:n])
	return &upstreamResult{raw: finalBuf[:n], aIPs: aIPs, ownsRaw: true}, nil
}

func fastRelay(conn *net.UDPConn, clientAddr *net.UDPAddr, rawResp []byte, idHigh byte, idLow byte, owned bool) {
	if owned {
		rawResp[0] = idHigh
		rawResp[1] = idLow
		conn.WriteToUDP(rawResp, clientAddr)
		return
	}
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

var blockedRespPool = sync.Pool{
	New: func() any {
		return make([]byte, MaxDNSPacketSize)
	},
}

// blockedRespHeaderTemplate 预构建的 DNS 响应头模板（12 字节）。
// 仅 ID 与 OpCode 需要在发送时按请求覆盖。
var blockedRespHeaderTemplate = [12]byte{
	0x00, 0x00, // ID
	0x80, 0x00, // Response=1, OpCode=0, RCode=0
	0x00, 0x01, // QDCOUNT=1
	0x00, 0x01, // ANCOUNT=1
	0x00, 0x00, // NSCOUNT=0
	0x00, 0x00, // ARCOUNT=0
}

// blockedRespAnswerTemplate 预构建的 A 记录 0.0.0.0 答案模板（16 字节），
// 使用压缩指针 0xC00C 指向请求中的 question name。
var blockedRespAnswerTemplate = [16]byte{
	0xc0, 0x0c, // Pointer to question name at offset 12
	0x00, 0x01, // Type A
	0x00, 0x01, // Class IN
	0x00, 0x00, 0x00, 0x3c, // TTL 60
	0x00, 0x04, // RDLENGTH=4
	0x00, 0x00, 0x00, 0x00, // 0.0.0.0
}

func sendBlockedResponse(conn *net.UDPConn, clientAddr *net.UDPAddr, reqData []byte, reqHeader dnsmessage.Header) {
	if conn == nil || len(reqData) < 12 {
		return
	}
	resp := blockedRespPool.Get().([]byte)
	if len(resp) < MaxDNSPacketSize {
		resp = make([]byte, MaxDNSPacketSize)
	}

	copy(resp, blockedRespHeaderTemplate[:])
	resp[0] = reqData[0]
	resp[1] = reqData[1]
	resp[2] = 0x80 | byte(reqHeader.OpCode<<3)

	// 找到 question name 的结束位置（0x00），question 区段总长为 nameLen+5（含 QTYPE/QCLASS）
	qEnd := 12
	for qEnd < len(reqData) && reqData[qEnd] != 0 {
		qEnd++
	}
	qEnd += 5
	if qEnd > len(reqData) || qEnd > MaxDNSPacketSize {
		blockedRespPool.Put(resp[:cap(resp)])
		return
	}

	copy(resp[12:], reqData[12:qEnd])

	off := 12 + (qEnd - 12)
	if off+16 > MaxDNSPacketSize {
		blockedRespPool.Put(resp[:cap(resp)])
		return
	}
	copy(resp[off:], blockedRespAnswerTemplate[:])

	conn.WriteToUDP(resp[:off+16], clientAddr)
	blockedRespPool.Put(resp[:cap(resp)])
}
