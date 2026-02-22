package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coocood/freecache"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

// ================= 核心配置项 =================
const (
	MaxDNSPacketSize = 512
	MinWorkers       = 50
	MaxWorkers       = 2000
	IdleTimeout      = 10 * time.Second
	JobQueueSize     = 10000
	ListenAddr       = "0.0.0.0:8053"
	LocalCacheSize   = 100 * 1024 * 1024 // 100MB 本地零 GC 缓存
	WriteQueueSize   = 50000             // 异步写入缓冲队列大小
)

// 竞速组：同时向这三个公共 DNS 发起请求，谁快用谁！
var upstreamList = []string{
	"114.114.114.114:53", // 114
	"223.5.5.5:53",       // 阿里
	"119.29.29.29:53",    // 腾讯
}

// ================= 全局组件 =================
var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, MaxDNSPacketSize)
			return &buf
		},
	}
	activeWorkers     int32
	jobQueue          chan *Request
	globalIPBlacklist atomic.Value
	localCache        *freecache.Cache
	rdb               *redis.Client
	requestGroup      singleflight.Group
	cacheWriteQueue   chan CacheWriteTask
)

// ================= 数据结构 =================
type Request struct {
	Data   []byte
	Length int
	Addr   *net.UDPAddr
}

// CacheWriteTask 异步写入任务：不再只存 IP，而是存完整的 Raw Bytes
type CacheWriteTask struct {
	Key string
	Raw []byte
	TTL time.Duration
}

// ================= IP 字典树 (Trie) 实现 =================
type TrieNode struct {
	children [2]*TrieNode
	isBlock  bool
}
type IPBlockTrie struct{ root *TrieNode }

func (t *IPBlockTrie) Insert(cidr string) error {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	if ip == nil {
		ip = net.ParseIP(cidr)
		ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	}
	ip4 := ip.To4()
	ipInt := binary.BigEndian.Uint32(ip4)
	ones, _ := ipnet.Mask.Size()
	curr := t.root
	for i := 31; i >= 32-ones; i-- {
		bit := (ipInt >> i) & 1
		if curr.children[bit] == nil {
			curr.children[bit] = &TrieNode{}
		}
		curr = curr.children[bit]
	}
	curr.isBlock = true
	return nil
}

func (t *IPBlockTrie) Match(ipStr string) bool {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	ipInt := binary.BigEndian.Uint32(ip)
	curr := t.root
	for i := 31; i >= 0; i-- {
		if curr.isBlock {
			return true
		}
		bit := (ipInt >> i) & 1
		if curr.children[bit] == nil {
			return false
		}
		curr = curr.children[bit]
	}
	return curr.isBlock
}

// ================= 系统初始化 =================
func initSystem(conn *net.UDPConn) {
	globalIPBlacklist.Store(&IPBlockTrie{root: &TrieNode{}})
	go syncBlacklistFromMySQL()

	localCache = freecache.NewCache(LocalCacheSize)
	rdb = redis.NewClient(&redis.Options{Addr: "localhost:6379", Password: "", DB: 0})

	cacheWriteQueue = make(chan CacheWriteTask, WriteQueueSize)
	for i := 0; i < 5; i++ {
		go asyncCacheWriter()
	}

	jobQueue = make(chan *Request, JobQueueSize)
	for i := 0; i < MinWorkers; i++ {
		spawnWorker(conn)
	}
}

func syncBlacklistFromMySQL() {
	for {
		newTrie := &IPBlockTrie{root: &TrieNode{}}
		newTrie.Insert("192.168.1.0/24") // 模拟屏蔽规则 
		globalIPBlacklist.Store(newTrie)
		time.Sleep(1 * time.Minute)
	}
}

// 读写分离：后台协程专门负责持久化写入缓存 
func asyncCacheWriter() {
	ctx := context.Background()
	for task := range cacheWriteQueue {
		localCache.Set([]byte(task.Key), task.Raw, int(task.TTL.Seconds()))
		rdb.Set(ctx, task.Key, task.Raw, task.TTL)
	}
}

// ================= 网络收发骨架 =================
func main() {
	addr, _ := net.ResolveUDPAddr("udp", ListenAddr)
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()

	initSystem(conn)
	log.Printf("🚀 终极版 DNS 中继服务器启动 (原字节中继引擎已挂载)，监听 %s", ListenAddr)

	for {
		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			bufferPool.Put(bufPtr)
			continue
		}
		dispatchRequest(&Request{Data: buf, Length: n, Addr: clientAddr}, conn)
	}
}

func dispatchRequest(req *Request, conn *net.UDPConn) {
	select {
	case jobQueue <- req:
	default:
		if atomic.LoadInt32(&activeWorkers) < MaxWorkers {
			spawnWorker(conn)
			jobQueue <- req
		} else {
			bufferPool.Put(&req.Data)
		}
	}
}

func spawnWorker(conn *net.UDPConn) {
	atomic.AddInt32(&activeWorkers, 1)
	go func() {
		defer atomic.AddInt32(&activeWorkers, -1)
		for {
			select {
			case req := <-jobQueue:
				processRequest(req, conn)
			case <-time.After(IdleTimeout):
				if atomic.LoadInt32(&activeWorkers) > MinWorkers {
					return
				}
			}
		}
	}()
}

// ================= 核心处理：鉴权、级联缓存与防击穿 =================
func processRequest(req *Request, conn *net.UDPConn) {
	defer bufferPool.Put(&req.Data)

	var parser dnsmessage.Parser
	header, err := parser.Start(req.Data[:req.Length])
	if err != nil {
		return
	}
	question, err := parser.Question()
	if err != nil {
		return
	}

	// 1. 无锁极速鉴权
	clientIP := req.Addr.IP.String()
	if globalIPBlacklist.Load().(*IPBlockTrie).Match(clientIP) {
		sendBlockedResponse(conn, req.Addr, header, question)
		return
	}

	// 缓存 Key 组合域名与类型，例如 "google.com._1" (A记录) 或 "google.com._28" (AAAA记录)
	cacheKey := fmt.Sprintf("%s_%d", question.Name.String(), question.Type)

	// 提取当前用户的 Transaction ID
	idHigh := req.Data[0]
	idLow := req.Data[1]

	// 2. L1 缓存极速查询 (FreeCache)
	if cachedRaw, err := localCache.Get([]byte(cacheKey)); err == nil {
		fastRelay(conn, req.Addr, cachedRaw, idHigh, idLow)
		return
	}

	// 3. L2 缓存查询 (Redis)
	ctxRedis, cancelRedis := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelRedis()
	redisRaw, err := rdb.Get(ctxRedis, cacheKey).Bytes()
	if err == nil {
		fastRelay(conn, req.Addr, redisRaw, idHigh, idLow)
		// 读写分离：异步回写到 L1
		cacheWriteQueue <- CacheWriteTask{Key: cacheKey, Raw: redisRaw, TTL: 60 * time.Second}
		return
	}

	// 4. 并发竞速回源查询 (Singleflight 防击穿)
	result, err, shared := requestGroup.Do(cacheKey, func() (interface{}, error) {
		return queryUpstreamWithRacing(req.Data[:req.Length])
	})

	if err == nil {
		rawResp := result.([]byte)
		// 拿到最快的结果后，替换 ID 并极速返回
		fastRelay(conn, req.Addr, rawResp, idHigh, idLow)

		// 只有真正发起请求的那个协程负责触发异步写入任务
		if !shared {
			select {
			case cacheWriteQueue <- CacheWriteTask{Key: cacheKey, Raw: rawResp, TTL: 60 * time.Second}:
			default:
			}
		}
	}
}

// ================= 并发竞速模型 =================
type racingResult struct {
	raw []byte
	err error
}

func queryUpstreamWithRacing(reqData []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel() 

	resCh := make(chan racingResult, len(upstreamList))

	for _, upDNS := range upstreamList {
		go func(targetDNS string) {
			raw, err := querySingleUpstream(ctx, targetDNS, reqData)
			resCh <- racingResult{raw, err}
		}(upDNS)
	}

	var lastErr error
	for i := 0; i < len(upstreamList); i++ {
		select {
		case res := <-resCh:
			if res.err == nil {
				return res.raw, nil // 竞速夺魁！
			}
			lastErr = res.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// 只负责读字节，不做深度解析，完美支持 A/AAAA/MX/TXT 等所有类型
func querySingleUpstream(ctx context.Context, upstreamAddr string, reqData []byte) ([]byte, error) {
	uAddr, err := net.ResolveUDPAddr("udp", upstreamAddr)
	if err != nil {
		return nil, err
	}
	uConn, err := net.DialUDP("udp", nil, uAddr)
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

	// 简单校验 Header 防止缓存无效的服务器错误 (SERVFAIL)
	var parser dnsmessage.Parser
	h, err := parser.Start(respData[:n])
	if err != nil || h.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("invalid response or rcode")
	}

	return respData[:n], nil
}

// ================= 【核心绝技】字节偷天换日 =================
func fastRelay(conn *net.UDPConn, clientAddr *net.UDPAddr, rawResp []byte, idHigh byte, idLow byte) {
	// 必须 Copy 一份！防止并发修改共享缓存中的原始字节切片
	reply := make([]byte, len(rawResp))
	copy(reply, rawResp)
	
	// 替换 Transaction ID 为当前客户端的 ID
	reply[0] = idHigh
	reply[1] = idLow
	
	conn.WriteToUDP(reply, clientAddr)
}

// ================= 黑名单拦截响应构造 =================
func sendBlockedResponse(conn *net.UDPConn, clientAddr *net.UDPAddr, reqHeader dnsmessage.Header, question dnsmessage.Question) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: reqHeader.ID, Response: true, OpCode: reqHeader.OpCode, RCode: dnsmessage.RCodeSuccess,
	})
	builder.StartQuestions()
	builder.Question(question)
	builder.StartAnswers()
	// 如果命中黑名单，强制返回 0.0.0.0
	builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{0, 0, 0, 0}})
	respBytes, _ := builder.Finish()
	conn.WriteToUDP(respBytes, clientAddr)
}