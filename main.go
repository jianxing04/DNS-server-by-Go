package main

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coocood/freecache"
	_ "github.com/go-sql-driver/mysql"
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
	LocalCacheSize   = 100 * 1024 * 1024
	WriteQueueSize   = 50000
)

var upstreamList = []string{
	"127.0.0.1:5300",
	// "114.114.114.114:53",
	// "223.5.5.5:53",
	// "119.29.29.29:53",
}

// ================= 全局组件 =================
var (
	bufferPool = sync.Pool{
		New: func() interface{} { buf := make([]byte, MaxDNSPacketSize); return &buf },
	}
	activeWorkers   int32
	jobQueue        chan *Request
	globalRules     atomic.Value // 【全新核心】无锁安全规则引擎
	localCache      *freecache.Cache
	rdb             *redis.Client
	requestGroup    singleflight.Group
	cacheWriteQueue chan CacheWriteTask
	domainStatsMap  sync.Map
	db              *sql.DB
)

// ================= 数据结构 =================
type Request struct {
	Data   []byte
	Length int
	Addr   *net.UDPAddr
}

type CacheWriteTask struct {
	Key string
	Raw []byte
	TTL time.Duration
}

// 【新增】安全规则集：包含三道防线
type SecurityRules struct {
	ClientIPBlocker *IPBlockTrie        // 防线1: 客户端 IP 拦截
	DomainBlocker   map[string]struct{} // 防线2: 恶意域名拦截 (使用哈希表达到 O(1) 极速匹配)
	TargetIPBlocker *IPBlockTrie        // 防线3: 解析结果目标 IP 拦截
}

// IPBlockTrie (字典树实现保持不变)
type TrieNode struct {
	children [2]*TrieNode
	isBlock  bool
}
type IPBlockTrie struct{ root *TrieNode }

func NewIPBlockTrie() *IPBlockTrie { return &IPBlockTrie{root: &TrieNode{}} }

func (t *IPBlockTrie) Insert(cidr string) error {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	if ip == nil {
		ip = net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid IP")
		}
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
	// 初始化一个空的安全规则防止空指针
	emptyRules := &SecurityRules{
		ClientIPBlocker: NewIPBlockTrie(),
		DomainBlocker:   make(map[string]struct{}),
		TargetIPBlocker: NewIPBlockTrie(),
	}
	globalRules.Store(emptyRules)

	go syncRulesFromMySQL() // 启动后台规则同步协程
	// 初始化 MySQL 连接池
	var err error
	dsn := "root:wjxmhcjlyAzg04@tcp(127.0.0.1:3306)/dns_relay?charset=utf8mb4&parseTime=True&loc=Local"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("MySQL 连接失败: %v", err)
	}
	db.SetMaxOpenConns(50) // 设置最大连接数
	db.SetMaxIdleConns(10) // 设置最大空闲连接数

	go asyncStatsFlusher() // 启动访问量定时刷盘引擎

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

// asyncStatsFlusher 每隔 10 秒收集一次内存增量，并写入数据库
func asyncStatsFlusher() {
	ticker := time.NewTicker(10 * time.Second)

	for range ticker.C {
		// 存储这 10 秒内的增量快照
		snapshot := make(map[string]int64)

		// 1. 遍历并提取内存数据
		domainStatsMap.Range(func(key, value interface{}) bool {
			domain := key.(string)
			countPtr := value.(*int64)

			// 【神来之笔】：原子性地将值提取出来，并瞬间把内存中的计数器重置为 0！
			// 这样就不会漏掉 Worker 协程还在不断写入的新请求
			delta := atomic.SwapInt64(countPtr, 0)

			if delta > 0 {
				snapshot[domain] = delta
			}
			return true // 继续遍历
		})

		// 2. 如果这 10 秒内有数据，执行批量入库
		if len(snapshot) > 0 {
			flushToMySQL(snapshot)
		}
	}
}

// flushToMySQL 执行批量 Upsert 写入
// flushToMySQL 真实的极速批量写入落库
func flushToMySQL(snapshot map[string]int64) {
	if len(snapshot) == 0 {
		return
	}

	// 获取当前时间和归属的小时
	now := time.Now()
	statDate := now.Format("2006-01-02")
	statHour := now.Hour()

	// 准备拼接巨大的批量 SQL
	query := "INSERT INTO dns_domain_stats (domain, stat_date, stat_hour, access_count) VALUES "
	var vals []interface{}

	// 为了高效拼接，预计算占位符
	placeholders := make([]string, 0, len(snapshot))

	for domain, count := range snapshot {
		placeholders = append(placeholders, "(?, ?, ?, ?)")
		vals = append(vals, domain, statDate, statHour, count)
	}

	// 将占位符拼接到主 SQL 中
	query += strings.Join(placeholders, ",")

	// 【核心绝技】：ON DUPLICATE KEY UPDATE 解决并发冲突
	// 如果库里没有这个域名这个小时的记录，就 INSERT；如果有，就在原有的数值上累加！
	query += " ON DUPLICATE KEY UPDATE access_count = access_count + VALUES(access_count)"

	// 执行真正的落库操作
	_, err := db.Exec(query, vals...)
	if err != nil {
		log.Printf("⚠️ 批量写入 MySQL 失败: %v", err)
		return
	}

	log.Printf("📈 成功将 %d 个域名的增量访问数据合并刷入 MySQL！", len(snapshot))
}

// 【核心优化】定时从数据库拉取启用的规则，并在内存中完成原子替换
func syncRulesFromMySQL() {
	for {
		// 1. 在后台创建一个全新的规则集 (此时完全不影响前端 Worker 处理请求)
		newRules := &SecurityRules{
			ClientIPBlocker: NewIPBlockTrie(),
			DomainBlocker:   make(map[string]struct{}),
			TargetIPBlocker: NewIPBlockTrie(),
		}

		// 2. 模拟从 MySQL 执行 SELECT 语句获取 status = 1 (启用) 的数据
		// 实际开发中：db.Query("SELECT cidr FROM acl_client_ip WHERE status = 1")
		mockClientIPs := []string{"192.168.1.0/24"}               // 防线1数据
		mockDomains := []string{"ads.google.com.", "badguy.net."} // 防线2数据 (注意 DNS 域名最后有根点)
		mockTargetIPs := []string{"10.255.255.254/32"}            // 防线3数据

		// 3. 将数据灌入新规则集
		for _, cidr := range mockClientIPs {
			newRules.ClientIPBlocker.Insert(cidr)
		}
		for _, cidr := range mockTargetIPs {
			newRules.TargetIPBlocker.Insert(cidr)
		}
		for _, domain := range mockDomains {
			// 将域名统一转为小写以实现不区分大小写的精准匹配
			newRules.DomainBlocker[strings.ToLower(domain)] = struct{}{}
		}

		// 4. 【神来之笔】：指针原子替换！
		// 这一瞬间，所有新的网络请求立刻开始使用新规则，旧规则会被 Go 的 GC 自动回收。
		// 这个操作耗时仅几纳秒，完美解决“增删改”导致的并发锁排队问题。
		globalRules.Store(newRules)

		// 假如你修改了数据库，最多等 1 分钟就能生效，且中途无需重启服务器！
		time.Sleep(1 * time.Minute)
	}
}

func asyncCacheWriter() {
	ctx := context.Background()
	for task := range cacheWriteQueue {
		localCache.Set([]byte(task.Key), task.Raw, int(task.TTL.Seconds()))
		rdb.Set(ctx, task.Key, task.Raw, task.TTL)
	}
}

// ================= 网络收发骨架 (略作折叠，保持不变) =================
func main() {
	addr, _ := net.ResolveUDPAddr("udp", ListenAddr)
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()
	initSystem(conn)
	log.Printf("🚀 终极版 DNS 防火墙启动 (三级安全拦截引擎已挂载)，监听 %s", ListenAddr)
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

// ================= 核心处理：三道防线与中继 =================
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

	// 获取当前生效的安全规则集 (只读，完全无锁)
	rules := globalRules.Load().(*SecurityRules)

	// ================= 防线 1: 客户端 IP 拦截 =================
	clientIP := req.Addr.IP.String()
	if rules.ClientIPBlocker.Match(clientIP) {
		// 来源非法，直接丢弃报文不响应，节省带宽
		return
	}

	// ================= 防线 2: 请求域名拦截 =================
	domainLower := strings.ToLower(question.Name.String())
	recordDomainAccess(domainLower)
	if _, exists := rules.DomainBlocker[domainLower]; exists {
		// 命中恶意域名，直接返回 0.0.0.0
		sendBlockedResponse(conn, req.Addr, header, question)
		return
	}

	cacheKey := fmt.Sprintf("%s_%d", question.Name.String(), question.Type)
	idHigh := req.Data[0]
	idLow := req.Data[1]

	// 尝试读取 L1 缓存
	if cachedRaw, err := localCache.Get([]byte(cacheKey)); err == nil {
		fastRelay(conn, req.Addr, cachedRaw, idHigh, idLow)
		return
	}

	// 尝试读取 L2 缓存
	ctxRedis, cancelRedis := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelRedis()
	redisRaw, err := rdb.Get(ctxRedis, cacheKey).Bytes()
	if err == nil {
		fastRelay(conn, req.Addr, redisRaw, idHigh, idLow)
		cacheWriteQueue <- CacheWriteTask{Key: cacheKey, Raw: redisRaw, TTL: 60 * time.Second}
		return
	}

	// 并发竞速回源
	result, err, shared := requestGroup.Do(cacheKey, func() (interface{}, error) {
		return queryUpstreamWithRacing(req.Data[:req.Length])
	})

	if err == nil {
		rawResp := result.([]byte)

		// ================= 防线 3: 目标解析 IP 拦截 =================
		// 虽然我们是字节流转发，但在第一次拿到上游结果时，我们可以快速解析一次判断其 IP
		if isTargetIPBlocked(rawResp, rules.TargetIPBlocker) {
			// 解析出的 IP 是违规的，篡改返回内容为 0.0.0.0 并不要缓存它！
			sendBlockedResponse(conn, req.Addr, header, question)
			return
		}

		fastRelay(conn, req.Addr, rawResp, idHigh, idLow)
		if !shared {
			select {
			case cacheWriteQueue <- CacheWriteTask{Key: cacheKey, Raw: rawResp, TTL: 60 * time.Second}:
			default:
			}
		}
	}
}

// recordDomainAccess 高并发下极速累加访问量
func recordDomainAccess(domain string) {
	// 1. 尝试直接加载已存在的计数器 (绝大多数情况走这条极速路径)
	if v, ok := domainStatsMap.Load(domain); ok {
		atomic.AddInt64(v.(*int64), 1) // 原子+1，完全无锁
		return
	}

	// 2. 如果是第一次访问该域名，初始化一个计数器
	var initCount int64 = 1
	actual, loaded := domainStatsMap.LoadOrStore(domain, &initCount)
	if loaded {
		// 并发情况下，如果其他协程刚刚抢先初始化了，我们就往它初始化的指针上加 1
		atomic.AddInt64(actual.(*int64), 1)
	}
}

// 【新增辅助函数】快速扫描字节流，检查上游返回的 IP 是否在黑名单中
func isTargetIPBlocked(rawResp []byte, targetBlocker *IPBlockTrie) bool {
	var p dnsmessage.Parser
	_, err := p.Start(rawResp)
	if err != nil {
		return false
	}
	p.SkipAllQuestions()

	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if ah.Type == dnsmessage.TypeA { // 目前主要拦截 IPv4
			res, err := p.AResource()
			if err == nil {
				ipStr := net.IP(res.A[:]).String()
				if targetBlocker.Match(ipStr) {
					return true // 命中了目标 IP 黑名单！
				}
			}
		}
		p.SkipAnswer()
	}
	return false
}

// ================= 并发竞速模型与底层响应 (保持不变) =================
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
				return res.raw, nil
			}
			lastErr = res.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

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
