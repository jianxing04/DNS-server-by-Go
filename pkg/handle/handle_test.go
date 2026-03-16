package handle

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ================= 辅助函数：构建标准 DNS 查询包 =================
func buildMockDNSQuery(domain string) []byte {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               1234,
		RecursionDesired: true,
	})
	builder.StartQuestions()
	_ = builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(domain),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	out, _ := builder.Finish()
	return out
}

// ================= 辅助函数：启动本地 Mock DNS 服务器 =================
func startMockDNSServer(t testing.TB) (*net.UDPConn, string) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0") // 分配随机端口
	if err != nil {
		t.Fatalf("无法解析 Mock 地址: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("无法启动 Mock DNS 服务器: %v", err)
	}

	// 启动后台协程，无脑返回一个成功的 DNS 响应
	go func() {
		buf := make([]byte, 512)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // 连接关闭时退出
			}

			// 解析请求并构造伪造响应 (默认返回 1.2.3.4)
			var parser dnsmessage.Parser
			header, _ := parser.Start(buf[:n])
			q, _ := parser.Question()

			respBuilder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
				ID: header.ID, Response: true, RCode: dnsmessage.RCodeSuccess,
			})
			respBuilder.StartQuestions()
			respBuilder.Question(q)
			respBuilder.StartAnswers()
			respBuilder.AResource(
				dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
			)
			respBytes, _ := respBuilder.Finish()
			conn.WriteToUDP(respBytes, clientAddr)
		}
	}()

	return conn, conn.LocalAddr().String()
}

// ================= 1. 功能测试 (Functional Test) =================

// 测试并发竞速回源逻辑
func TestQueryUpstreamWithRacing(t *testing.T) {
	// 1. 启动两个 Mock 服务器模拟上游
	mockConn1, addr1 := startMockDNSServer(t)
	defer mockConn1.Close()
	mockConn2, addr2 := startMockDNSServer(t)
	defer mockConn2.Close()

	// 2. 劫持全局的上游地址配置
	oldAddrs := upstreamAddrs
	defer func() { upstreamAddrs = oldAddrs }() // 测试结束后恢复

	u1, _ := net.ResolveUDPAddr("udp", addr1)
	u2, _ := net.ResolveUDPAddr("udp", addr2)
	upstreamAddrs = []*net.UDPAddr{u1, u2}

	// 3. 构造请求包
	reqData := buildMockDNSQuery("example.com.")

	// 4. 执行测试目标函数
	start := time.Now()
	respRaw, err := queryUpstreamWithRacing(reqData)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("竞速回源失败: %v", err)
	}
	if len(respRaw) == 0 {
		t.Fatal("返回的数据包为空")
	}

	t.Logf("✅ 竞速回源测试通过，耗时: %v，返回包大小: %d bytes", duration, len(respRaw))
}

// ================= 2. 性能基准测试 (Benchmark) =================

// 压测协程池的派发性能 (DispatchRequest)
func BenchmarkWorkerPoolDispatch(b *testing.B) {
	// 准备一个假的客户端地址和连接（为了不真实发包，我们不测 processRequest 的底层逻辑，只测派发能力）
	dummyAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	req := &Request{Data: make([]byte, 50), Length: 50, Addr: dummyAddr}

	// 初始化工组池 (不传 conn 因为我们不真实回包)
	InitWorkerPool(nil)

	b.ResetTimer() // 重置计时器，排除初始化时间的干扰

	// 模拟极端高并发持续塞入请求
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			DispatchRequest(req, nil)
		}
	})
}

// 压测单节点回源性能 (querySingleUpstream)
func BenchmarkQuerySingleUpstream(b *testing.B) {
	mockConn, addr := startMockDNSServer(b)
	defer mockConn.Close()
	targetAddr, _ := net.ResolveUDPAddr("udp", addr)

	reqData := buildMockDNSQuery("speedtest.com.")
	ctx := context.Background()

	b.ResetTimer()

	// 串行压测，测试建立连接、发送、等待响应、解析的一套极速流程
	for i := 0; i < b.N; i++ {
		_, err := querySingleUpstream(ctx, targetAddr, reqData)
		if err != nil {
			b.Fatalf("回源压测失败: %v", err)
		}
	}
}

// 压测并发竞速回源性能 (queryUpstreamWithRacing)
func BenchmarkQueryUpstreamWithRacing(b *testing.B) {
	mockConn1, addr1 := startMockDNSServer(b)
	defer mockConn1.Close()
	mockConn2, addr2 := startMockDNSServer(b)
	defer mockConn2.Close()

	u1, _ := net.ResolveUDPAddr("udp", addr1)
	u2, _ := net.ResolveUDPAddr("udp", addr2)
	upstreamAddrs = []*net.UDPAddr{u1, u2}

	reqData := buildMockDNSQuery("racing.com.")

	b.ResetTimer()

	// 并行压测，模拟多个客户端同时请求防火墙，防火墙向多个上游竞速
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := queryUpstreamWithRacing(reqData)
			if err != nil {
				b.Fatalf("竞速回源压测失败: %v", err)
			}
		}
	})
}
