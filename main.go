package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"DNS-server-by-Go/pkg/database"
	"DNS-server-by-Go/pkg/handle"
	"DNS-server-by-Go/pkg/metrics"
	"DNS-server-by-Go/pkg/security"
)

// ================= 核心配置项 =================
const (
	ListenAddr = "0.0.0.0:8053"
)

func main() {
	addr, _ := net.ResolveUDPAddr("udp", ListenAddr)
	conn, _ := net.ListenUDP("udp", addr)
	// 移除了 defer conn.Close()，因为我们要在收到信号后手动控制关闭顺序

	if err := InitSystem(conn); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	log.Printf("🚀 DNS 防火墙启动 (三级安全引擎已挂载)，监听 %s", ListenAddr)

	// 1. 将原先的死循环放入独立的后台协程中
	go func() {
		for {
			bufPtr := handle.GetFromPool()
			buf := *bufPtr
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				handle.PutToPool(bufPtr)
				continue
			}
			handle.DispatchRequest(&handle.Request{Data: buf, Length: n, Addr: clientAddr}, conn)
		}
	}()

	// 2. 优雅退出 (Graceful Shutdown) 机制
	// 拦截 Ctrl+C (SIGINT) 和 Docker Stop (SIGTERM)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 主线程会在这里阻塞，直到收到退出信号
	<-sigCh

	log.Println("🛑 接收到退出信号，正在执行优雅关闭...")

	// 3. 安全关闭顺序
	conn.Close()     // 停止接收新的 UDP 请求
	database.Close() // 关闭 Redis 连接

	// 注意：在更极端的生产环境中，我们还会在这里主动调用一次 MySQL Flush
	// 把内存中最后几秒的数据强行刷入数据库再退出。

	log.Println("👋 DNS 防火墙已安全退出")
}

func InitSystem(conn *net.UDPConn) error {
	// 1. 初始化空规则
	security.InitEmptyGlobalRules()

	// 2. 初始化 MySQL
	if err := database.InitMySQL(); err != nil {
		return err // 使用 return 交给 main 函数去 Fatal
	}
	go database.SyncRulesFromMySQL()
	go database.AsyncStatsFlusher()

	// 3. 初始化 Redis
	if err := database.InitRedis(); err != nil {
		return err
	}

	// 4. 初始化内存缓存与异步写入队列
	database.InitCache()

	// 5. 初始化工作池
	handle.InitWorkerPool(conn)

	// 6. 启动监控指标
	metrics.StartServer(":2112")
	return nil
}
