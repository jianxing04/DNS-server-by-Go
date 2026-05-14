package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"DNS-server-by-Go/pkg/config"
	"DNS-server-by-Go/pkg/database"
	"DNS-server-by-Go/pkg/handle"
	"DNS-server-by-Go/pkg/metrics"
	"DNS-server-by-Go/pkg/security"
)

func main() {
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	addr, _ := net.ResolveUDPAddr("udp", cfg.Server.Listen)
	conn, _ := net.ListenUDP("udp", addr)

	if err := InitSystem(conn, cfg); err != nil {
		log.Fatalf("系统初始化失败: %v", err)
	}
	log.Printf("🚀 DNS 防火墙启动 (三级安全引擎已挂载)，监听 %s", cfg.Server.Listen)

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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh

	log.Println("🛑 接收到退出信号，正在执行优雅关闭...")

	conn.Close()
	database.CloseCache()
	database.CloseMySQL()

	log.Println("👋 DNS 防火墙已安全退出")
}

func InitSystem(conn *net.UDPConn, cfg *config.Config) error {
	security.InitEmptyGlobalRules()

	if err := database.InitMySQL(cfg.MySQL); err != nil {
		return err
	}

	if err := database.InitCache(cfg.Redis, cfg.Cache); err != nil {
		return err
	}

	handle.SetUpstreams(cfg.Upstream.Servers, cfg.Upstream.TimeoutDuration())

	handle.InitWorkerPool(conn, cfg.Worker)

	metrics.StartServer(cfg.Server.MetricsAddr)
	return nil
}
