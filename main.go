package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

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

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
		},
	}
	packetConn, err := lc.ListenPacket(context.Background(), "udp", cfg.Server.Listen)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	conn := packetConn.(*net.UDPConn)

	if err := InitSystem(conn, cfg); err != nil {
		log.Fatalf("系统初始化失败: %v", err)
	}
	log.Printf("🚀 DNS 防火墙启动 (三级安全引擎已挂载)，监听 %s", cfg.Server.Listen)

	pc := ipv4.NewPacketConn(packetConn)
	stopReader := make(chan struct{})

	go func() {
		defer close(stopReader)
		const batchSize = 64
		msgs := make([]ipv4.Message, batchSize)
		for i := range msgs {
			buf := make([]byte, handle.MaxDNSPacketSize)
			msgs[i].Buffers = [][]byte{buf}
		}

		for {
			n, err := pc.ReadBatch(msgs, 0)
			if err != nil {
				select {
				case <-stopReader:
					return
				default:
				}
				continue
			}
			for i := range n {
				msg := &msgs[i]
				// 零拷贝：直接复用 ReadBatch 填好的 buffer，再换一个新的给 ReadBatch
				bufPtr := handle.GetFromPool()
				reqData := msg.Buffers[0]
				msg.Buffers = [][]byte{*bufPtr}

				req := handle.GetRequest()
				req.Data = reqData
				req.Length = msg.N
				req.Addr = msg.Addr.(*net.UDPAddr)
				handle.DispatchRequest(req, conn)
			}
		}
	}()

	metrics.SetReady()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh

	log.Println("🛑 接收到退出信号，正在执行优雅关闭...")

	metrics.SetNotReady()
	time.Sleep(5 * time.Second)

	conn.Close()
	<-stopReader
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

	handle.InitSocketPool(cfg.Server.SocketPoolSize)
	handle.InitWorkerPool(conn, cfg.Worker)

	metrics.StartServer(cfg.Server.MetricsAddr)
	return nil
}
