package metrics

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ================= 私有指标变量 =================
var (
	totalQueries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_queries_total",
		Help: "收到的 DNS 查询总数",
	})

	cacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_cache_hits_total",
		Help: "缓存命中次数 (包含 L1, L2, Miss)",
	}, []string{"layer"}) // layer: L1, L2, Miss

	blockedQueries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_blocked_total",
		Help: "被安全规则拦截的请求数",
	}, []string{"reason"}) // reason: ClientIP, Domain, TargetIP

	requestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "dns_request_duration_seconds",
		Help:    "DNS 请求处理延迟分布",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5}, // 0.1ms 到 500ms
	})
)

// ================= 公开打点函数 =================

// IncQuery 记录一次请求
func IncQuery() {
	totalQueries.Inc()
}

// IncCacheHit 记录缓存命中情况 (layer 传 "L1", "L2" 或 "Miss")
func IncCacheHit(layer string) {
	cacheHits.WithLabelValues(layer).Inc()
}

// IncBlocked 记录拦截原因 (reason 传 "ClientIP", "Domain" 或 "TargetIP")
func IncBlocked(reason string) {
	blockedQueries.WithLabelValues(reason).Inc()
}

// ObserveDuration 记录处理耗时
func ObserveDuration(seconds float64) {
	requestDuration.Observe(seconds)
}

// ================= 服务启动 =================

// StartServer 启动 Prometheus 暴露接口
func StartServer(addr string) {
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Printf("📊 Prometheus Metrics 接口已启动: http://%s/metrics", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("⚠️ Metrics 服务异常退出: %v", err)
		}
	}()
}
