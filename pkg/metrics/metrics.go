package metrics

import (
	"log"
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var ready int32

func SetReady()  { atomic.StoreInt32(&ready, 1) }
func SetNotReady() { atomic.StoreInt32(&ready, 0) }

var (
	totalQueries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_queries_total",
		Help: "收到的 DNS 查询总数",
	})

	cacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_cache_hits_total",
		Help: "缓存命中次数 (包含 L1, L2, Miss)",
	}, []string{"layer"})

	blockedQueries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_blocked_total",
		Help: "被安全规则拦截的请求数",
	}, []string{"reason"})

	requestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "dns_request_duration_seconds",
		Help:    "DNS 请求处理延迟分布",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
	})
)

func IncQuery()                { totalQueries.Inc() }
func IncCacheHit(layer string) { cacheHits.WithLabelValues(layer).Inc() }
func IncBlocked(reason string) { blockedQueries.WithLabelValues(reason).Inc() }
func ObserveDuration(s float64) { requestDuration.Observe(s) }

func StartServer(addr string) {
	mux := http.NewServeMux()

	mux.HandleFunc("/metrics", promhttp.Handler().ServeHTTP)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&ready) == 1 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ready"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("not ready"))
		}
	})

	go func() {
		log.Printf("📊 Metrics / 健康检查接口已启动: http://%s", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("⚠️ Metrics 服务异常退出: %v", err)
		}
	}()
}
