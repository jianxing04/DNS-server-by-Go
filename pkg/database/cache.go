package database

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coocood/freecache"
	"github.com/redis/go-redis/v9"
)

const (
	CacheSize      = 100 * 1024 * 1024 // 100MB
	WriteQueueSize = 50_000

	// 弹性调度参数
	MinCacheWorkers   = 10               // 低谷期保留的最少协程数
	MaxCacheWorkers   = 1000             // 高峰期允许的最大协程数
	ScaleUpThreshold  = 1000             // 队列长度超过此值时触发扩容
	ScaleDownIdleTime = 30 * time.Second // 协程空闲多久后自动销毁

	// Redis 配置
	RedisAddr     = "localhost:6379"
	RedisPassword = ""
	RedisDB       = 0
	PoolSize      = 500
	MinIdleConns  = 50
	DialTimeout   = 5 * time.Second
	ReadTimeout   = 1 * time.Second
	WriteTimeout  = 1 * time.Second
	PoolTimeout   = 2 * time.Second
)

var (
	DomainStatsMap  sync.Map
	CacheWriteQueue chan CacheWriteTask
	LocalCache      *freecache.Cache

	rdb *redis.Client
	ctx = context.Background()

	// 📊 命中率统计指标
	hitL1   int64
	hitL2   int64
	hitMiss int64

	// 📈 弹性调度与可观测性指标
	activeWorkers atomic.Int32 // 当前活跃的写入协程数量
	droppedTasks  atomic.Int64 // 队列满导致的丢弃数量

	// 🛑 优雅退出控制
	wg          sync.WaitGroup
	stopMonitor chan struct{}
)

type CacheWriteTask struct {
	Key string
	Raw []byte
	TTL time.Duration
}

// InitCache 初始化缓存，连接 Redis，并启动弹性调度器
func InitCache() error {
	LocalCache = freecache.NewCache(CacheSize)
	CacheWriteQueue = make(chan CacheWriteTask, WriteQueueSize)
	stopMonitor = make(chan struct{})

	// 1. 启动最小数量的基础写入协程 (底薪员工)
	for range MinCacheWorkers {
		wg.Add(1)
		activeWorkers.Add(1)
		go asyncRedisWriter()
	}

	// 2. 启动动态调度器和命中率监控
	go workerManager()
	go startHitRateMonitor()

	// 3. 初始化 Redis 客户端
	rdb = redis.NewClient(&redis.Options{
		Addr:         RedisAddr,
		Password:     RedisPassword,
		DB:           RedisDB,
		PoolSize:     PoolSize,
		MinIdleConns: MinIdleConns,
		DialTimeout:  DialTimeout,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		PoolTimeout:  PoolTimeout,
	})

	var err error
	maxRetries := 5

	for i := range maxRetries {
		checkCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err = rdb.Ping(checkCtx).Result()
		cancel()

		if err == nil {
			log.Println("✅ Redis 连接成功")
			return nil
		}

		log.Printf("⚠️ Redis 连接失败 (第%d次): %v", i+1, err)
		time.Sleep(time.Duration(1<<i) * time.Second) // 指数退避
	}

	return fmt.Errorf("❌ Redis 多次重试失败: %w", err)
}

// CloseCache 优雅关闭缓存模块，确保数据不丢失
func CloseCache() {
	log.Println("🔄 开始关闭缓存模块...")

	// 1. 停止所有后台监控和调度协程
	if stopMonitor != nil {
		close(stopMonitor)
	}

	// 2. 关闭任务队列，拒绝新任务，但允许消费者继续消费存量数据
	if CacheWriteQueue != nil {
		close(CacheWriteQueue)
	}

	// 3. 阻塞等待所有活跃的写协程安全退出
	wg.Wait()
	log.Println("✅ 异步写入队列已清空，所有写协程已安全退出")

	// 4. 清理本地缓存
	if LocalCache != nil {
		LocalCache.Clear()
	}

	// 5. 关闭 Redis 连接
	if rdb != nil {
		err := rdb.Close()
		if err != nil {
			log.Printf("⚠️ Redis 连接关闭异常: %v\n", err)
		} else {
			log.Println("✅ Redis 连接已关闭")
		}
	}
}

// SetCache 封装统一的缓存写入入口，先写入程序缓存，再传递给写队列写入 Redis
func SetCache(key string, raw []byte, ttl time.Duration) {
	// 绝对优先：同步写入本地极速缓存，保证热点数据 0 延迟可用
	LocalCache.Set([]byte(key), raw, int(ttl.Seconds()))

	// 异步降级：投递给 Redis 队列
	select {
	case CacheWriteQueue <- CacheWriteTask{Key: key, Raw: raw, TTL: ttl}:
	default:
		// 队列满了直接丢弃，保护系统不崩溃，同时记录丢弃指标
		droppedTasks.Add(1)
	}
}

// RecordDomainAccess 在程序内存记录域名访问次数
func RecordDomainAccess(domain string) {
	if v, ok := DomainStatsMap.Load(domain); ok {
		atomic.AddInt64(v.(*int64), 1)
		return
	}
	var initCount int64 = 1
	if actual, loaded := DomainStatsMap.LoadOrStore(domain, &initCount); loaded {
		atomic.AddInt64(actual.(*int64), 1)
	}
}

// GetRedis 获取 Redis 数据
func GetRedis(ctx context.Context, key string) ([]byte, error) {
	val, err := rdb.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	return val, nil
}

// asyncRedisWriter 异步写入 Redis (支持空闲自动释放)
func asyncRedisWriter() {
	defer wg.Done()
	defer activeWorkers.Add(-1)

	idleTimer := time.NewTimer(ScaleDownIdleTime)
	defer idleTimer.Stop()

	for {
		select {
		case task, ok := <-CacheWriteQueue:
			if !ok {
				return // 队列已关闭，优雅退出
			}

			// 停止定时器并清空通道，准备复用
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}

			writeCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			err := rdb.Set(writeCtx, task.Key, task.Raw, task.TTL).Err()
			cancel()

			if err != nil {
				// 压测下屏蔽 Redis 错误日志，避免大量 I/O 拖垮 QPS
			}

			// 重置空闲倒计时
			idleTimer.Reset(ScaleDownIdleTime)

		case <-idleTimer.C:
			// 触发空闲超时，判断是否需要“裁员”
			if activeWorkers.Load() > int32(MinCacheWorkers) {
				return // 留下足够的基础协程，当前协程功成身退
			}
			idleTimer.Reset(ScaleDownIdleTime)
		}
	}
}

// workerManager 监控队列并动态扩缩容协程
func workerManager() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stopMonitor:
			log.Println("🛑 协程调度器已停止")
			return
		case <-ticker.C:
			qLen := len(CacheWriteQueue)
			currentWorkers := activeWorkers.Load()

			// 如果队列积压超过阈值，且还没达到协程上限，则按批次扩容
			if qLen > ScaleUpThreshold && currentWorkers < MaxCacheWorkers {
				batchSize := int32(20)
				if currentWorkers+batchSize > MaxCacheWorkers {
					batchSize = MaxCacheWorkers - currentWorkers
				}

				for i := int32(0); i < batchSize; i++ {
					wg.Add(1)
					activeWorkers.Add(1)
					go asyncRedisWriter()
				}
			}
		}
	}
}

// =========== 暴露给外部的打点方法 ===========
func RecordHitL1() { atomic.AddInt64(&hitL1, 1) }
func RecordHitL2() { atomic.AddInt64(&hitL2, 1) }
func RecordMiss()  { atomic.AddInt64(&hitMiss, 1) }

// startHitRateMonitor 每分钟输出一次缓存战报
func startHitRateMonitor() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stopMonitor:
			log.Println("🛑 缓存战报与可观测性监控已停止")
			return
		case <-ticker.C:
			l1 := atomic.SwapInt64(&hitL1, 0)
			l2 := atomic.SwapInt64(&hitL2, 0)
			miss := atomic.SwapInt64(&hitMiss, 0)
			dropped := droppedTasks.Swap(0)

			total := l1 + l2 + miss
			workers := activeWorkers.Load()
			qLen := len(CacheWriteQueue)

			if total == 0 && qLen == 0 && dropped == 0 {
				continue
			}

			l1Rate, l2Rate, missRate := 0.0, 0.0, 0.0
			if total > 0 {
				l1Rate = float64(l1) / float64(total) * 100
				l2Rate = float64(l2) / float64(total) * 100
				missRate = float64(miss) / float64(total) * 100
			}

			log.Printf("📊 [缓存战报] QPM: %d | L1: %.2f%% | L2: %.2f%% | Miss: %.2f%% | 活跃Worker: %d | 队列积压: %d | 丢弃任务: %d",
				total, l1Rate, l2Rate, missRate, workers, qLen, dropped)
		}
	}
}
