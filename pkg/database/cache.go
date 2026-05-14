package database

import (
	"DNS-server-by-Go/pkg/config"
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coocood/freecache"
	"github.com/redis/go-redis/v9"
)

var (
	DomainStatsMap  sync.Map
	CacheWriteQueue chan CacheWriteTask
	LocalCache      *freecache.Cache

	rdb *redis.Client
	ctx = context.Background()

	hitL1   int64
	hitL2   int64
	hitMiss int64

	activeWorkers atomic.Int32
	droppedTasks  atomic.Int64

	wg          sync.WaitGroup
	stopMonitor chan struct{}

	cacheCfg config.CacheConfig
)

type CacheWriteTask struct {
	Key string
	Raw []byte
	TTL time.Duration
}

func InitCache(redisCfg config.RedisConfig, cfg config.CacheConfig) error {
	cacheCfg = cfg

	LocalCache = freecache.NewCache(cfg.LocalCacheSize)
	CacheWriteQueue = make(chan CacheWriteTask, cfg.WriteQueueSize)
	stopMonitor = make(chan struct{})

	for range cfg.MinWorkers {
		wg.Add(1)
		activeWorkers.Add(1)
		go asyncRedisWriter()
	}

	go workerManager()
	go startHitRateMonitor()

	rdb = redis.NewClient(&redis.Options{
		Addr:         redisCfg.Addr,
		Password:     redisCfg.Password,
		DB:           redisCfg.DB,
		PoolSize:     redisCfg.PoolSize,
		MinIdleConns: redisCfg.MinIdleConns,
		DialTimeout:  redisCfg.DialTimeoutDuration(),
		ReadTimeout:  redisCfg.ReadTimeoutDuration(),
		WriteTimeout: redisCfg.WriteTimeoutDuration(),
		PoolTimeout:  redisCfg.PoolTimeoutDuration(),
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

	idleTimer := time.NewTimer(cacheCfg.ScaleDownIdleDuration())
	defer idleTimer.Stop()

	for {
		select {
		case task, ok := <-CacheWriteQueue:
			if !ok {
				return
			}

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
			}

			idleTimer.Reset(cacheCfg.ScaleDownIdleDuration())

		case <-idleTimer.C:
			if activeWorkers.Load() > int32(cacheCfg.MinWorkers) {
				return
			}
			idleTimer.Reset(cacheCfg.ScaleDownIdleDuration())
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

			if qLen > cacheCfg.ScaleUpThreshold && currentWorkers < int32(cacheCfg.MaxWorkers) {
				batchSize := int32(20)
				if currentWorkers+batchSize > int32(cacheCfg.MaxWorkers) {
					batchSize = int32(cacheCfg.MaxWorkers) - currentWorkers
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
