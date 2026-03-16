package database

import (
	"context"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	RedisAddr     = "localhost:6379"
	RedisPassword = ""
	RedisDB       = 0
	PoolSize      = 50
	MinIdleConns  = 10
	DialTimeout   = 5 * time.Second
	ReadTimeout   = 3 * time.Second
	WriteTimeout  = 3 * time.Second
	PoolTimeout   = 4 * time.Second
)

var (
	rdb *redis.Client
	ctx = context.Background()
)

// InitRedis 初始化 Redis 客户端并测试连通性
func InitRedis() error {
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

	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if _, err := rdb.Ping(checkCtx).Result(); err != nil {
		log.Printf("❌ Redis 连接失败，请检查服务是否启动: %v", err)
		return err
	}

	log.Println("✅ Redis 连接安全建立，检测通过")
	return nil
}

// Close 优雅关闭 Redis 连接
func Close() {
	if rdb != nil {
		rdb.Close()
		log.Println("🔌 Redis 连接已关闭")
	}
}

// GetRedis 获取 Redis 中的 DNS 缓存记录
func GetRedis(ctx context.Context, key string) ([]byte, error) {
	val, err := rdb.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	return val, nil
}

// asyncCacheWriter 异步将热点数据写入多级缓存
func asyncCacheWriter() {
	for task := range CacheWriteQueue {
		// 1. 写入本地极速缓存
		LocalCache.Set([]byte(task.Key), task.Raw, int(task.TTL.Seconds()))

		// 2. 写入 Redis (带极短的超时保护)
		// 防止 Redis 卡顿导致这 5 个 Writer 协程被永远挂死，进而导致 Channel 爆满
		writeCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		err := rdb.Set(writeCtx, task.Key, task.Raw, task.TTL).Err()
		cancel() // 必须立即释放 Context
		
		if err != nil {
			log.Printf("⚠️ Redis 异步写入失败 [Key: %s]: %v", task.Key, err)
		}
	}
}