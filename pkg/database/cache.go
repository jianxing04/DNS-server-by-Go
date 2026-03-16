package database

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/coocood/freecache"
)

const (
	CacheSize      = 100 * 1024 * 1024 // 100MB
	WriteQueueSize = 1000
	CacheWriterNum = 5
)

var (
	DomainStatsMap  sync.Map
	CacheWriteQueue chan CacheWriteTask
	LocalCache      *freecache.Cache
)

type CacheWriteTask struct {
	Key string
	Raw []byte
	TTL time.Duration
}

func InitCache() {
	LocalCache = freecache.NewCache(CacheSize)
	CacheWriteQueue = make(chan CacheWriteTask, WriteQueueSize)
	for range CacheWriterNum {
		go asyncCacheWriter()
	}
}

// RecordDomainAccess 高并发下极速累加访问量
func RecordDomainAccess(domain string) {
	// 1. 尝试直接加载已存在的计数器 (绝大多数情况走这条极速路径)
	if v, ok := DomainStatsMap.Load(domain); ok {
		atomic.AddInt64(v.(*int64), 1) // 原子+1，完全无锁
		return
	}

	// 2. 如果是第一次访问该域名，初始化一个计数器
	var initCount int64 = 1
	if actual, loaded := DomainStatsMap.LoadOrStore(domain, &initCount); loaded {
		// 并发情况下，如果其他协程刚刚抢先初始化了，我们就往它初始化的指针上加 1
		atomic.AddInt64(actual.(*int64), 1)
	}
}
