package database

import (
	"sync"
	"sync/atomic"
	"testing"
)

// ================= 1. 功能测试：验证高并发下无锁计数器的绝对准确性 =================

func TestRecordDomainAccess_Concurrency(t *testing.T) {
	// 每次测试前清空 Map，防止干扰
	DomainStatsMap.Reset()

	const goroutines = 1000 // 模拟 1000 个并发请求同时涌入
	const increments = 100  // 每个协程访问同一个域名 100 次
	targetDomain := "google.com."

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// 1. 发动高并发洪峰袭击
	for range goroutines {
		go func() {
			defer wg.Done()
			for range increments {
				RecordDomainAccess(targetDomain)
			}
		}()
	}

	wg.Wait() // 等待所有协程执行完毕

	// 2. 验证结果
	val, ok := DomainStatsMap.Load(targetDomain)
	if !ok {
		t.Fatalf("❌ 域名 %s 没有被记录进 Map", targetDomain)
	}

	finalCount := atomic.LoadInt64(val)
	expectedCount := int64(goroutines * increments)

	if finalCount != expectedCount {
		t.Fatalf("❌ 严重的并发数据丢失！预期: %d, 实际: %d", expectedCount, finalCount)
	}

	t.Logf("✅ 无锁并发测试完美通过！预期: %d, 实际: %d", expectedCount, finalCount)
}

func TestAsyncStatsFlusher_AtomicSwap(t *testing.T) {
	// 验证在提取数据的瞬间，原子替换是否正确运作
	DomainStatsMap.Reset()
	testDomain := "example.com."

	// 模拟写入 50 次
	for range 50 {
		RecordDomainAccess(testDomain)
	}

	// 模拟 Flusher 提取数据的核心逻辑
	val, _ := DomainStatsMap.Load(testDomain)
	countPtr := val

	// 提取并瞬间归零
	delta := atomic.SwapInt64(countPtr, 0)

	if delta != 50 {
		t.Fatalf("❌ 提取的数据量错误，预期 50，实际: %d", delta)
	}

	// 验证内存里是否真的归零了
	currentCount := atomic.LoadInt64(countPtr)
	if currentCount != 0 {
		t.Fatalf("❌ 数据提取后没有成功归零，当前值: %d", currentCount)
	}

	t.Logf("✅ 原子提取并归零逻辑测试通过！提取的增量: %d", delta)
}

// ================= 2. 性能基准测试：压榨你的计数器性能极限 =================

func BenchmarkRecordDomainAccess_SameKey(b *testing.B) {
	DomainStatsMap.Reset()
	domain := "hot-domain.com."

	// 先初始化一次，为了测纯粹的原子累加性能
	RecordDomainAccess(domain)

	b.ResetTimer()

	// 模拟极端热点域名：所有 CPU 核心都在疯狂访问同一个域名
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			RecordDomainAccess(domain)
		}
	})
}

func BenchmarkRecordDomainAccess_RandomKeys(b *testing.B) {
	DomainStatsMap.Reset()

	// 准备一组字典，模拟正常用户的真实访问分布
	domains := []string{
		"a.com.", "b.com.", "c.com.", "d.com.", "e.com.",
		"f.com.", "g.com.", "h.com.", "i.com.", "j.com.",
	}

	b.ResetTimer()

	// 模拟访问分散的不同域名，测试 sync.Map 的寻址与原子操作综合性能
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// 简单的轮询模拟随机
			RecordDomainAccess(domains[i%len(domains)])
			i++
		}
	})
}
