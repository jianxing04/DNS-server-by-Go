package security

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// ================= 1. 功能测试 =================

func TestIPBlockTrie(t *testing.T) {
	trie := NewIPBlockTrie()

	// 测试插入合法的 CIDR 和单 IP
	_ = trie.Insert("192.168.1.0/24")
	_ = trie.Insert("10.0.0.1/32")

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"命中 /24 网段", "192.168.1.100", true},
		{"未命中 /24 网段", "192.168.2.1", false},
		{"精准命中单 IP", "10.0.0.1", true},
		{"未命中单 IP", "10.0.0.2", false},
		{"无效 IP 格式", "999.999.999.999", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 在测试中，我们先将字符串解析为字节，模拟 processRequest 里的操作
			ip := net.ParseIP(tt.ip).To4()

			// 如果是无效 IP 格式，net.ParseIP 会返回 nil
			// MatchBytes 内部处理了 nil 的情况
			if got := trie.MatchBytes(ip); got != tt.expected {
				t.Errorf("MatchBytes(%s) = %v, 预期 %v", tt.ip, got, tt.expected)
			}
		})
	}
}

// ================= 2. 性能基准测试 =================

func BenchmarkIPBlockTrie_MatchBytes(b *testing.B) {
	trie := NewIPBlockTrie()
	trie.Insert("192.168.1.0/24")
	trie.Insert("10.0.0.0/8")
	trie.Insert("172.16.0.0/12")

	// 【关键优化】：在循环外解析好字节数组
	// 这样压测指标反映的是 Trie 树匹配的纯粹速度，不含解析开销
	targetIP := net.ParseIP("192.168.1.250").To4()

	b.ResetTimer() // 重置计时器，排除解析 IP 的耗时
	for i := 0; i < b.N; i++ {
		trie.MatchBytes(targetIP)
	}
}

// 压测整个 DNS 响应包的 IP 提取与匹配
func BenchmarkIsTargetIPBlocked(b *testing.B) {
	trie := NewIPBlockTrie()
	trie.Insert("1.2.3.4/32")

	// 构造一个包含 1.2.3.4 作为解析结果的 DNS 响应包
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	builder.StartAnswers()
	builder.AResource(
		dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("evil.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
	)
	rawResp, _ := builder.Finish()

	for b.Loop() {
		IsTargetIPBlocked(rawResp, trie)
	}
}
