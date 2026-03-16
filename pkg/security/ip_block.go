package security

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"
)

var GlobalRules atomic.Value // 无锁安全规则引擎

// 安全规则集：包含三道防线
type SecurityRules struct {
	ClientIPBlocker *IPBlockTrie        // 防线1: 客户端 IP 拦截
	DomainBlocker   map[string]struct{} // 防线2: 恶意域名拦截 (使用哈希表达到 O(1) 极速匹配)
	TargetIPBlocker *IPBlockTrie        // 防线3: 解析结果目标 IP 拦截
}

// 字典树上的节点
type TrieNode struct {
	children [2]*TrieNode
	isBlock  bool
}

// 存储根节点
type IPBlockTrie struct {
	root *TrieNode
}

func NewIPBlockTrie() *IPBlockTrie {
	return &IPBlockTrie{
		root: &TrieNode{},
	}
}

// 初始化空的安全规则
func InitEmptyGlobalRules() {
	emptyRules := &SecurityRules{
		ClientIPBlocker: NewIPBlockTrie(),
		DomainBlocker:   make(map[string]struct{}),
		TargetIPBlocker: NewIPBlockTrie(),
	}
	GlobalRules.Store(emptyRules)
}

func (t *IPBlockTrie) Insert(cidr string) error {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	if ip == nil {
		ip = net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid IP")
		}
		ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	}
	ip4 := ip.To4()
	ipInt := binary.BigEndian.Uint32(ip4)
	ones, _ := ipnet.Mask.Size()
	curr := t.root
	for i := 31; i >= 32-ones; i-- {
		bit := (ipInt >> i) & 1
		if curr.children[bit] == nil {
			curr.children[bit] = &TrieNode{}
		}
		curr = curr.children[bit]
	}
	curr.isBlock = true
	return nil
}

// MatchBytes 零分配匹配核心逻辑：直接接收底层 IPv4 字节切片
func (t *IPBlockTrie) MatchBytes(ip4 []byte) bool {
	if len(ip4) != 4 {
		return false
	}

	// 直接将 4 字节转换为 uint32，没有任何内存分配
	ipInt := binary.BigEndian.Uint32(ip4)
	curr := t.root

	for i := 31; i >= 0; i-- {
		if curr.isBlock {
			return true
		}
		bit := (ipInt >> i) & 1
		if curr.children[bit] == nil {
			return false
		}
		curr = curr.children[bit]
	}
	return curr.isBlock
}

// 快速扫描字节流，检查上游返回的 IP 是否在黑名单中
func IsTargetIPBlocked(rawResp []byte, targetBlocker *IPBlockTrie) bool {
	var p dnsmessage.Parser
	_, err := p.Start(rawResp)
	if err != nil {
		return false
	}
	p.SkipAllQuestions()

	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if ah.Type == dnsmessage.TypeA {
			res, err := p.AResource()
			if err == nil {
				// 直接将 res.A (类型为 [4]byte) 转换为切片传入
				// 彻底消灭了 net.IP(res.A[:]).String() 带来的堆内存分配
				if targetBlocker.MatchBytes(res.A[:]) {
					return true
				}
			}
		}
		p.SkipAnswer()
	}
	return false
}
