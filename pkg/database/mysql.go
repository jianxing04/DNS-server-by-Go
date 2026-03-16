package database

import (
	"DNS-server-by-Go/pkg/security"
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql" // 必须匿名导入驱动，否则无法 Open
)

const (
	MaxOpenConns = 50
	MaxIdleConns = 10
	Username     = "root"
	Password     = "password"
	Host         = "localhost"
	Port         = 3306
	DBName       = "dns"
	Charset      = "utf8mb4"
	ParseTime    = true
	Loc          = "Local"
)

var db *sql.DB

// InitMySQL 初始化 MySQL 连接池
func InitMySQL() error {
	var err error
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=%t&loc=%s",
		Username,
		Password,
		Host,
		Port,
		DBName,
		Charset,
		ParseTime,
		url.QueryEscape(Loc),
	)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("MySQL 驱动初始化失败: %v", err)
		return err
	}
	db.SetMaxOpenConns(MaxOpenConns)
	db.SetMaxIdleConns(MaxIdleConns)

	// 强制进行真实连通性测试，避免程序启动假死
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("❌ MySQL 连接失败，请检查服务或密码: %v", err)
		return err
	}
	log.Println("✅ MySQL 连接安全建立")
	return nil
}

// SyncRulesFromMySQL 定时从数据库拉取启用的规则，并在内存中完成原子替换
func SyncRulesFromMySQL() {
	for {
		newRules := &security.SecurityRules{
			ClientIPBlocker: security.NewIPBlockTrie(),
			DomainBlocker:   make(map[string]struct{}),
			TargetIPBlocker: security.NewIPBlockTrie(),
		}

		// 模拟从 MySQL 获取数据 (这里保留你的 mock 数据)
		mockClientIPs := []string{"192.168.1.0/24"}
		mockDomains := []string{"ads.google.com.", "badguy.net."}
		mockTargetIPs := []string{"10.255.255.254/32"}

		for _, cidr := range mockClientIPs {
			newRules.ClientIPBlocker.Insert(cidr)
		}
		for _, cidr := range mockTargetIPs {
			newRules.TargetIPBlocker.Insert(cidr)
		}
		for _, domain := range mockDomains {
			newRules.DomainBlocker[strings.ToLower(domain)] = struct{}{}
		}

		// 原子替换
		security.GlobalRules.Store(newRules)
		time.Sleep(1 * time.Minute)
	}
}

// AsyncStatsFlusher 每隔 10 秒收集一次内存增量，并写入数据库
// 对于该段时间内未被访问域名，从内存中删除，避免内存爆炸
func AsyncStatsFlusher() {
	ticker := time.NewTicker(10 * time.Second)

	for range ticker.C {
		snapshot := make(map[string]int64)

		DomainStatsMap.Range(func(key, value any) bool {
			domain := key.(string)
			countPtr := value.(*int64)

			delta := atomic.SwapInt64(countPtr, 0)
			if delta > 0 {
				snapshot[domain] = delta
			} else {
				// 防爆内存：如果 10 秒内无人访问该域名，直接从 Map 删除。
				// 防止遭遇随机子域名攻击(PRSD)导致内存溢出。
				DomainStatsMap.Delete(key)
			}
			return true
		})

		if len(snapshot) > 0 {
			FlushToMySQL(snapshot)
		}
	}
}

// FlushToMySQL 执行批量 Upsert 写入 (带 Chunk 分块防超长 SQL)
func FlushToMySQL(snapshot map[string]int64) {
	if len(snapshot) == 0 {
		return
	}

	const batchSize = 1000 // 【优化】每次最多插入 1000 条，防止超长 SQL 被 MySQL 拒绝
	now := time.Now()
	statDate := now.Format("2006-01-02")
	statHour := now.Hour()

	var placeholders []string
	var vals []any

	count := 0
	totalProcessed := 0

	for domain, accCount := range snapshot {
		placeholders = append(placeholders, "(?, ?, ?, ?)")
		vals = append(vals, domain, statDate, statHour, accCount)
		count++
		totalProcessed++

		// 达到批次上限，执行一次入库
		if count >= batchSize {
			executeBatch(placeholders, vals)
			placeholders = placeholders[:0] // 清空切片复用内存
			vals = vals[:0]
			count = 0
		}
	}

	// 处理剩余尾部数据
	if count > 0 {
		executeBatch(placeholders, vals)
	}

	log.Printf("📈 成功将 %d 个域名的增量访问数据合并刷入 MySQL！", totalProcessed)
}

// executeBatch 内部函数，执行真正的单批次 SQL 写入
func executeBatch(placeholders []string, vals []any) {
	query := "INSERT INTO dns_domain_stats (domain, stat_date, stat_hour, access_count) VALUES " +
		strings.Join(placeholders, ",") +
		" ON DUPLICATE KEY UPDATE access_count = access_count + VALUES(access_count)"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctx, query, vals...)
	if err != nil {
		log.Printf("⚠️ 批量写入 MySQL 失败: %v", err)
	}
}
