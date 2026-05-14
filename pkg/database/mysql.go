package database

import (
	"DNS-server-by-Go/pkg/config"
	"DNS-server-by-Go/pkg/security"
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var (
	db           *sql.DB
	mysqlCfg     config.MySQLConfig
	dbWg         sync.WaitGroup
	stopDBWorker chan struct{}
)

func InitMySQL(cfg config.MySQLConfig) error {
	mysqlCfg = cfg

	var err error
	dsn := cfg.DSN()

	maxRetries := 10
	for i := range maxRetries {
		db, err = sql.Open("mysql", dsn)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = db.PingContext(ctx)
			cancel()
			if err == nil {
				log.Println("✅ MySQL 连接安全建立")
				db.SetMaxOpenConns(cfg.MaxOpenConns)
				db.SetMaxIdleConns(cfg.MaxIdleConns)

				stopDBWorker = make(chan struct{})

				dbWg.Add(2)
				go SyncRulesFromMySQL()
				go AsyncStatsFlusher()

				return nil
			}
		}
		log.Printf("⚠️ MySQL 尚未就绪，等待中... (%d/%d): %v", i+1, maxRetries, err)
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("❌ 达到最大重试次数，MySQL 依然无法连接: %w", err)
}

// CloseMySQL 优雅关闭 MySQL 模块
func CloseMySQL() {
	log.Println("🔄 开始关闭 MySQL 模块...")

	// 1. 发送信号停止后台刷盘和拉取规则的协程
	if stopDBWorker != nil {
		close(stopDBWorker)
	}

	// 2. 阻塞等待后台协程完成最后一次刷盘任务
	dbWg.Wait()
	log.Println("✅ MySQL 后台任务已全部安全停止")

	// 3. 关闭数据库连接池
	if db != nil {
		err := db.Close()
		if err != nil {
			log.Printf("⚠️ MySQL 连接关闭异常: %v\n", err)
		} else {
			log.Println("✅ MySQL 连接已关闭")
		}
	}
}

// SyncRulesFromMySQL 定时从数据库拉取启用的规则，并在内存中完成原子替换
func SyncRulesFromMySQL() {
	defer dbWg.Done()

	ticker := time.NewTicker(mysqlCfg.RuleSyncDuration())
	defer ticker.Stop()

	pullRulesFromDB()

	for {
		select {
		case <-stopDBWorker:
			log.Println("🛑 规则同步任务已停止")
			return
		case <-ticker.C:
			pullRulesFromDB()
		}
	}
}

// 内部函数：执行真实的 DB 查询和字典树构建
func pullRulesFromDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 只查询已启用的规则
	query := `SELECT rule_type, rule_value FROM security_rules WHERE is_enabled = 1`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		log.Printf("⚠️ 拉取安全规则失败: %v", err)
		return
	}
	defer rows.Close()

	// 初始化新的空规则集
	newRules := &security.SecurityRules{
		ClientIPBlocker: security.NewIPBlockTrie(),
		DomainBlocker:   make(map[string]struct{}),
		TargetIPBlocker: security.NewIPBlockTrie(),
	}

	var ruleType, ruleValue string
	count := 0

	for rows.Next() {
		if err := rows.Scan(&ruleType, &ruleValue); err != nil {
			log.Printf("⚠️ 解析安全规则数据行失败: %v", err)
			continue
		}

		switch ruleType {
		case "client_ip":
			if err := newRules.ClientIPBlocker.Insert(ruleValue); err != nil {
				log.Printf("⚠️ 无效的客户端 IP 规则 [%s]: %v", ruleValue, err)
			}
		case "target_ip":
			if err := newRules.TargetIPBlocker.Insert(ruleValue); err != nil {
				log.Printf("⚠️ 无效的目标 IP 规则 [%s]: %v", ruleValue, err)
			}
		case "domain":
			newRules.DomainBlocker[strings.ToLower(ruleValue)] = struct{}{}
		}
		count++
	}

	if err := rows.Err(); err != nil {
		log.Printf("⚠️ 读取规则行遍历时发生错误: %v", err)
		return
	}

	// 原子替换，零停机更新规则！
	security.GlobalRules.Store(newRules)
	log.Printf("🛡️ 成功从 MySQL 同步并加载 %d 条安全规则", count)
}

// AsyncStatsFlusher 每隔 10 秒收集一次内存增量，并写入数据库
func AsyncStatsFlusher() {
	defer dbWg.Done()

	ticker := time.NewTicker(mysqlCfg.StatsFlushDuration())
	defer ticker.Stop()

	for {
		select {
		case <-stopDBWorker:
			log.Println("🛑 收到退出信号，准备执行最后一次统计数据刷盘...")
			doFlush()
			return
		case <-ticker.C:
			doFlush()
		}
	}
}

// 内部函数：执行一次遍历和刷盘
func doFlush() {
	snapshot := make(map[string]int64)

	DomainStatsMap.Range(func(key, value any) bool {
		domain := key.(string)
		countPtr := value.(*int64)

		delta := atomic.SwapInt64(countPtr, 0)
		if delta > 0 {
			snapshot[domain] = delta
		} else {
			// 防爆内存：如果一段时间内无人访问该域名，直接从 Map 删除
			DomainStatsMap.Delete(key)
		}
		return true
	})

	if len(snapshot) > 0 {
		FlushToMySQL(snapshot)
	}
}

// FlushToMySQL 执行批量 Upsert 写入 (带 Chunk 分块防超长 SQL)
func FlushToMySQL(snapshot map[string]int64) {
	if len(snapshot) == 0 {
		return
	}

	const batchSize = 1000
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

		if count >= batchSize {
			executeBatch(placeholders, vals)
			placeholders = placeholders[:0]
			vals = vals[:0]
			count = 0
		}
	}

	if count > 0 {
		executeBatch(placeholders, vals)
	}

	// log.Printf("📈 成功将 %d 个域名的增量访问数据合并刷入 MySQL！", totalProcessed)
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
