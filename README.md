# DNS-server-by-Go

高性能 DNS 防火墙/代理服务器，基于 Go 实现。

## 架构概览

```
客户端 DNS 请求 (UDP 53)
       │
       ▼
   Nginx UDP 四层负载均衡
       │
       ├───────┬───────┐
       ▼       ▼       ▼
   DNS-Node-1  DNS-Node-2  DNS-Node-3    ← 多节点水平扩展
       │
       ▼
   ┌─────────────────────────────────┐
   │  三级安全防线                      │
   │  1. 客户端 IP 拦截 (Trie树)        │
   │  2. 恶意域名拦截 (哈希表 O(1))      │
   │  3. 解析结果 IP 拦截 (回包扫描)      │
   ├─────────────────────────────────┤
   │  两级缓存                          │
   │  L1: 本地内存 (freecache 100MB)    │
   │  L2: Redis 分布式缓存              │
   ├─────────────────────────────────┤
   │  并发竞速回源                       │
   │  同时向多个上游 DNS 发起请求，       │
   │  取最快响应                        │
   └─────────────────────────────────┘
       │
       ▼
   上游 DNS 服务器 (114DNS / 8.8.8.8 / 1.1.1.1 / 223.5.5.5)
```

## 快速开始

### 方式一：Docker Compose 一键部署（推荐）

```bash
# 启动全部服务：3个DNS节点 + Nginx负载均衡 + Redis + MySQL
docker compose up -d

# 查看运行状态
docker compose ps

# 测试 DNS 查询
dig @127.0.0.1 example.com
```

### 方式二：本地编译运行

**前置依赖：** Go 1.24+、Redis、MySQL（仅发行版需要）

```bash
# 安装依赖
go mod download

# 测试版启动（Mock 上游 DNS + Docker 本地 MySQL/Redis）
go run main.go -config config.dev.yaml

# 发行版启动
go run main.go -config config.yaml

# 编译二进制
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o dns-firewall main.go
./dns-firewall -config config.yaml
```

## 配置文件

项目提供两套配置文件，按需选择：

| 配置文件 | 用途 | 上游DNS | 数据库 |
|---|---|---|---|
| `config.dev.yaml` | 测试/开发版 | Mock (`127.0.0.1:8079`) | Docker 容器 |
| `config.yaml` | 发行版模板 | 真实上游DNS | 客户自行配置 |

通过 `-config` 参数指定：

```bash
./dns-firewall -config config.dev.yaml   # 测试版
./dns-firewall -config config.yaml       # 发行版
```

### 配置项说明

```yaml
server:
  listen: "0.0.0.0:8053"        # DNS 服务监听地址
  metrics_addr: ":2112"          # Prometheus 指标端口

upstream:
  servers:                       # 上游 DNS 服务器列表
    - "114.114.114.114:53"
    - "8.8.8.8:53"
  timeout: "200ms"               # 竞速回源超时时间

mysql:
  host: "127.0.0.1"              # MySQL 地址
  port: 3306
  user: "dns_user"
  password: "请修改为实际密码"      # 【发行版必须修改】
  database: "dns"
  rule_sync_interval: "1m"       # 安全规则同步间隔
  stats_flush_interval: "10s"    # 访问统计刷盘间隔

redis:
  addr: "127.0.0.1:6379"         # Redis 地址
  password: ""                   # Redis 密码
  db: 0
  pool_size: 500                 # 连接池大小

cache:
  local_cache_size: 104857600    # L1 本地缓存大小 (字节, 默认100MB)
  write_queue_size: 50000        # Redis 异步写入队列长度
  min_workers: 10                # 最少写入协程数
  max_workers: 1000              # 最多写入协程数

worker:
  job_queue_size: 10000          # 请求队列长度
  min_workers: 5                 # 最少处理协程数
  max_workers: 100000            # 最多处理协程数
  idle_timeout: "10m"            # 空闲协程回收时间
```

## 数据库初始化

使用 `init.sql` 初始化 MySQL 表结构和示例安全规则：

```bash
# Docker 部署会自动执行 init.sql
# 手动导入：
mysql -u root -p dns < init.sql
```

### 安全规则管理

在 `security_rules` 表中管理拦截规则，支持三种类型：

```sql
-- 拦截指定客户端 IP 或网段
INSERT INTO security_rules (rule_type, rule_value, is_enabled, description)
VALUES ('client_ip', '192.168.1.0/24', 1, '拦截内网网段');

-- 拦截恶意域名
INSERT INTO security_rules (rule_type, rule_value, is_enabled, description)
VALUES ('domain', 'ads.google.com.', 1, '拦截谷歌广告');

-- 拦截解析结果中的目标 IP
INSERT INTO security_rules (rule_type, rule_value, is_enabled, description)
VALUES ('target_ip', '10.255.255.254/32', 1, '拦截特定解析目标');
```

规则每分钟自动从数据库同步，无需重启服务。将 `is_enabled` 设为 `0` 即可禁用规则。

## 监控

Prometheus 指标暴露在 `:2112/metrics` 端点：

| 指标名 | 类型 | 说明 |
|---|---|---|
| `dns_queries_total` | Counter | 收到的 DNS 查询总数 |
| `dns_cache_hits_total` | CounterVec | 缓存命中次数（L1 / L2 / Miss） |
| `dns_blocked_total` | CounterVec | 拦截次数（ClientIP / Domain / TargetIP） |
| `dns_request_duration_seconds` | Histogram | 请求处理延迟分布 |

```bash
# 本地查看指标
curl http://localhost:2112/metrics
```

`prometheus.yml` 提供了 Prometheus 抓取配置示例。

## 运行测试

```bash
# 运行全部测试
go test ./... -v

# 运行性能压测
go test ./... -bench=. -benchmem

# 生成测试流量数据（Python脚本）
python generate_domains.py
```

## 优雅退出

服务支持优雅退出，收到 `SIGINT`（Ctrl+C）或 `SIGTERM`（Docker Stop）信号时：

1. 停止接收新 UDP 请求
2. 等待缓存异步写入队列清空
3. 执行最后一次统计数据刷盘
4. 关闭 Redis 连接
5. 关闭 MySQL 连接池
