# DNS Firewall — Kubernetes 部署与运维指南

> **版本**: v1.0 | **最后更新**: 2026-05-14

---

## 一、架构总览

```
                          ┌─────────────────────────────┐
                          │  DNS Client (internet)        │
                          └──────────────┬──────────────┘
                                         │ UDP :53
                                         ▼
                    ┌────────────────────────────────────┐
                    │  LoadBalancer Service (external)     │
                    │  externalTrafficPolicy: Local         │
                    └───────┬─────────────┬──────────────┘
                            │             │
                   ┌────────▼──┐    ┌─────▼─────┐
                   │ Pod-1     │    │ Pod-2     │  ...  Pod-N
                   │ SO_REUSE  │    │ SO_REUSE  │
                   │ PORT      │    │ PORT      │
                   │ ReadBatch │    │ ReadBatch │
                   └──┬───┬────┘    └──┬───┬────┘
                      │   │            │   │
            ┌─────────▼┐  └────────────▼┐  │
            │  MySQL   │                │  │
            │  State   │    ┌───────────▼──▼──────┐
            │  fulSet  │    │    Redis              │
            │          │    │    StatefulSet        │
            └──────────┘    └──────────────────────┘

            ┌──────────────────────────────────────┐
            │  Prometheus (ServiceMonitor)          │
            │  /metrics → dns_queries_total         │
            │              dns_cache_hits_total     │
            │              dns_blocked_total        │
            │              dns_request_duration     │
            └──────────────────────────────────────┘

            ┌──────────────────────────────────────┐
            │  HPA: min=3 / max=20                  │
            │  触发器: CPU > 70% | Memory > 80%      │
            └──────────────────────────────────────┘
```

| 组件 | 资源类型 | 副本数 | 暴露方式 |
|------|---------|--------|---------|
| DNS Firewall | Deployment | 3 (base) / 5 (prod) | LoadBalancer UDP :53 |
| MySQL | StatefulSet | 1 | ClusterIP (headless) |
| Redis | StatefulSet | 1 | ClusterIP (headless) |

---

## 二、快速部署

### 2.1 前置条件

- Kubernetes 集群 ≥ v1.25
- 已安装 `kubectl`
- 可选：`kustomize`（已内置于 kubectl v1.25+）
- 可选：Prometheus Operator（ServiceMonitor CRD）
- 集群支持 LoadBalancer 类型 Service（云厂商）或 MetalLB（裸金属）

### 2.2 构建镜像

```bash
# 构建并推送到你的镜像仓库
docker build -t your-registry/dns-firewall:v1.0 .
docker push your-registry/dns-firewall:v1.0

# 更新 kustomization 中的镜像引用
cd k8s/base
kustomize edit set image dns-firewall=your-registry/dns-firewall:v1.0
```

### 2.3 部署基础环境

```bash
# 方式一：一键部署（开发/测试）
kubectl apply -k k8s/base/

# 方式二：生产环境
kubectl apply -k k8s/overlays/production/

# 查看部署状态
kubectl get all -n dns-firewall

# 等待所有 Pod 就绪
kubectl wait --for=condition=ready pod -l app=dns-firewall -n dns-firewall --timeout=300s
```

### 2.4 验证

```bash
# 获取外部 IP
DNS_LB=$(kubectl get svc dns-firewall -n dns-firewall -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo "DNS 防火墙地址: $DNS_LB"

# 测试 DNS 查询
dig @$DNS_LB google.com +short

# 测试健康检查
kubectl port-forward -n dns-firewall svc/dns-firewall 2112:2112 &
curl http://localhost:2112/healthz   # → "ok"
curl http://localhost:2112/readyz    # → "ready"
curl http://localhost:2112/metrics   # Prometheus metrics
```

---

## 三、K8s 资源清单说明

### 3.1 目录结构

```
k8s/
├── base/                          # 基础配置（所有环境共享）
│   ├── kustomization.yaml         # Kustomize 编排入口
│   ├── namespace.yaml             # 命名空间隔离
│   ├── secret.yaml                # MySQL/Redis 密码
│   ├── configmap.yaml             # DNS Firewall 运行时配置
│   ├── initdb-configmap.yaml      # MySQL 初始化 SQL
│   ├── mysql-statefulset.yaml     # MySQL 有状态部署
│   ├── mysql-svc.yaml             # MySQL 无头服务
│   ├── redis-statefulset.yaml     # Redis 有状态部署
│   ├── redis-svc.yaml             # Redis 无头服务
│   ├── deployment.yaml            # DNS Firewall 无状态部署
│   ├── service.yaml               # DNS LoadBalancer + Metrics
│   ├── hpa.yaml                   # 水平自动伸缩
│   ├── pdb.yaml                   # Pod 中断预算
│   ├── servicemonitor.yaml        # Prometheus 服务发现
│   └── network-policy.yaml        # 零信任网络策略
└── overlays/
    └── production/                # 生产环境覆盖
        ├── kustomization.yaml     # 5 副本 + 更高资源配额
        └── .env.secret            # 生产环境密钥（gitignore）
```

### 3.2 关键设计决策

#### SO_REUSEPORT — 内核级多 Pod 负载均衡

每个 Pod 在 `net.ListenConfig` 中已设置 `SO_REUSEPORT`，K8s 节点上的多个 Pod 共享同一个端口时，内核通过哈希将 UDP 包均衡分发到不同 Pod 的 socket。这比 K8s Service 的 iptables 负载均衡更高效——省去了 DNAT 转发开销。

#### externalTrafficPolicy: Local

设置为 `Local` 可避免跨节点转发，确保来源 IP 在 `processRequest()` 中的 `ClientIPBlocker` 检查有效。配合 `podAntiAffinity` 优先分散调度。

#### Readiness Probe — 暖启动保护

`/readyz` 端点仅在 `InitSystem()` 全部成功后返回 200（`metrics.SetReady()` 调用）。在 MySQL/Redis 初始化完成前，Pod 不会被加入 Service 端点，防止请求打到未就绪的 Pod。

#### Graceful Shutdown — 流量排干

1. K8s 发送 SIGTERM → 5 秒 drain（`SetNotReady()` + `time.Sleep`）
2. 关闭 UDP listener → 拒绝新连接
3. 等待 reader goroutine 退出
4. 关闭 Redis → 刷空写入队列
5. 关闭 MySQL → 最后一次刷盘统计数据

`terminationGracePeriodSeconds: 60` 给足了上述流程的执行时间。

#### 网络策略 — 零信任安全

仅放行：
- **入站**: UDP :8053 (DNS 查询) + TCP :2112 (metrics)
- **出站**: MySQL :3306 + Redis :6379 + 公网 :53 (上游 DNS)

---

## 四、HPA 弹性伸缩

| 参数 | base | production |
|------|------|------------|
| minReplicas | 3 | 5 |
| maxReplicas | 20 | 30 |
| CPU 目标 | 70% | 70% |
| 内存目标 | 80% | 80% |
| 扩容冷却 | 60s | 60s |
| 缩容冷却 | 300s | 300s |

> 根据压测数据：单 Pod 在 Apple M2 下支持 ~27k QPS，CPU 约 25%（2 核）。在典型 8 核节点上，预计单 Pod 饱和 QPS > 50k。

### 触发 HPA 压测

```bash
# 模拟大量 DNS 查询触发扩容
dnsperf -s $DNS_LB -p 53 -d bench_queries.txt -c 200 -T 8 -l 300 -Q 200000

# 观察 HPA
kubectl get hpa -n dns-firewall -w
```

---

## 五、可观测性

### 5.1 Prometheus 指标

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| `dns_queries_total` | Counter | — | 总查询数 |
| `dns_cache_hits_total` | CounterVec | `layer` (L1/Miss) | 缓存命中 |
| `dns_blocked_total` | CounterVec | `reason` (ClientIP/Domain/TargetIP) | 安全拦截 |
| `dns_request_duration_seconds` | Histogram | — | 延迟分布 |

### 5.2 Grafana 告警规则建议

```yaml
# 示例告警规则
- alert: DNSHighErrorRate
  expr: rate(dns_blocked_total[5m]) / rate(dns_queries_total[5m]) > 0.05
  annotations:
    summary: "DNS 拦截率超过 5%"

- alert: DNSHighLatency
  expr: histogram_quantile(0.99, rate(dns_request_duration_seconds_bucket[5m])) > 0.5
  annotations:
    summary: "DNS P99 延迟超过 500ms"
```

---

## 六、运维操作

### 6.1 滚动更新

```bash
# 更新镜像
kubectl set image deployment/dns-firewall dns-firewall=your-registry/dns-firewall:v1.1 -n dns-firewall

# 监控更新过程
kubectl rollout status deployment/dns-firewall -n dns-firewall

# 回滚
kubectl rollout undo deployment/dns-firewall -n dns-firewall
```

### 6.2 安全规则热更新

```bash
# 进入 MySQL Pod
kubectl exec -it -n dns-firewall statefulset/mysql -- mysql -u dns_user -p dns

# 插入新规则（无需重启，每秒自动同步）
INSERT INTO security_rules (rule_type, rule_value, description)
VALUES ('domain', 'evil.com.', '紧急拦截恶意域名');

# 禁用某条规则
UPDATE security_rules SET is_enabled = 0 WHERE id = 5;
```

DNS Firewall 内部每 1 分钟自动从 MySQL 拉取规则并原子替换 —— **零停机热更新**。

### 6.3 日志查看

```bash
kubectl logs -f deployment/dns-firewall -n dns-firewall --tail=100
kubectl logs -f statefulset/mysql -n dns-firewall
kubectl logs -f statefulset/redis -n dns-firewall
```

---

## 七、可用的环境变量覆盖

在 K8s 中通过 `env` 字段注入，覆盖 ConfigMap 中的值：

| 环境变量 | ConfigMap 对应字段 |
|----------|-------------------|
| `DNS_LISTEN` | server.listen |
| `DNS_METRICS_ADDR` | server.metrics_addr |
| `DNS_SOCKET_POOL_SIZE` | server.socket_pool_size |
| `DNS_UPSTREAM_TIMEOUT` | upstream.timeout |
| `MYSQL_HOST` | mysql.host |
| `MYSQL_PORT` | mysql.port |
| `MYSQL_USER` | mysql.user |
| `MYSQL_PASSWORD` | mysql.password |
| `MYSQL_DATABASE` | mysql.database |
| `REDIS_ADDR` | redis.addr |
| `REDIS_PASSWORD` | redis.password |
| `CACHE_SIZE` | cache.local_cache_size |

---

## 八、删除所有资源

```bash
kubectl delete namespace dns-firewall
```

> **注意**：MySQL 和 Redis 的 PersistentVolumeClaim 不会被自动删除，需手动清理或在 StatefulSet 删除后执行：
> ```bash
> kubectl delete pvc -l app=mysql -n dns-firewall
> kubectl delete pvc -l app=redis -n dns-firewall
> ```
