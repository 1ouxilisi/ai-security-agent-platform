# SecurityAI Platform 企业级部署手册

> 版本: v1.0.0 | 最后更新: 2026-09-12 | 适用环境: 生产环境 / 私有化部署

---

## 一、概述

### 1.1 产品定位

SecurityAI Platform（AI安全攻防平台）是一款基于人工智能驱动的攻防兼备安全评估平台。它融合了 AI 智能分析引擎与传统安全检测能力，覆盖渗透测试、移动安全、区块链安全、AI 系统安全等 20 大安全领域，同时提供入侵检测、基线检查、日志分析、威胁狩猎等防御侧能力。平台支持完全私有化部署，适用于金融、政府、能源、互联网等对数据安全和合规性有严格要求的企业客户。

### 1.2 系统要求

| 资源 | 最低配置 | 推荐配置 | 生产推荐 |
|------|---------|---------|---------|
| CPU | 4 核 | 8 核 | 16 核+ |
| 内存 | 8 GB | 16 GB | 32 GB+ |
| 磁盘 | 100 GB SSD | 500 GB SSD | 1 TB SSD (RAID 10) |
| 操作系统 | Ubuntu 22.04 LTS / CentOS 8+ | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| Docker | 20.10+ | 24.0+ | 24.0+ |
| Docker Compose | 2.0+ | 2.20+ | 2.20+ |
| 网络 | 100 Mbps | 1 Gbps | 1 Gbps+ |

**网络端口要求:**
- 80/tcp: HTTP (Nginx, 重定向到 HTTPS)
- 443/tcp: HTTPS (Nginx, 用户访问入口)
- 22/tcp: SSH (运维管理, 建议限制来源 IP)

**内部端口 (不对外暴露):**
- 8000/tcp: 应用服务 (FastAPI, 仅 Nginx 可访问)
- 5432/tcp: PostgreSQL (仅应用可访问)
- 6379/tcp: Redis (仅应用可访问)

---

## 二、架构概览

### 2.1 整体架构

```
                    ┌─────────────────────────────────┐
                    │           用户浏览器 / API         │
                    └──────────────┬──────────────────┘
                                   │ HTTPS (443)
                                   ▼
                    ┌─────────────────────────────────┐
                    │     Nginx 反向代理 / SSL 终止     │
                    │  (限流 / 安全头 / gzip / 缓存)    │
                    └──────────────┬──────────────────┘
                                   │ HTTP (内部网络)
                                   ▼
                    ┌─────────────────────────────────┐
                    │   App 应用服务器 (FastAPI)        │
                    │   Gunicorn + 4×Uvicorn Workers  │
                    │   AI引擎 / 扫描引擎 / 防御引擎     │
                    └──────┬──────────────┬────────────┘
                           │              │
                           ▼              ▼
              ┌─────────────────┐  ┌─────────────────┐
              │  PostgreSQL 16  │  │   Redis 7       │
              │  (主数据库)     │  │  (缓存/队列)     │
              └─────────────────┘  └─────────────────┘
```

### 2.2 网络隔离设计

平台采用双层网络架构实现安全隔离:

- **security-tier (前端网络):** Nginx 与 App 之间通信，外部流量经 Nginx 进入。
- **db-tier (后端网络, internal):** 仅 App、PostgreSQL、Redis 可访问。此网络标记为 `internal: true`，完全禁止外部容器和宿主机直接访问数据库，即使 Docker 网络配置错误也不会导致数据库暴露。

---

## 三、私有化部署步骤

### 3.1 环境准备

**第一步: 安装 Docker 与 Docker Compose**

```bash
# Ubuntu 22.04 安装 Docker
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# 验证安装
docker --version
docker compose version
```

**第二步: 配置防火墙**

```bash
# 仅开放必要端口
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp       # SSH (建议限制来源 IP)
sudo ufw allow 80/tcp       # HTTP
sudo ufw allow 443/tcp      # HTTPS
sudo ufw enable
```

**第三步: 创建部署目录**

```bash
sudo mkdir -p /opt/security-platform
cd /opt/security-platform
# 将项目代码拷贝到此目录
```

### 3.2 配置文件修改

**第一步: 创建 .env 文件**

```bash
cp .env.example .env
```

编辑 `.env` 文件，逐项配置以下关键参数:

| 配置项 | 说明 | 示例 |
|--------|------|------|
| `POSTGRES_USER` | 数据库用户名 | `security_admin` |
| `POSTGRES_PASSWORD` | 数据库密码 (必须修改!) | 生成 32 位随机字符串 |
| `POSTGRES_DB` | 数据库名 | `security_platform` |
| `REDIS_PASSWORD` | Redis 密码 (必须修改!) | 生成 32 位随机字符串 |
| `JWT_SECRET_KEY` | JWT 签名密钥 (必须修改!) | `openssl rand -hex 32` |
| `ENCRYPTION_MASTER_KEY` | 数据加密主密钥 (必须修改!) | `openssl rand -hex 32` |
| `API_AUTH_KEY` | API 认证密钥 | 生成高强度随机字符串 |
| `LLM_API_KEY` | 大模型 API Key | 填入你的 LLM 服务商 Key |
| `LLM_BASE_URL` | 大模型 API 地址 | `https://api.deepseek.com/v1` |
| `LLM_MODEL` | 模型名称 | `deepseek-chat` |
| `SCAN_RATE_LIMIT` | 扫描速率限制 | `10` (请求/秒) |
| `MAX_CONCURRENCY` | 最大并发扫描数 | `5` |
| `SAAS_ENABLED` | 是否启用多租户 | `false` (私有化部署设为 false) |

**生成随机密钥的命令:**
```bash
# 生成 JWT 密钥
openssl rand -hex 32

# 生成数据库密码
openssl rand -base64 24
```

### 3.3 SSL 证书配置

平台强制使用 HTTPS，支持三种证书配置方式:

**方式一: Let's Encrypt (推荐生产环境)**

```bash
# 安装 Certbot
sudo apt-get install -y certbot

# 获取证书 (需要域名已解析到服务器)
sudo certbot certonly --standalone -d security.example.com

# 证书路径
# /etc/letsencrypt/live/security.example.com/fullchain.pem
# /etc/letsencrypt/live/security.example.com/privkey.pem

# 将证书拷贝到 Docker certs 卷
sudo mkdir -p deploy/certs
sudo cp /etc/letsencrypt/live/security.example.com/fullchain.pem deploy/certs/
sudo cp /etc/letsencrypt/live/security.example.com/privkey.pem deploy/certs/

# 设置自动续期 (每月执行)
echo "0 0 1 * * certbot renew --quiet && docker restart security-platform-nginx" | sudo crontab -
```

**方式二: 企业 CA 证书**

将企业签发的证书放入 `deploy/certs/` 目录:
```bash
cp your-company-fullchain.pem deploy/certs/fullchain.pem
cp your-company-privkey.pem deploy/certs/privkey.pem
```

**方式三: 自签名证书 (仅测试用)**

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout deploy/certs/privkey.pem \
  -out deploy/certs/fullchain.pem \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=Test/CN=security.example.com"
```

### 3.4 启动服务

```bash
# 构建镜像并启动 (首次部署)
docker compose up -d --build

# 查看服务状态
docker compose ps

# 查看应用日志
docker compose logs -f app

# 查看 Nginx 日志
docker compose logs -f nginx
```

预期输出: 4 个服务全部为 `Up` 状态，app 和 nginx 的健康检查为 `healthy`。

### 3.5 初始化配置

**第一步: 数据库迁移**

```bash
# 进入 app 容器执行数据库迁移
docker compose exec app python -m scripts.migrate

# 或手动执行 (如果有 alembic)
docker compose exec app alembic upgrade head
```

**第二步: 创建管理员账号**

```bash
# 创建初始管理员
docker compose exec app python -m scripts.create_admin \
  --username admin \
  --password "YourStrongPassword123!" \
  --email admin@yourcompany.com
```

**第三步: 配置默认扫描策略**

登录控制台后，进入「系统设置 → 扫描配置」，确认以下参数:
- 允许扫描的目标范围 (授权资产 IP/CIDR 列表)
- 扫描速率限制 (默认 10 请求/秒)
- 漏洞库自动更新频率 (默认每日同步)

### 3.6 验证部署

**第一步: 健康检查**

```bash
# 检查应用健康状态
curl -k https://localhost/health
# 预期返回: {"status": "healthy", "version": "1.0.0"}
```

**第二步: 登录控制台**

1. 浏览器访问 `https://security.example.com`
2. 使用管理员账号登录
3. 确认 Dashboard 正常加载，各模块菜单可见

**第三步: 首次扫描验证**

1. 进入「安全评估 → 新建扫描」
2. 输入一个测试目标 (如 `scanme.nmap.org`，需确保已获授权)
3. 选择「快速扫描」模板
4. 等待扫描完成，确认报告正常生成
5. 检查报告内容包含漏洞列表、风险评级、修复建议

---

## 四、Kubernetes 部署步骤

### 4.1 前置条件

- Kubernetes 集群版本 1.25+
- 已安装 ingress-nginx controller
- 已配置 StorageClass (用于 PVC 动态供给)
- kubectl 已配置集群访问

### 4.2 部署步骤

```bash
# 第一步: 创建命名空间
kubectl create namespace security-platform

# 第二步: 创建 PVC (持久化存储)
kubectl apply -f deploy/kubernetes/pvc.yaml

# 第三步: 创建 ConfigMap (非敏感配置)
kubectl apply -f deploy/kubernetes/configmap.yaml

# 第四步: 创建 Secret (敏感配置)
# !!! 重要: 先编辑 secret.yaml，将 base64 占位符替换为真实值 !!!
# 生成方法: echo -n "your-value" | base64
kubectl apply -f deploy/kubernetes/secret.yaml

# 第五步: 创建 Deployment
kubectl apply -f deploy/kubernetes/deployment.yaml

# 第六步: 创建 Service
kubectl apply -f deploy/kubernetes/service.yaml

# 第七步: 创建 Ingress (需要域名和 TLS 证书)
# 先创建 TLS Secret:
kubectl create secret tls security-platform-tls \
  --cert=fullchain.pem --key=privkey.pem \
  -n security-platform
# 然后应用 Ingress
kubectl apply -f deploy/kubernetes/ingress.yaml
```

### 4.3 验证部署

```bash
# 查看 Pod 状态
kubectl get pods -n security-platform

# 查看 Service
kubectl get svc -n security-platform

# 查看 Ingress
kubectl get ingress -n security-platform

# 查看应用日志
kubectl logs -f deployment/security-platform-app -n security-platform

# 端口转发测试 (外部访问前)
kubectl port-forward svc/security-platform-service 8000:8000 -n security-platform
curl http://localhost:8000/health
```

### 4.4 扩缩容

```bash
# 手动扩容到 5 个副本
kubectl scale deployment security-platform-app --replicas=5 -n security-platform

# 配置自动扩缩容 (HPA)
kubectl autoscale deployment security-platform-app \
  --cpu-percent=70 \
  --min=3 \
  --max=10 \
  -n security-platform
```

---

## 五、数据备份策略

### 5.1 PostgreSQL 定时备份

**创建备份脚本 `/opt/backup/pg_backup.sh`:**

```bash
#!/bin/bash
BACKUP_DIR="/opt/backup/postgres"
DATE=$(date +%Y%m%d_%H%M%S)
CONTAINER="security-platform-db"
DB_USER="security_admin"
DB_NAME="security_platform"

mkdir -p $BACKUP_DIR

# 执行备份
docker exec $CONTAINER pg_dump -U $DB_USER $DB_NAME | gzip > $BACKUP_DIR/pg_backup_$DATE.sql.gz

# 保留最近 30 天的备份
find $BACKUP_DIR -name "pg_backup_*.sql.gz" -mtime +30 -delete

echo "Backup completed: pg_backup_$DATE.sql.gz"
```

**配置 crontab (每日凌晨 2 点执行):**

```bash
chmod +x /opt/backup/pg_backup.sh
echo "0 2 * * * /opt/backup/pg_backup.sh >> /opt/backup/backup.log 2>&1" | sudo crontab -
```

### 5.2 Redis 持久化

Redis 已配置 AOF (Append Only File) 持久化和 RDB 快照:
- AOF: `appendonly yes`, `appendfsync everysec` (每秒同步一次)
- RDB: `save 900 1` (900 秒内有 1 个 key 变化则快照)

数据存储在 Docker Volume `redis_data` 中，重启不丢失。

**Redis 手动备份:**
```bash
docker exec security-platform-redis redis-cli -a "$REDIS_PASSWORD" BGSAVE
docker cp security-platform-redis:/data/dump.rdb /opt/backup/redis/dump_$(date +%Y%m%d).rdb
```

### 5.3 应用数据备份

应用数据 (扫描结果、报告、资产库) 存储在 Docker Volume `app_data` 中:

```bash
# 备份应用数据卷
docker run --rm -v security-platform_app_data:/data -v /opt/backup/app:/backup alpine \
  tar czf /backup/app_data_$(date +%Y%m%d).tar.gz -C /data .
```

### 5.4 备份验证

每周执行一次备份恢复验证:
```bash
# 恢复到测试环境
docker compose -f docker-compose.test.yml up -d db
gunzip < /opt/backup/postgres/pg_backup_YYYYMMDD.sql.gz | \
  docker exec -i security-platform-test-db psql -U security_admin security_platform

# 验证数据完整性
docker exec security-platform-test-db psql -U security_admin -c "SELECT COUNT(*) FROM scans;"
```

### 5.5 异地备份

每周将备份文件同步到异地存储 (如对象存储 OSS/S3):
```bash
# 使用 rclone 同步到 S3
rclone copy /opt/backup/ s3:security-platform-backup/weekly/

# 或使用 rsync 同步到另一台服务器
rsync -avz /opt/backup/ backup-server:/mnt/backup/security-platform/
```

---

## 六、升级流程

### 6.1 标准升级流程

```bash
# 第一步: 备份当前数据 (必须!)
/opt/backup/pg_backup.sh

# 第二步: 拉取最新代码/镜像
cd /opt/security-platform
git pull origin main
# 或拉取新镜像:
# docker pull security-platform:v1.1.0

# 第三步: 更新 .env 配置 (如有新增配置项)
diff .env.example .env

# 第四步: 重建并启动
docker compose up -d --build

# 第五步: 执行数据库迁移
docker compose exec app python -m scripts.migrate

# 第六步: 验证
curl -k https://localhost/health
docker compose ps
```

### 6.2 回滚方案

```bash
# 回滚到上一个版本
docker compose down
# 切换到上一个版本的代码/镜像
git checkout v1.0.0
# 恢复数据库备份
gunzip < /opt/backup/postgres/pg_backup_YYYYMMDD.sql.gz | \
  docker exec -i security-platform-db psql -U security_admin security_platform
docker compose up -d
```

---

## 七、灾备方案

### 7.1 主从复制架构

PostgreSQL 配置流复制 (Streaming Replication):
- 主库: 写入操作
- 从库: 只读查询 + 故障自动切换

RTO (恢复时间目标): < 30 分钟
RPO (恢复点目标): < 5 分钟

### 7.2 灾难恢复演练

每季度执行一次完整的灾难恢复演练:
1. 在备用环境恢复数据库备份
2. 启动应用服务
3. 执行健康检查和功能验证
4. 记录 RTO 和 RPO 实际值
5. 优化恢复流程

---

## 八、监控与告警

### 8.1 监控指标 (Prometheus)

平台暴露 `/metrics` 端点，包含以下指标:
- HTTP 请求量 / 延迟 / 错误率
- 扫描任务执行数 / 成功率 / 平均耗时
- AI 引擎调用次数 / Token 消耗 / 响应时间
- 数据库连接池使用率
- Redis 缓存命中率
- 容器 CPU / 内存 / 磁盘使用率

### 8.2 日志收集

使用 ELK Stack (Elasticsearch + Logstash + Kibana) 收集:
- 应用日志 (Gunicorn access/error log)
- Nginx 访问/错误日志
- PostgreSQL 慢查询日志
- 安全审计日志

### 8.3 告警规则

| 告警项 | 条件 | 级别 | 通知方式 |
|--------|------|------|---------|
| 服务不可用 | 健康检查失败 3 次 | P0 | 电话 + 短信 + 邮件 |
| CPU 使用率 > 90% | 持续 5 分钟 | P1 | 邮件 + 钉钉 |
| 内存使用率 > 85% | 持续 5 分钟 | P1 | 邮件 + 钉钉 |
| 磁盘使用率 > 80% | 持续 10 分钟 | P2 | 邮件 |
| 扫描失败率 > 10% | 持续 10 分钟 | P1 | 邮件 + 钉钉 |
| 新高危漏洞发现 | CVSS >= 9.0 | P1 | 邮件 + 钉钉 + Webhook |
| 数据库连接池耗尽 | 使用率 100% | P0 | 电话 + 短信 |

---

## 九、安全加固

### 9.1 操作系统加固

- 禁用 root SSH 登录，使用密钥认证
- 配置自动安全更新: `unattended-upgrades`
- 关闭不必要的系统服务
- 配置 fail2ban 防止暴力破解
- 磁盘加密 (LUKS)

### 9.2 容器安全

- 应用以非 root 用户运行 (appuser)
- 容器镜像定期漏洞扫描 (Trivy)
- 只读根文件系统 (如可能)
- 限制容器 capabilities
- 禁止特权容器

### 9.3 网络隔离

- 数据库和 Redis 仅内部网络可达 (internal network)
- 防火墙仅开放 80/443/22 端口
- Nginx 限流防止 DDoS
- WAF 规则拦截常见 Web 攻击

### 9.4 密钥管理

- 所有密钥存储在 .env 文件或 Kubernetes Secret 中
- .env 文件权限设为 600 (仅所有者可读写)
- 定期轮换密钥 (每 90 天)
- 禁止将密钥提交到 Git 仓库

---

## 十、性能调优

### 10.1 数据库参数调优

```ini
# postgresql.conf 关键参数 (16GB 内存场景)
shared_buffers = 4GB              # 总内存的 25%
effective_cache_size = 12GB       # 总内存的 75%
maintenance_work_mem = 64MB
work_mem = 16MB
max_connections = 100
random_page_cost = 1.1            # SSD 优化
effective_io_concurrency = 200
```

### 10.2 应用并发调优

- Gunicorn workers: `2 × CPU + 1` (2 核 CPU → 5 workers)
- `max_requests=1000`: 防止内存泄漏
- 数据库连接池大小: 每个实例 20 连接 × 3 实例 = 60 总连接

### 10.3 Nginx 调优

- `worker_connections 4096`: 支持高并发
- `keepalive 32`: 上游长连接复用
- gzip 压缩: 减少 60-80% 带宽
- 静态资源缓存 7 天: 减少后端压力

---

## 十一、常见问题排查 (FAQ)

**Q1: 容器启动后健康检查失败，应用无法访问?**

A: 检查应用日志 `docker compose logs app`。常见原因: 数据库连接失败 (检查 DATABASE_URL 配置)、LLM API Key 未配置、端口被占用。确保 PostgreSQL 和 Redis 先于应用启动 (depends_on + healthcheck)。

**Q2: 扫描任务一直排队不执行?**

A: 检查 `MAX_CONCURRENCY` 配置和 Redis 连接。扫描任务通过 Redis 队列分发，如果 Redis 密码错误或不可达，任务会堆积。执行 `docker compose exec redis redis-cli -a "密码" ping` 验证 Redis 连通性。

**Q3: Nginx 返回 502 Bad Gateway?**

A: 502 表示 Nginx 无法连接到后端应用。检查: 1) 应用容器是否运行 `docker compose ps`；2) 应用健康检查是否通过；3) Nginx upstream 配置中的服务名是否正确 (应为 `app:8000`)。

**Q4: 大文件上传被拒绝 (413 错误)?**

A: Nginx 默认 `client_max_body_size` 为 1MB。已在配置中设为 100m，如果仍有限制，检查是否有额外的反向代理层 (如云厂商 LB) 需要调整。

**Q5: 数据库磁盘空间不足?**

A: 1) 清理旧的扫描结果和报告 (`REPORT_RETENTION_DAYS`)；2) 清理 PostgreSQL 日志 (`pg_log`)；3) 执行 VACUUM ANALYZE；4) 扩展数据卷。

**Q6: AI 引擎响应慢或超时?**

A: 1) 检查 LLM API 的响应时间和配额；2) 确认 `LLM_BASE_URL` 和 `LLM_API_KEY` 配置正确；3) 调整 `SCAN_RATE_LIMIT` 降低并发；4) 考虑使用更快的模型 (如从 deepseek-reasoner 切换到 deepseek-chat)。

**Q7: HTTPS 证书过期?**

A: Let's Encrypt 证书 90 天过期，已配置自动续期。手动续期: `sudo certbot renew --force-renewal && docker restart security-platform-nginx`。企业证书请联系 CA 续签后替换证书文件并重启 Nginx。

**Q8: 如何查看实时扫描进度?**

A: 登录控制台 → 「任务中心」→ 点击对应任务查看实时日志流。平台通过 WebSocket 推送实时进度。也可通过 API: `GET /api/v1/scans/{task_id}/status`。

**Q9: 数据备份恢复后应用无法启动?**

A: 确保恢复的数据库版本与应用版本兼容。恢复前先确认: 1) PostgreSQL 版本一致；2) 执行了 `alembic upgrade head` 迁移到最新 schema；3) 检查 `DATABASE_URL` 连接串是否正确。

**Q10: 多副本部署时扫描任务重复执行?**

A: 平台使用 Redis 分布式锁确保扫描任务不重复执行。如果出现重复，检查: 1) Redis 连接是否正常；2) 锁超时时间是否合理；3) 是否所有副本连接的是同一个 Redis 实例。

---

## 十二、技术支持

- **邮箱:** support@securityai-platform.com
- **企业微信:** SecurityAI 技术支持群
- **官网:** https://www.securityai-platform.com
- **文档中心:** https://docs.securityai-platform.com
- **紧急故障 (P0):** 7×24 小时热线 400-XXX-XXXX

---

*本手册随产品版本持续更新，请以最新版为准。*
