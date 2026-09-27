# AI Hacking Agent 部署文档 (DEPLOY.md)

本文档说明如何在生产 / 私有化环境中一键部署 AI Hacking Agent 平台。

---

## 1. 系统要求

| 组件 | 最低版本 | 推荐 |
| --- | --- | --- |
| OS | Linux x86_64 / Windows 10+ / macOS 12+ | Ubuntu 22.04 LTS |
| Docker | 20.10+ | 24.x / 29.x |
| Docker Compose | V2 插件 | `docker compose` 可用 |
| CPU / 内存 | 2 核 / 4 GB | 4 核 / 8 GB |
| 磁盘 | 20 GB | 50 GB SSD |
| 端口 | 8000 (应用) | 可选 5432 / 6379 |

> 本机已验证环境：Docker v29.6.1、Python 3.11+。

---

## 2. Docker 一键部署（推荐）

### 2.1 克隆 / 进入项目

```bash
cd ai-hacking-agent
```

### 2.2 （可选）准备环境变量

```bash
cp .env.example .env
# 编辑 .env，至少修改：
#   POSTGRES_PASSWORD / REDIS_PASSWORD / JWT_SECRET_KEY / LICENSE_MASTER_KEY
```

### 2.3 执行一键部署

```bash
chmod +x deploy.sh
./deploy.sh
```

脚本将自动：
1. 检查 Docker / Docker Compose 环境；
2. 构建镜像 `ai-hacking-agent:latest`；
3. 启动 `app` + `db`(PostgreSQL) + `redis` 三个容器；
4. 轮询 `http://localhost:8000/health` 直到通过；
5. 输出访问地址。

部署成功后访问：

- 平台首页：<http://localhost:8000>
- 健康检查：<http://localhost:8000/health>
- License 管理控制台：<http://localhost:8000/license-management>

### 2.4 常用命令

```bash
./deploy.sh build     # 仅构建镜像
./deploy.sh up        # 启动已构建服务
./deploy.sh logs      # 跟踪应用日志
./deploy.sh health    # 手动触发健康检查
./deploy.sh down      # 停止并移除容器（数据卷保留）
./deploy.sh rebuild   # 重新构建并重启
```

也可直接使用 `docker compose`：

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f app
docker compose down
```

---

## 3. 手动部署（不使用 Docker）

### 3.1 安装系统依赖

```bash
# Debian / Ubuntu
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv curl
```

### 3.2 创建虚拟环境并安装依赖

```bash
cd ai-hacking-agent
python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3.3 创建运行目录

```bash
mkdir -p data logs reports uploads temp
```

### 3.4 启动服务

```bash
uvicorn api_server.app:app --host 0.0.0.0 --port 8000
```

生产环境建议使用多 worker：

```bash
uvicorn api_server.app:app --host 0.0.0.0 --port 8000 \
    --workers 4 --timeout-keep-alive 30
```

---

## 4. 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `APP_ENV` | `production` | 运行环境 |
| `API_HOST` | `0.0.0.0` | 监听地址 |
| `API_PORT` | `8000` | 监听端口 |
| `LOG_LEVEL` | `INFO` | 日志级别 |
| `DATABASE_URL` | （内部） | PostgreSQL 连接串 |
| `REDIS_URL` | （内部） | Redis 连接串 |
| `POSTGRES_USER` | `aiah_user` | 数据库用户 |
| `POSTGRES_PASSWORD` | `aiah_pass` | 数据库密码（**生产必改**） |
| `POSTGRES_DB` | `aiah` | 数据库名 |
| `REDIS_PASSWORD` | `aiah_redis` | Redis 密码（**生产必改**） |
| `JWT_SECRET_KEY` | `change-me-...` | JWT 签名密钥 |
| `LICENSE_MASTER_KEY` | `change-me-...` | License 签名主密钥 |

---

## 5. 数据卷与持久化

`docker-compose.yml` 已声明以下命名卷：

| 卷 | 容器内路径 | 用途 |
| --- | --- | --- |
| `app_data` | `/app/data` | 业务数据 / 扫描结果 |
| `app_logs` | `/app/logs` | 运行日志 |
| `app_reports` | `/app/reports` | 生成的报告 |
| `pg_data` | `/var/lib/postgresql/data` | PostgreSQL 数据 |
| `redis_data` | `/data` | Redis AOF 持久化 |

> `docker compose down` 不会删除卷；如需彻底清理，执行
> `docker compose down -v`。

---

## 6. 常见问题 (FAQ)

**Q1: `docker compose up` 报 `permission denied while trying to connect to the Docker daemon socket`**
A: 当前用户不在 `docker` 组。执行 `sudo usermod -aG docker $USER` 后重新登录，或使用 `sudo ./deploy.sh`。

**Q2: 健康检查一直失败？**
A: 查看日志：`docker compose logs app`。常见原因：
- 8000 端口被占用：修改 `.env` 中 `APP_PORT`，或编辑 `docker-compose.yml` 的 `ports`；
- 首次启动需要安装依赖，等待 30~60 秒；
- 检查 `api_server.app:app` 是否能正常导入。

**Q3: 如何完全重置环境？**
A: `docker compose down -v && docker compose build --no-cache && ./deploy.sh`。

**Q4: 容器时区不对？**
A: 镜像已默认设置 `Asia/Shanghai`。如需其他时区，在 `docker-compose.yml` 中追加 `TZ: Asia/Shanghai` 环境变量。

**Q5: 如何对外开放 HTTPS？**
A: 本镜像仅暴露 HTTP 8000。生产环境建议在前面挂载 Nginx / Caddy / 云负载均衡做 TLS 终止，并将 8000 端口限制在内部网络。

**Q6: License 系统在哪？**
A: 启动后访问 `/license-management`，可输入 License Key 激活、查看当前版本 / 到期时间 / 功能列表，或调用管理员接口 `/api/v1/license/generate` 生成新 License。

---

## 7. 目录结构（交付物）

```
ai-hacking-agent/
├── Dockerfile              # 多阶段构建（python:3.11-slim）
├── docker-compose.yml      # app + postgres + redis 编排
├── deploy.sh                # 一键部署脚本
├── DEPLOY.md                # 本文档
└── api_server/
    ├── app.py               # 主应用（不修改）
    ├── license_real_routes.py   # License API（15+ 端点）
    └── license_console.html     # 深色主题 License 控制台
```
