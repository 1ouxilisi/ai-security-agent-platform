# AI Hacking Agent 部署指南

## 目录

1. [系统要求](#系统要求)
2. [快速开始](#快速开始)
3. [Docker部署](#docker部署)
4. [手动部署](#手动部署)
5. [生产环境配置](#生产环境配置)
6. [常见问题](#常见问题)

---

## 系统要求

### 最低配置
- **CPU**: 2核
- **内存**: 4GB
- **磁盘**: 20GB
- **操作系统**: Windows 10+ / Ubuntu 20.04+ / macOS 11+

### 推荐配置
- **CPU**: 4核+
- **内存**: 8GB+
- **磁盘**: 50GB+ SSD
- **操作系统**: Ubuntu 22.04 LTS

### 软件要求
- **Python**: 3.10+
- **Git**: 2.30+
- **可选工具**: nmap, sqlmap, metasploit-framework

---

## 快速开始

### Windows
```bash
# 1. 克隆项目
git clone https://github.com/your-repo/ai-hacking-agent.git
cd ai-hacking-agent

# 2. 运行一键安装脚本
install.bat

# 3. 启动服务
venv\Scripts\activate
python main.py api-server --host 0.0.0.0 --port 8000
```

### Linux/macOS
```bash
# 1. 克隆项目
git clone https://github.com/your-repo/ai-hacking-agent.git
cd ai-hacking-agent

# 2. 运行一键安装脚本
bash install.sh

# 3. 启动服务
source venv/bin/activate
python main.py api-server --host 0.0.0.0 --port 8000
```

### 访问地址
- 统一控制台: http://127.0.0.1:8000/console-v7
- 实战能力中心: http://127.0.0.1:8000/combat-console
- API文档: http://127.0.0.1:8000/docs
- 健康检查: http://127.0.0.1:8000/health

---

## Docker部署

### 方式1：使用Docker Compose（推荐）

```bash
# 1. 克隆项目
git clone https://github.com/your-repo/ai-hacking-agent.git
cd ai-hacking-agent

# 2. 启动所有服务
docker-compose up -d

# 3. 查看日志
docker-compose logs -f app

# 4. 停止服务
docker-compose down
```

**服务说明：**
- `app`: 主应用服务（端口8000）
- `redis`: Redis缓存（端口6379，用于任务队列）
- `postgres`: PostgreSQL数据库（端口5432，生产环境推荐）
- `worker`: Celery异步任务Worker

### 方式2：仅启动主应用

```bash
# 构建镜像
docker build -t ai-hacking-agent .

# 运行容器
docker run -d \
  --name ai-hacking-agent \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/config:/app/config:ro \
  ai-hacking-agent

# 查看日志
docker logs -f ai-hacking-agent
```

### 环境变量配置

创建 `.env` 文件：

```bash
# 应用配置
APP_ENV=production
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=INFO

# 数据库配置（默认SQLite）
DATABASE_URL=sqlite:///data/hacking_agent.db

# PostgreSQL配置（生产环境推荐）
# DATABASE_URL=postgresql://hacking:hacking_password@postgres:5432/hacking_agent

# Redis配置（任务队列）
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/1

# LLM配置
LLM_API_KEY=your-api-key
LLM_BASE_URL=https://api.deepseek.com
LLM_MODEL=deepseek-chat

# 安全配置
API_AUTH_ENABLED=true
API_AUTH_KEY=your-secret-api-key
SECRET_KEY=your-secret-key-for-sessions

# 实战能力配置
COMBAT_ENABLED=true
COMBAT_ALLOWED_TARGETS=192.168.0.0/16,10.0.0.0/8
COMBAT_MAX_EXECUTION_TIME=3600
```

---

## 手动部署

### 1. 安装Python依赖

```bash
# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 安装依赖
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. 安装可选安全工具

**Ubuntu/Debian:**
```bash
# Nmap
sudo apt install nmap

# sqlmap
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Metasploit Framework
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

**Windows:**
- Nmap: 下载 https://nmap.org/download.html
- sqlmap: `git clone https://github.com/sqlmapproject/sqlmap.git`
- Metasploit: 下载 https://www.metasploit.com/download

### 3. 初始化配置

```bash
# 复制配置文件
cp .env.example .env

# 编辑配置
# Windows: notepad .env
# Linux/macOS: nano .env

# 创建必要目录
mkdir -p data logs uploads reports temp
```

### 4. 启动服务

```bash
# 开发模式
python main.py api-server --host 0.0.0.0 --port 8000 --reload

# 生产模式
python main.py api-server --host 0.0.0.0 --port 8000
```

### 5. 使用Gunicorn部署（生产环境推荐）

```bash
# 安装Gunicorn
pip install gunicorn uvicorn

# 启动
gunicorn main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 120 \
  --access-logfile logs/access.log \
  --error-logfile logs/error.log
```

---

## 生产环境配置

### Nginx反向代理

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # 客户端请求体大小限制
    client_max_body_size 100M;

    # 主应用
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }

    # WebSocket支持
    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### HTTPS配置（Let's Encrypt）

```bash
# 安装Certbot
sudo apt install certbot python3-certbot-nginx

# 获取证书
sudo certbot --nginx -d your-domain.com

# 自动续期
sudo certbot renew --dry-run
```

### Systemd服务配置

创建 `/etc/systemd/system/ai-hacking-agent.service`:

```ini
[Unit]
Description=AI Hacking Agent
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/ai-hacking-agent
Environment="PATH=/opt/ai-hacking-agent/venv/bin"
Environment="APP_ENV=production"
ExecStart=/opt/ai-hacking-agent/venv/bin/gunicorn main:app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 127.0.0.1:8000 \
    --timeout 120
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

启动服务：
```bash
sudo systemctl daemon-reload
sudo systemctl enable ai-hacking-agent
sudo systemctl start ai-hacking-agent
sudo systemctl status ai-hacking-agent
```

### 数据库配置

#### SQLite（默认，适合小规模）
```bash
DATABASE_URL=sqlite:///data/hacking_agent.db
```

#### PostgreSQL（生产环境推荐）
```bash
# 安装PostgreSQL
sudo apt install postgresql postgresql-contrib

# 创建数据库和用户
sudo -u postgres psql
CREATE USER hacking WITH PASSWORD 'your_secure_password';
CREATE DATABASE hacking_agent OWNER hacking;
GRANT ALL PRIVILEGES ON DATABASE hacking_agent TO hacking;
\q

# 配置环境变量
DATABASE_URL=postgresql://hacking:your_secure_password@localhost:5432/hacking_agent
```

### 日志配置

```bash
# 日志级别: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL=INFO

# 日志文件路径
LOG_FILE=logs/app.log

# 日志轮转
LOG_ROTATION=10 MB
LOG_RETENTION=30 days
```

### 安全配置

```bash
# 启用API认证
API_AUTH_ENABLED=true
API_AUTH_KEY=your-very-secure-api-key

# Session密钥
SECRET_KEY=your-very-secure-secret-key-at-least-32-chars

# CORS配置
CORS_ORIGINS=https://your-domain.com,https://www.your-domain.com

# 实战能力限制
COMBAT_ENABLED=true
COMBAT_ALLOWED_TARGETS=192.168.0.0/16,10.0.0.0/8
COMBAT_DENIED_TARGETS=127.0.0.1,localhost
COMBAT_MAX_EXECUTION_TIME=3600
COMBAT_ENABLE_AUDIT_LOG=true
```

---

## 常见问题

### Q1: 端口被占用怎么办？

```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <进程ID> /F

# Linux
sudo lsof -i :8000
sudo kill -9 <进程ID>

# 或换个端口启动
python main.py api-server --port 8001
```

### Q2: 依赖安装失败怎么办？

```bash
# 升级pip
python -m pip install --upgrade pip

# 使用国内镜像源
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 单独安装失败的包
pip install <package-name> --upgrade
```

### Q3: API服务启动后访问不了？

1. 检查防火墙是否开放8000端口
2. 检查是否绑定了0.0.0.0（不是127.0.0.1）
3. 查看日志是否有报错
4. 测试本地访问：`curl http://127.0.0.1:8000/health`

### Q4: 如何更新到最新版本？

```bash
# 拉取最新代码
git pull origin main

# 更新依赖
pip install -r requirements.txt --upgrade

# 重启服务
# systemd:
sudo systemctl restart ai-hacking-agent
# Docker:
docker-compose up -d --build
```

### Q5: 如何备份数据？

```bash
# 备份数据库
cp data/hacking_agent.db data/backup_$(date +%Y%m%d).db

# 备份配置
cp -r config config_backup_$(date +%Y%m%d)

# 备份报告
tar -czf reports_backup_$(date +%Y%m%d).tar.gz reports/

# Docker环境备份
docker-compose exec app tar -czf /app/data/backup.tar.gz /app/data /app/reports
```

### Q6: 实战能力模块需要哪些外部工具？

| 模块 | 必需工具 | 安装方式 |
|------|----------|----------|
| SQL注入 | sqlmap | `git clone https://github.com/sqlmapproject/sqlmap.git` |
| Metasploit | msfconsole | 参考 https://www.metasploit.com/download |
| 端口扫描 | nmap | `sudo apt install nmap` |
| 目录扫描 | gobuster/dirb | `sudo apt install gobuster` |
| 子域名枚举 | subfinder/amass | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |

**注意：** 未安装外部工具时，模块会自动降级为模拟模式，返回示例数据用于演示和测试。

### Q7: 如何配置LLM API？

```bash
# DeepSeek（推荐，性价比高）
LLM_API_KEY=sk-xxx
LLM_BASE_URL=https://api.deepseek.com
LLM_MODEL=deepseek-chat

# OpenAI
LLM_API_KEY=sk-xxx
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-3.5-turbo

# 硅基流动
LLM_API_KEY=sk-xxx
LLM_BASE_URL=https://api.siliconflow.cn/v1
LLM_MODEL=Qwen/Qwen2-72B-Instruct

# 本地模型（Ollama）
LLM_API_KEY=ollama
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=llama2
```

### Q8: 性能优化建议

1. **使用PostgreSQL替代SQLite** - 并发性能更好
2. **启用Redis缓存** - 减少重复计算
3. **使用Gunicorn多Worker** - 提高并发处理能力
4. **配置CDN** - 静态资源加速
5. **定期清理临时文件** - 释放磁盘空间
6. **监控内存使用** - 长时间运行可能内存泄漏

---

## 技术支持

- 文档: 查看 `docs/` 目录
- 问题反馈: GitHub Issues
- 社区讨论: GitHub Discussions

---

*最后更新: 2026-08-31*
