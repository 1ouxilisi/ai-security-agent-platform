# 安装指南

## 系统要求

- Python 3.10+
- 4GB+ 内存
- 2GB+ 磁盘空间
- 网络连接（用于API调用和工具下载）

## 快速安装

### Windows

```bash
# 1. 克隆或下载项目
git clone https://github.com/your-repo/ai-hacking-agent.git
cd ai-hacking-agent

# 2. 创建虚拟环境（推荐）
python -m venv venv
venv\Scripts\activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 配置环境变量
copy .env.example .env
# 编辑 .env 文件，填入你的API密钥

# 5. 启动服务
start.bat
```

### Linux / macOS

```bash
# 1. 克隆项目
git clone https://github.com/your-repo/ai-hacking-agent.git
cd ai-hacking-agent

# 2. 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 配置环境变量
cp .env.example .env
# 编辑 .env 文件

# 5. 启动服务
chmod +x start.sh
./start.sh
```

## Docker 部署

```bash
# 构建镜像
docker build -t ai-hacking-agent .

# 运行容器
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/.env:/app/.env \
  -v $(pwd)/data:/app/data \
  --name ai-hacking-agent \
  ai-hacking-agent

# 使用 docker-compose
docker-compose up -d
```

## 环境变量配置

编辑 `.env` 文件，至少配置以下变量：

```env
# LLM配置（必填）
LLM_API_KEY=your-api-key
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_MODEL=deepseek-chat

# API鉴权（推荐）
API_AUTH_ENABLED=true
API_AUTH_KEY=your-secret-auth-key

# 可选配置
LOG_LEVEL=INFO
MAX_CONCURRENT_TASKS=5
SCAN_TIMEOUT=300
```

## 验证安装

1. 访问 http://127.0.0.1:8000/docs 查看API文档
2. 访问 http://127.0.0.1:8000/health 检查健康状态
3. 访问 http://127.0.0.1:8000/console-v7 打开主控制台

## 常见问题

### Q: 依赖安装失败？
A: 升级pip后重试：`pip install --upgrade pip`

### Q: 端口被占用？
A: 修改启动端口：`python main.py api-server --port 8001`

### Q: LLM连接失败？
A: 检查 `.env` 中的API密钥和BASE_URL是否正确，确认网络可访问。

### Q: 如何更新项目？
A: `git pull && pip install -r requirements.txt --upgrade`
