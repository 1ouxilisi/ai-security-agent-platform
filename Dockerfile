# =============================================================================
# AI Hacking Agent - 一键部署 Dockerfile
# 基于 python:3.11-slim，多阶段构建
# 启动: uvicorn api_server.app:app --host 0.0.0.0 --port 8000
# =============================================================================

# ---------- 阶段 1: 构建阶段 ----------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# 系统构建依赖（编译 cryptography / pydantic-core 等带 C 扩展的包需要）
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 先单独拷贝依赖清单，最大化利用 Docker 层缓存
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt


# ---------- 阶段 2: 运行阶段 ----------
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="AI Hacking Agent" \
      org.opencontainers.image.description="AI 驱动的全栈安全测试平台 - 一键部署镜像" \
      org.opencontainers.image.version="30.0.0" \
      org.opencontainers.image.licenses="Proprietary"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    LOG_LEVEL=INFO

WORKDIR /app

# 运行时最小依赖：curl 用于健康检查；常用安全工具（可选，按需扩展）
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        tzdata \
    && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && rm -rf /var/lib/apt/lists/*

# 从构建阶段拷贝已安装好的 Python 依赖
COPY --from=builder /install /usr/local

# 拷贝整个项目源码
COPY . .

# 创建运行期数据/日志/报告目录（对应 docker-compose 中的数据卷）
RUN mkdir -p /app/data /app/logs /app/reports /app/uploads /app/temp

# 暴露应用端口
EXPOSE 8000

# 容器内健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

# 启动命令：uvicorn 直挂 api_server.app:app
CMD ["uvicorn", "api_server.app:app", "--host", "0.0.0.0", "--port", "8000"]
