#!/usr/bin/env bash
# =============================================================================
# AI Hacking Agent - 一键部署脚本 (deploy.sh)
# 用法:
#   chmod +x deploy.sh
#   ./deploy.sh                # 构建并启动
#   ./deploy.sh build          # 仅构建
#   ./deploy.sh up             # 仅启动（已构建）
#   ./deploy.sh down           # 停止并移除容器
#   ./deploy.sh logs           # 跟踪应用日志
#   ./deploy.sh health         # 健康检查
# =============================================================================
set -euo pipefail

# ---------- 颜色输出 ----------
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}   $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[FAIL]${NC}  $*"; }

# ---------- 项目根目录 ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${APP_PORT:-8000}"
HEALTH_URL="http://localhost:${PORT}/health"

# ---------- 命令: 检查 Docker 环境 ----------
check_env() {
    info "检查 Docker 环境..."
    if ! command -v docker >/dev/null 2>&1; then
        err "未检测到 docker 命令，请先安装 Docker (v20.10+)。"
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        err "Docker 守护进程未运行，请启动 Docker Desktop / dockerd 后重试。"
        exit 1
    fi

    if docker compose version >/dev/null 2>&1; then
        COMPOSE="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE="docker-compose"
    else
        err "未检测到 docker compose 插件，请安装 Compose V2。"
        exit 1
    fi
    ok "Docker 环境就绪: $(docker --version) | $($COMPOSE version --short 2>/dev/null || echo compose)"
}

# ---------- 命令: 构建镜像 ----------
build() {
    check_env
    info "构建镜像 ai-hacking-agent:latest ..."
    $COMPOSE build app
    ok "镜像构建完成"
}

# ---------- 命令: 启动服务 ----------
up() {
    check_env
    info "启动服务 (后台)..."
    $COMPOSE up -d app db redis
    ok "容器已启动"
    health
}

# ---------- 命令: 健康检查 ----------
health() {
    info "等待应用就绪 (最多 60s)..."
    local i=0
    until curl -fsS "$HEALTH_URL" >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -ge 30 ]; then
            err "健康检查超时，请执行 '$0 logs' 查看日志"
            docker compose ps || true
            exit 1
        fi
        sleep 2
    done
    ok "应用健康检查通过"
    echo
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  AI Hacking Agent 部署成功!${NC}"
    echo -e "${GREEN}  访问地址:   http://localhost:${PORT}${NC}"
    echo -e "${GREEN}  健康检查:   ${HEALTH_URL}${NC}"
    echo -e "${GREEN}  License控制台: http://localhost:${PORT}/license-management${NC}"
    echo -e "${GREEN}  查看日志:   $0 logs${NC}"
    echo -e "${GREEN}  停止服务:   $0 down${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

# ---------- 命令: 日志 ----------
logs() {
    $COMPOSE logs -f --tail=200 app
}

# ---------- 命令: 停止 ----------
down() {
    check_env
    info "停止并移除容器..."
    $COMPOSE down
    ok "已停止（数据卷保留）"
}

# ---------- 命令: 重建并重启 ----------
rebuild() {
    build
    up
}

# ---------- 入口 ----------
case "${1:-all}" in
    build)   build ;;
    up)      up ;;
    down)    down ;;
    logs)    logs ;;
    health)  health ;;
    rebuild) rebuild ;;
    all)     rebuild ;;
    *)
        echo "用法: $0 {build|up|down|logs|health|rebuild|all}"
        exit 1
        ;;
esac
