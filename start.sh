#!/bin/bash
# AI Hacking Agent - Linux/Mac 启动脚本
# 用法: ./start.sh [api-server|console|test|install]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  AI Hacking Agent v4.0.0 启动脚本${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 检查Python
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON=python3
    elif command -v python &> /dev/null; then
        PYTHON=python
    else
        echo -e "${RED}❌ 未找到Python，请先安装Python 3.10+${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Python版本: $($PYTHON --version)${NC}"
}

# 检查虚拟环境
check_venv() {
    if [ -d "venv" ]; then
        echo -e "${GREEN}✅ 检测到虚拟环境，正在激活...${NC}"
        source venv/bin/activate
    else
        echo -e "${YELLOW}⚠️  未检测到虚拟环境，使用系统Python${NC}"
    fi
}

# 安装依赖
install_deps() {
    echo -e "${YELLOW}📦 正在安装依赖...${NC}"
    $PYTHON -m pip install --upgrade pip
    $PYTHON -m pip install -r requirements.txt
    echo -e "${GREEN}✅ 依赖安装完成${NC}"
}

# 检查.env
check_env() {
    if [ ! -f ".env" ]; then
        echo -e "${YELLOW}⚠️  未检测到.env文件，正在从模板创建...${NC}"
        if [ -f ".env.example" ]; then
            cp .env.example .env
            echo -e "${YELLOW}   请编辑.env文件配置API密钥${NC}"
        else
            echo -e "${RED}❌ 未找到.env.example模板${NC}"
        fi
    else
        echo -e "${GREEN}✅ .env配置文件存在${NC}"
    fi
}

# 启动API服务
start_api() {
    echo -e "${GREEN}🚀 正在启动API服务...${NC}"
    echo -e "${BLUE}   API文档: http://127.0.0.1:8000/docs${NC}"
    echo -e "${BLUE}   健康检查: http://127.0.0.1:8000/health${NC}"
    echo -e "${YELLOW}   按 Ctrl+C 停止服务${NC}"
    echo ""
    $PYTHON main.py api-server --host 0.0.0.0 --port 8000
}

# 运行测试
run_tests() {
    echo -e "${YELLOW}🧪 正在运行单元测试...${NC}"
    $PYTHON -m pytest tests/ -v --tb=short
}

# 主逻辑
check_python
check_venv
check_env

case "${1:-api-server}" in
    api-server)
        install_deps
        start_api
        ;;
    install)
        install_deps
        echo -e "${GREEN}✅ 安装完成！运行 ./start.sh api-server 启动服务${NC}"
        ;;
    test)
        run_tests
        ;;
    *)
        echo -e "${RED}❌ 未知命令: $1${NC}"
        echo "用法: ./start.sh [api-server|install|test]"
        exit 1
        ;;
esac
