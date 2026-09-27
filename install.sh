#!/bin/bash
# AI Hacking Agent 一键安装脚本 (Linux/macOS)
# 用法: bash install.sh

set -e

echo "========================================"
echo "  AI Hacking Agent 一键安装"
echo "========================================"
echo ""

# 检查Python版本
echo "[1/6] 检查Python版本..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    echo "  Python版本: $PYTHON_VERSION"
    if [ "$(printf '%s\n' "3.10" "$PYTHON_VERSION" | sort -V | head -n1)" != "3.10" ]; then
        echo "  警告: 需要Python 3.10+"
    fi
else
    echo "  错误: 未找到Python3，请先安装Python 3.10+"
    exit 1
fi

# 检查pip
echo ""
echo "[2/6] 检查pip..."
if command -v pip3 &> /dev/null; then
    echo "  pip已安装"
else
    echo "  安装pip..."
    python3 -m ensurepip --upgrade
fi

# 创建虚拟环境
echo ""
echo "[3/6] 创建虚拟环境..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "  虚拟环境创建成功"
else
    echo "  虚拟环境已存在，跳过"
fi

# 激活虚拟环境
source venv/bin/activate

# 安装依赖
echo ""
echo "[4/6] 安装Python依赖..."
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo "  依赖安装完成"
else
    echo "  警告: 未找到requirements.txt"
fi

# 安装可选工具
echo ""
echo "[5/6] 检查可选安全工具..."
if command -v nmap &> /dev/null; then
    echo "  nmap已安装"
else
    echo "  提示: 建议安装nmap (sudo apt install nmap)"
fi

if command -v sqlmap &> /dev/null; then
    echo "  sqlmap已安装"
else
    echo "  提示: 建议安装sqlmap (git clone https://github.com/sqlmapproject/sqlmap.git)"
fi

# 初始化配置
echo ""
echo "[6/6] 初始化配置..."
if [ ! -f ".env" ]; then
    cp .env.example .env 2>/dev/null || true
    echo "  配置文件已创建 (.env)"
else
    echo "  配置文件已存在，跳过"
fi

# 创建必要目录
mkdir -p data logs uploads reports temp

echo ""
echo "========================================"
echo "  安装完成！"
echo "========================================"
echo ""
echo "启动命令:"
echo "  source venv/bin/activate"
echo "  python main.py api-server --host 0.0.0.0 --port 8000"
echo ""
echo "访问地址:"
echo "  统一控制台: http://127.0.0.1:8000/console-v7"
echo "  实战能力中心: http://127.0.0.1:8000/combat-console"
echo "  API文档: http://127.0.0.1:8000/docs"
echo ""
