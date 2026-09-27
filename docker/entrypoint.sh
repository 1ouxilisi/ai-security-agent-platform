#!/bin/bash
# AI Hacking Agent - 容器启动脚本

set -e

echo "========================================"
echo "  AI Hacking Agent v3.0.0"
echo "  企业级安全测试平台"
echo "========================================"
echo ""

# 等待数据库就绪
if [ -n "$DATABASE_URL" ]; then
    echo "[1/5] 等待数据库连接..."
    RETRIES=0
    MAX_RETRIES=30
    while [ $RETRIES -lt $MAX_RETRIES ]; do
        if python -c "import psycopg2; psycopg2.connect('$DATABASE_URL')" 2>/dev/null; then
            echo "  数据库连接成功"
            break
        fi
        RETRIES=$((RETRIES + 1))
        echo "  等待数据库... ($RETRIES/$MAX_RETRIES)"
        sleep 2
    done
fi

# 数据库迁移
echo "[2/5] 执行数据库迁移..."
python -c "
import os
import sys
sys.path.insert(0, '/app')
try:
    from auth.auth_system import AuthSystem
    auth = AuthSystem()
    auth.init_db()
    print('  数据库初始化完成')
except Exception as e:
    print(f'  数据库初始化警告: {e}')
" 2>/dev/null || echo "  跳过数据库初始化"

# 更新Nuclei模板
echo "[3/5] 更新Nuclei漏洞模板..."
nuclei -update-templates 2>/dev/null || echo "  Nuclei模板更新跳过"

# 创建管理员账户
echo "[4/5] 检查管理员账户..."
python -c "
import sys
sys.path.insert(0, '/app')
try:
    from auth.auth_system import AuthSystem
    auth = AuthSystem()
    if not auth.user_exists('admin'):
        auth.register_user('admin', 'admin123', 'admin@aihacking.local', role='admin')
        print('  默认管理员已创建: admin / admin123')
        print('  ⚠️  请立即修改默认密码！')
    else:
        print('  管理员账户已存在')
except Exception as e:
    print(f'  管理员检查跳过: {e}')
" 2>/dev/null || echo "  管理员检查跳过"

# 启动服务
echo "[5/5] 启动服务..."
echo ""
echo "  API服务:    http://localhost:8000"
echo "  API文档:    http://localhost:8000/docs"
echo "  Web UI:     http://localhost:8001"
echo "  移动端:     http://localhost:8001/mobile.html"
echo "  MCP服务:    http://localhost:8002"
echo ""
echo "========================================"
echo "  服务启动中..."
echo "========================================"

# 根据命令启动不同服务
case "${1:-api-server}" in
    api-server)
        exec python main.py api-server --host 0.0.0.0 --port 8000
        ;;
    web-ui)
        exec python -m http.server 8001 --directory /app/web
        ;;
    mcp-server)
        exec python mcp/mcp_server.py
        ;;
    worker)
        exec python scheduler/task_scheduler.py
        ;;
    all)
        # 启动所有服务
        python -m http.server 8001 --directory /app/web &
        python mcp/mcp_server.py &
        exec python main.py api-server --host 0.0.0.0 --port 8000
        ;;
    *)
        exec "$@"
        ;;
esac
