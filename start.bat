@echo off
chcp 65001 >nul
title AI Hacking Agent v10.0 - 一键启动
color 0B

echo ========================================
echo   AI Hacking Agent v10.0 一键启动脚本
echo   企业级全栈安全测试平台 - 终极完整版
echo ========================================
echo.

:: 检查Python
echo [1/5] 检查Python环境...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到Python，请先安装Python 3.10+
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo [OK] Python版本: %PYVER%
echo.

:: 检查项目目录
echo [2/5] 检查项目目录...
if not exist "main.py" (
    echo [错误] 未找到main.py，请确保在项目根目录运行此脚本
    pause
    exit /b 1
)
echo [OK] 项目目录正确
echo.

:: 检查依赖
echo [3/5] 检查依赖安装...
python -c "import fastapi; import uvicorn; import loguru" >nul 2>&1
if %errorlevel% neq 0 (
    echo [提示] 检测到缺少依赖，正在安装...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [警告] 部分依赖安装失败，尝试安装核心依赖...
        pip install python-dotenv pydantic loguru rich aiohttp pyyaml fastapi uvicorn streamlit openai
    )
) else (
    echo [OK] 核心依赖已安装
)
echo.

:: 检查.env文件
echo [4/5] 检查配置文件...
if not exist ".env" (
    echo [提示] 未找到.env文件，正在创建...
    echo LLM_API_KEY=your_api_key_here > .env
    echo LLM_BASE_URL=https://api.deepseek.com/v1 >> .env
    echo LLM_MODEL=deepseek-chat >> .env
    echo [OK] 已创建.env模板，请编辑填入API密钥
) else (
    echo [OK] .env配置文件存在
)
echo.

:: 启动服务
echo [5/5] 启动API服务...
echo.
echo ========================================
echo   服务启动中，请稍候...
echo ========================================
echo.
echo API文档:     http://127.0.0.1:8000/docs
echo 主控制台:    http://127.0.0.1:8000/console-v7
echo 增强控制台:  http://127.0.0.1:8000/enhanced-console
echo 扩展控制台:  http://127.0.0.1:8000/extended-console
echo 高级控制台:  http://127.0.0.1:8000/advanced-console
echo 仪表盘:      http://127.0.0.1:8000/dashboard
echo 漏洞库:      http://127.0.0.1:8000/vuln-database
echo 健康检查:    http://127.0.0.1:8000/health
echo.
echo 按 Ctrl+C 停止服务
echo.

:: 等待2秒后打开浏览器
start "" cmd /c "timeout /t 3 /nobreak >nul && start http://127.0.0.1:8000/enhanced-console"

:: 启动API服务
python main.py api-server --host 127.0.0.1 --port 8000

pause
