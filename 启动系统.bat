@echo off
chcp 65001 >nul
title AI全栈安全作战中心 v44
echo ========================================
echo   AI Full-Stack Security Command v44
echo ========================================
echo.

REM 检查Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到Python，请先安装Python 3.10+
    pause
    exit /b 1
)

echo [1/3] 检查依赖...
pip install fastapi uvicorn httpx pydantic -q 2>nul

echo [2/3] 启动API服务器...
start /B python app_lite.py > server.log 2>&1
timeout /t 3 /nobreak >nul

echo [3/3] 打开浏览器...
start http://127.0.0.1:8001/ai-security

echo.
echo ========================================
echo   系统已启动!
echo   控制台: http://127.0.0.1:8001/ai-security
echo   API文档: http://127.0.0.1:8001/docs
echo   登录密码: security2026
echo ========================================
echo.
echo 按 Ctrl+C 停止服务器
echo.
python app_lite.py
pause
