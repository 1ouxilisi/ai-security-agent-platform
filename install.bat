@echo off
chcp 65001 >nul
echo ========================================
echo   AI Hacking Agent 一键安装 (Windows)
echo ========================================
echo.

REM 检查Python版本
echo [1/6] 检查Python版本...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   错误: 未找到Python，请先安装Python 3.10+
    echo   下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)
python --version

REM 检查pip
echo.
echo [2/6] 检查pip...
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   安装pip...
    python -m ensurepip --upgrade
) else (
    echo   pip已安装
)

REM 创建虚拟环境
echo.
echo [3/6] 创建虚拟环境...
if not exist venv (
    python -m venv venv
    echo   虚拟环境创建成功
) else (
    echo   虚拟环境已存在，跳过
)

REM 激活虚拟环境并安装依赖
echo.
echo [4/6] 安装Python依赖...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
if exist requirements.txt (
    pip install -r requirements.txt
    echo   依赖安装完成
) else (
    echo   警告: 未找到requirements.txt
)

REM 检查可选工具
echo.
echo [5/6] 检查可选安全工具...
where nmap >nul 2>&1
if %errorlevel% equ 0 (
    echo   nmap已安装
) else (
    echo   提示: 建议安装nmap (https://nmap.org/download.html)
)

REM 初始化配置
echo.
echo [6/6] 初始化配置...
if not exist .env (
    if exist .env.example (
        copy .env.example .env >nul
        echo   配置文件已创建 (.env)
    )
) else (
    echo   配置文件已存在，跳过
)

REM 创建必要目录
if not exist data mkdir data
if not exist logs mkdir logs
if not exist uploads mkdir uploads
if not exist reports mkdir reports
if not exist temp mkdir temp

echo.
echo ========================================
echo   安装完成！
echo ========================================
echo.
echo 启动命令:
echo   venv\Scripts\activate
echo   python main.py api-server --host 0.0.0.0 --port 8000
echo.
echo 访问地址:
echo   统一控制台: http://127.0.0.1:8000/console-v7
echo   实战能力中心: http://127.0.0.1:8000/combat-console
echo   API文档: http://127.0.0.1:8000/docs
echo.
pause
