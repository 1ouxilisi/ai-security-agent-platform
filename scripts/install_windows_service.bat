@echo off
chcp 65001 >nul
title AI Hacking Agent - Windows服务安装
color 0A

echo ============================================================
echo   AI Hacking Agent - Windows服务安装脚本
echo   将API服务安装为Windows系统服务，开机自动启动
echo ============================================================
echo.

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 请以管理员身份运行此脚本！
    echo 右键点击脚本，选择"以管理员身份运行"
    pause
    exit /b 1
)

:: 设置项目路径
set PROJECT_DIR=%~dp0..
cd /d "%PROJECT_DIR%"
echo 项目目录: %PROJECT_DIR%
echo.

:: 检查Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到Python，请先安装Python 3.10+
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo Python版本: %PYTHON_VERSION%
echo.

:: 检查nssm
if not exist "tools\nssm.exe" (
    echo [信息] 未找到nssm.exe，正在下载...
    powershell -Command "Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile '%TEMP%\nssm.zip'"
    powershell -Command "Expand-Archive -Path '%TEMP%\nssm.zip' -DestinationPath '%TEMP%\nssm' -Force"
    copy "%TEMP%\nssm\nssm-2.24\win64\nssm.exe" "tools\nssm.exe" >nul
    if exist "tools\nssm.exe" (
        echo [成功] nssm下载完成
    ) else (
        echo [错误] nssm下载失败，请手动下载并放到tools目录
        echo 下载地址: https://nssm.cc/release/nssm-2.24.zip
        pause
        exit /b 1
    )
)
echo nssm位置: tools\nssm.exe
echo.

:: 停止并删除已存在的服务
echo [信息] 检查是否已存在服务...
tools\nssm.exe status AIHackingAgent >nul 2>&1
if %errorlevel% equ 0 (
    echo [信息] 发现已存在的服务，正在停止并删除...
    tools\nssm.exe stop AIHackingAgent >nul 2>&1
    tools\nssm.exe remove AIHackingAgent confirm >nul 2>&1
    timeout /t 2 /nobreak >nul
    echo [成功] 旧服务已删除
)
echo.

:: 安装服务
echo [信息] 正在安装Windows服务...
tools\nssm.exe install AIHackingAgent "python" "main.py api-server --host 0.0.0.0 --port 8000"
tools\nssm.exe set AIHackingAgent AppDirectory "%PROJECT_DIR%"
tools\nssm.exe set AIHackingAgent AppStdout "%PROJECT_DIR%\data\logs\service_stdout.log"
tools\nssm.exe set AIHackingAgent AppStderr "%PROJECT_DIR%\data\logs\service_stderr.log"
tools\nssm.exe set AIHackingAgent AppRotateFiles 1
tools\nssm.exe set AIHackingAgent AppRotateBytes 10485760
tools\nssm.exe set AIHackingAgent Start SERVICE_AUTO_START
tools\nssm.exe set AIHackingAgent Description "AI Hacking Agent - AI驱动的安全研究智能体平台API服务"

:: 创建日志目录
if not exist "data\logs" mkdir data\logs

echo.
echo [成功] 服务安装完成！
echo.

:: 启动服务
echo [信息] 正在启动服务...
tools\nssm.exe start AIHackingAgent
timeout /t 3 /nobreak >nul

:: 检查服务状态
echo.
echo ============================================================
echo   服务状态检查
echo ============================================================
tools\nssm.exe status AIHackingAgent
echo.

:: 健康检查
echo [信息] 等待服务启动...
timeout /t 5 /nobreak >nul
powershell -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/health' -UseBasicParsing -TimeoutSec 5; Write-Host '[成功] API服务健康检查通过:' $r.Content } catch { Write-Host '[警告] API服务健康检查失败，可能还在启动中，请稍后重试' }"

echo.
echo ============================================================
echo   安装完成！
echo ============================================================
echo.
echo 服务名称: AIHackingAgent
echo 服务状态: 自动启动（开机自启）
echo API地址: http://127.0.0.1:8000
echo API文档: http://127.0.0.1:8000/docs
echo 日志文件: data\logs\service_stdout.log
echo.
echo 常用命令:
echo   启动服务: tools\nssm.exe start AIHackingAgent
echo   停止服务: tools\nssm.exe stop AIHackingAgent
echo   重启服务: tools\nssm.exe restart AIHackingAgent
echo   服务状态: tools\nssm.exe status AIHackingAgent
echo   删除服务: tools\nssm.exe remove AIHackingAgent confirm
echo.
pause
