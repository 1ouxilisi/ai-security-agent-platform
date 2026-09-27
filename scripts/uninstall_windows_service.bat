@echo off
chcp 65001 >nul
title AI Hacking Agent - Windows服务卸载
color 0C

echo ============================================================
echo   AI Hacking Agent - Windows服务卸载脚本
echo ============================================================
echo.

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 请以管理员身份运行此脚本！
    pause
    exit /b 1
)

:: 检查nssm
if not exist "tools\nssm.exe" (
    echo [错误] 未找到nssm.exe，无法卸载服务
    pause
    exit /b 1
)

:: 检查服务是否存在
tools\nssm.exe status AIHackingAgent >nul 2>&1
if %errorlevel% neq 0 (
    echo [信息] 服务 AIHackingAgent 不存在，无需卸载
    pause
    exit /b 0
)

:: 停止服务
echo [信息] 正在停止服务...
tools\nssm.exe stop AIHackingAgent
timeout /t 2 /nobreak >nul

:: 删除服务
echo [信息] 正在删除服务...
tools\nssm.exe remove AIHackingAgent confirm
timeout /t 2 /nobreak >nul

echo.
echo [成功] 服务 AIHackingAgent 已卸载
echo.
pause
