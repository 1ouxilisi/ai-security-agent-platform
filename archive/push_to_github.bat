@echo off
chcp 65001 >nul
echo ========================================
echo   AI Hacking Agent - GitHub 推送脚本
echo ========================================
echo.

REM 检查Git是否安装
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] Git未安装，请先安装Git
    echo 下载地址: https://git-scm.com/download/win
    pause
    exit /b 1
)

REM 检查是否在Git仓库中
git rev-parse --is-inside-work-tree >nul 2>&1
if %errorlevel% neq 0 (
    echo [信息] 初始化Git仓库...
    git init
    git branch -M main
)

echo [1/5] 添加所有文件...
git add -A
if %errorlevel% neq 0 (
    echo [错误] 添加文件失败
    pause
    exit /b 1
)

echo [2/5] 检查变更...
git status --short

echo.
echo [3/5] 提交更改...
set /p commit_msg="请输入提交信息 (默认: AI Hacking Agent v8.0 空前提升): "
if "%commit_msg%"=="" set commit_msg=AI Hacking Agent v8.0 空前提升

git commit -m "%commit_msg%"
if %errorlevel% neq 0 (
    echo [警告] 没有新的更改需要提交
)

echo.
echo [4/5] 检查远程仓库...
git remote -v
git remote get-url origin >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [信息] 未配置远程仓库
    set /p repo_url="请输入GitHub仓库URL (例如: https://github.com/username/ai-hacking-agent.git): "
    if not "%repo_url%"=="" (
        git remote add origin "%repo_url%"
        echo [成功] 远程仓库已添加
    )
)

echo.
echo [5/5] 推送到GitHub...
git push -u origin main
if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo   ✅ 推送成功！
    echo ========================================
) else (
    echo.
    echo [提示] 如果是首次推送，请先在GitHub创建仓库
    echo [提示] 或者使用: git push -u origin main --force
)

echo.
pause
