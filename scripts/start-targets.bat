@echo off
chcp 65001 >nul
echo ========================================
echo   AI Hacking Agent - 漏洞靶场一键启动
echo ========================================
echo.

echo [1/4] 检查Docker是否可用...
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker未安装或未启动
    echo 请先安装Docker Desktop: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)
echo ✅ Docker可用
echo.

echo [2/4] 创建靶场网络...
docker network create hacking-lab >nul 2>&1
echo ✅ 网络已创建
echo.

echo [3/4] 启动DVWA漏洞靶场 (端口: 8080)...
docker rm -f dvwa >nul 2>&1
docker run -d --name dvwa --network hacking-lab -p 8080:80 vulnerables/web-dvwa
if %errorlevel% neq 0 (
    echo ⚠️  DVWA启动失败，尝试拉取镜像...
    docker pull vulnerables/web-dvwa
    docker run -d --name dvwa --network hacking-lab -p 8080:80 vulnerables/web-dvwa
)
echo.

echo [4/4] 启动OWASP Juice Shop靶场 (端口: 3000)...
docker rm -f juice-shop >nul 2>&1
docker run -d --name juice-shop --network hacking-lab -p 3000:3000 bkimminich/juice-shop
if %errorlevel% neq 0 (
    echo ⚠️  Juice Shop启动失败，尝试拉取镜像...
    docker pull bkimminich/juice-shop
    docker run -d --name juice-shop --network hacking-lab -p 3000:3000 bkimminich/juice-shop
)
echo.

echo ========================================
echo   ✅ 漏洞靶场启动完成！
echo ========================================
echo.
echo 访问地址:
echo   - DVWA:        http://127.0.0.1:8080
echo   - Juice Shop:  http://127.0.0.1:3000
echo.
echo 默认账号:
echo   - DVWA: admin / password
echo   - Juice Shop: 无需登录，直接访问
echo.
echo 注意: DVWA首次访问需要点击 "Create / Reset Database" 初始化数据库
echo.
echo 查看靶场状态: docker ps
echo 停止靶场:     docker stop dvwa juice-shop
echo 重启靶场:     docker start dvwa juice-shop
echo 删除靶场:     docker rm -f dvwa juice-shop
echo.
pause
