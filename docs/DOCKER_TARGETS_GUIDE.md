# Docker安装与漏洞靶场启动指南

## 一、Docker Desktop安装

### 1. 下载Docker Desktop
访问官网下载：https://www.docker.com/products/docker-desktop/

选择Windows版本，下载安装包（约500MB）。

### 2. 安装Docker Desktop
1. 双击运行安装包
2. 勾选 "Use WSL 2 instead of Hyper-V"（推荐）
3. 点击 "OK" 开始安装
4. 安装完成后重启电脑
5. 启动Docker Desktop，等待初始化完成

### 3. 验证安装
打开PowerShell，执行：
```powershell
docker --version
docker compose version
```
如果显示版本号，说明安装成功。

### 4. 配置国内镜像加速（可选，推荐）
1. 打开Docker Desktop设置
2. 进入 "Docker Engine"
3. 在配置中添加：
```json
{
  "registry-mirrors": [
    "https://docker.mirrors.ustc.edu.cn",
    "https://hub-mirror.c.163.com"
  ]
}
```
4. 点击 "Apply & Restart"

---

## 二、漏洞靶场启动

### 方式1：一键启动脚本（推荐）
双击运行项目根目录下的 `scripts\start-targets.bat`

脚本会自动：
1. 创建Docker网络
2. 启动DVWA漏洞靶场（端口8080）
3. 启动OWASP Juice Shop靶场（端口3000）
4. 显示访问地址

### 方式2：手动启动
打开PowerShell，依次执行：

```powershell
# 1. 创建网络
docker network create hacking-lab

# 2. 启动DVWA
docker run -d --name dvwa --network hacking-lab -p 8080:80 vulnerables/web-dvwa

# 3. 启动Juice Shop
docker run -d --name juice-shop --network hacking-lab -p 3000:3000 bkimminich/juice-shop
```

### 方式3：Docker Compose（推荐用于长期使用）
在项目根目录创建 `docker-compose.targets.yml`：

```yaml
version: '3.8'

networks:
  hacking-lab:
    driver: bridge

services:
  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa
    ports:
      - "8080:80"
    networks:
      - hacking-lab
    restart: unless-stopped

  juice-shop:
    image: bkimminich/juice-shop
    container_name: juice-shop
    ports:
      - "3000:3000"
    networks:
      - hacking-lab
    restart: unless-stopped
```

启动：
```powershell
docker-compose -f docker-compose.targets.yml up -d
```

---

## 三、靶场访问与初始化

### DVWA（Damn Vulnerable Web Application）
- **访问地址**：http://127.0.0.1:8080
- **默认账号**：admin / password
- **首次初始化**：
  1. 访问 http://127.0.0.1:8080
  2. 点击底部 "Create / Reset Database"
  3. 等待数据库创建完成
  4. 使用 admin/password 登录
- **漏洞类型**：SQL注入、XSS、CSRF、文件上传、命令注入、文件包含等

### OWASP Juice Shop
- **访问地址**：http://127.0.0.1:3000
- **默认账号**：无需登录，直接访问
- **特点**：现代Web应用，包含OWASP Top 10全部漏洞
- **漏洞类型**：SQL注入、XSS、SSRF、XXE、反序列化、JWT攻击、权限绕过等

---

## 四、使用AI Hacking Agent扫描靶场

### 1. Nuclei POC扫描
```powershell
# 扫描DVWA
python main.py nuclei --target http://127.0.0.1:8080

# 扫描Juice Shop
python main.py nuclei --target http://127.0.0.1:3000
```

### 2. 通过API创建扫描任务
```powershell
# 创建任务
$body = '{"target":"http://127.0.0.1:8080","task_type":"scan","description":"DVWA漏洞扫描"}'
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/tasks" -Method POST -Body $body -ContentType "application/json"

# 查看任务列表
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/tasks" -UseBasicParsing
```

### 3. 通过Web UI操作
```powershell
streamlit run web_ui/app.py
```
然后访问 http://localhost:8501，在"新建任务"页面输入靶场地址。

---

## 五、靶场管理命令

### 查看运行状态
```powershell
docker ps
```

### 查看靶场日志
```powershell
docker logs dvwa
docker logs juice-shop
```

### 停止靶场
```powershell
docker stop dvwa juice-shop
```

### 启动靶场
```powershell
docker start dvwa juice-shop
```

### 重启靶场
```powershell
docker restart dvwa juice-shop
```

### 删除靶场（清理）
```powershell
docker rm -f dvwa juice-shop
docker network rm hacking-lab
```

---

## 六、其他推荐漏洞靶场

### 1. WebGoat
```powershell
docker run -d --name webgoat -p 8081:8080 webgoat/webgoat
```
访问：http://127.0.0.1:8081/WebGoat

### 2. DVWA（高级版）
```powershell
docker run -d --name dvwa-high -p 8082:80 vulnerables/web-dvwa
```

### 3. bWAPP
```powershell
docker run -d --name bwapp -p 8083:80 raesene/bwapp
```
访问：http://127.0.0.1:8083，默认账号：bee / bug

### 4. Mutillidae
```powershell
docker run -d --name mutillidae -p 8084:80 citizenstig/nowasp
```
访问：http://127.0.0.1:8084

---

## 七、常见问题

### Q1: Docker启动失败，提示"WSL 2 installation is incomplete"
**解决**：
1. 下载并安装WSL2内核更新包：https://aka.ms/wsl2kernel
2. 安装完成后重启Docker Desktop

### Q2: 镜像拉取慢或失败
**解决**：
1. 配置国内镜像加速（见上文）
2. 或手动拉取镜像：
```powershell
docker pull vulnerables/web-dvwa
docker pull bkimminich/juice-shop
```

### Q3: 端口被占用
**解决**：
```powershell
# 查看占用端口的进程
netstat -ano | findstr :8080
# 杀掉进程
taskkill /PID <进程ID> /F
# 或换个端口启动
docker run -d --name dvwa -p 8081:80 vulnerables/web-dvwa
```

### Q4: DVWA页面显示"Could not connect to MySQL service"
**解决**：
1. 等待容器完全启动（约30秒）
2. 访问 http://127.0.0.1:8080
3. 点击 "Create / Reset Database" 初始化数据库

---

## 八、安全提示

⚠️ **重要安全提醒**：
1. 这些靶场包含真实漏洞，**仅用于授权的安全研究和学习**
2. 不要将靶场暴露到公网，仅在本地127.0.0.1访问
3. 扫描和测试仅针对自己搭建的靶场，不要针对未授权的目标
4. 遵守《网络安全法》和相关法律法规
5. 学习用途，禁止用于非法攻击

---

## 九、下一步

靶场启动后，可以：
1. 运行Nuclei POC扫描：`python main.py nuclei --target http://127.0.0.1:8080`
2. 启动API服务：`python main.py api-server`
3. 启动Web UI：`streamlit run web_ui/app.py`
4. 查看扫描报告：在Web UI的"漏洞库"页面查看

祝学习愉快！🛡️
