# -*- coding: utf-8 -*-
"""
installer.py — 一键安装脚本生成器。

支持生成：
  - Windows 一键安装（PowerShell 脚本）
  - Linux 一键安装（Bash 脚本，apt/yum/pacman）
  - macOS 一键安装（Bash 脚本 + brew）
  - Docker 一键部署（Dockerfile + docker-compose.yml）
  - K8s 部署（Deployment/Service/ConfigMap/Secret/Ingress/PVC/HPA/RBAC）
  - 离线安装包（依赖打包 + 校验和）

所有脚本仅生成文本，不执行。
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Dict, List, Optional

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# =========================================================================== #
# 1. Windows 一键安装（PowerShell）
# =========================================================================== #
def generate_windows_installer(port: int = 8000, install_dir: Optional[str] = None) -> str:
    """生成 Windows PowerShell 一键安装脚本。"""
    install_dir = install_dir or r"C:\ai-hacking-agent"
    return f"""# ============================================================
# ai-hacking-agent Windows 一键安装脚本
# 生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}
# 用法: 以管理员身份运行 PowerShell，执行:
#   Set-ExecutionPolicy Bypass -Scope Process -Force; .\\install.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$InstallDir = "{install_dir}"
$Port = {port}

Write-Host "=== ai-hacking-agent Windows 一键安装 ===" -ForegroundColor Cyan

# --- 1. 检查 Python ---
Write-Host "[1/7] 检查 Python 环境..." -ForegroundColor Yellow
try {{
    $pyVer = python --version 2>&1
    Write-Host "  已安装: $pyVer" -ForegroundColor Green
}} catch {{
    Write-Host "  未检测到 Python 3.10+，请先从 https://www.python.org/downloads/ 安装" -ForegroundColor Red
    exit 1
}}

# --- 2. 创建安装目录 ---
Write-Host "[2/7] 创建安装目录 $InstallDir ..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Set-Location $InstallDir

# --- 3. 复制项目文件（假设当前脚本在项目根） ---
Write-Host "[3/7] 复制项目文件..." -ForegroundColor Yellow
# Copy-Item -Recurse -Force ".\\api_server" "$InstallDir\\api_server"
# Copy-Item -Recurse -Force ".\\deploy" "$InstallDir\\deploy"

# --- 4. 安装 Python 依赖 ---
Write-Host "[4/7] 安装 Python 依赖..." -ForegroundColor Yellow
python -m pip install --upgrade pip
python -m pip install fastapi uvicorn pydantic pydantic-settings requests httpx aiohttp
python -m pip install sqlalchemy aiosqlite redis celery numpy pandas scapy
python -m pip install python-nmap paramiko cryptography pyyaml jinja2
python -m pip install python-multipart websockets plotly matplotlib networkx
python -m pip install aiofiles orjson psutil speedtest-cli

# --- 5. 环境变量 ---
Write-Host "[5/7] 配置环境变量..." -ForegroundColor Yellow
[Environment]::SetEnvironmentVariable("AI_HACKING_HOME", $InstallDir, "Machine")
[Environment]::SetEnvironmentVariable("AI_HACKING_PORT", "$Port", "Machine")

# --- 6. 防火墙规则 ---
Write-Host "[6/7] 配置防火墙规则..." -ForegroundColor Yellow
New-NetFirewallRule -DisplayName "ai-hacking-agent" -Direction Inbound `
    -Protocol TCP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue

# --- 7. 创建快捷方式 / 启动脚本 ---
Write-Host "[7/7] 创建启动脚本..." -ForegroundColor Yellow
$startBat = "@echo off`r`ncd /d $InstallDir`r`npython -m uvicorn api_server.app:app --host 0.0.0.0 --port $Port`r`npause"
Set-Content -Path "$InstallDir\\start.bat" -Value $startBat -Encoding ASCII

Write-Host ""
Write-Host "=== 安装完成! ===" -ForegroundColor Green
Write-Host "启动: 双击 $InstallDir\\start.bat" -ForegroundColor Cyan
Write-Host "访问: http://localhost:$Port/api/v1/deploy/console" -ForegroundColor Cyan
"""


# =========================================================================== #
# 2. Linux 一键安装（Bash）
# =========================================================================== #
def generate_linux_installer(port: int = 8000, install_dir: str = "/opt/ai-hacking-agent") -> str:
    """生成 Linux Bash 一键安装脚本（自动识别 apt/yum/pacman）。"""
    return f"""#!/usr/bin/env bash
# ============================================================
# ai-hacking-agent Linux 一键安装脚本
# 生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}
# 用法: sudo bash install.sh
# ============================================================
set -euo pipefail

INSTALL_DIR="{install_dir}"
PORT={port}

echo "=== ai-hacking-agent Linux 一键安装 ==="

# --- 0. 检测包管理器 ---
if command -v apt &>/dev/null; then
    PKG="apt"
    PKG_INSTALL="apt-get install -y"
    PKG_UPDATE="apt-get update"
elif command -v yum &>/dev/null; then
    PKG="yum"
    PKG_INSTALL="yum install -y"
    PKG_UPDATE="yum check-update || true"
elif command -v pacman &>/dev/null; then
    PKG="pacman"
    PKG_INSTALL="pacman -S --noconfirm"
    PKG_UPDATE="pacman -Sy"
else
    echo "[!] 不支持的 Linux 发行版"
    exit 1
fi
echo "[0/8] 包管理器: $PKG"

# --- 1. 系统依赖 ---
echo "[1/8] 安装系统依赖..."
$PKG_UPDATE
$PKG_INSTALL python3 python3-pip python3-venv git curl wget

# --- 2. 创建用户 ---
echo "[2/8] 创建运行用户..."
id aiagent &>/dev/null || useradd -r -m -d /home/aiagent -s /bin/bash aiagent

# --- 3. 安装目录 ---
echo "[3/8] 创建安装目录 $INSTALL_DIR ..."
mkdir -p $INSTALL_DIR
# cp -r api_server deploy $INSTALL_DIR/
chown -R aiagent:aiagent $INSTALL_DIR

# --- 4. Python 依赖 ---
echo "[4/8] 安装 Python 依赖..."
sudo -u aiagent python3 -m venv $INSTALL_DIR/.venv
sudo -u aiagent $INSTALL_DIR/.venv/bin/pip install --upgrade pip
sudo -u aiagent $INSTALL_DIR/.venv/bin/pip install fastapi uvicorn pydantic pydantic-settings
sudo -u aiagent $INSTALL_DIR/.venv/bin/pip install requests httpx aiohttp sqlalchemy aiosqlite
sudo -u aiagent $INSTALL_DIR/.venv/bin/pip install redis celery numpy pandas scapy
sudo -u aiagent $INSTALL_DIR/.venv/bin/pip install python-nmap paramiko cryptography pyyaml
sudo -u aiagent $INSTALL_DIR/.venv/bin/pip install jinja2 python-multipart websockets
sudo -u aiagent $INSTALL_DIR/.venv/bin/pip install plotly matplotlib networkx
sudo -u aiagent $INSTALL_DIR/.venv/bin/pip install aiofiles orjson psutil

# --- 5. systemd 服务 ---
echo "[5/8] 配置 systemd 服务..."
cat > /etc/systemd/system/ai-hacking-agent.service <<UNIT
[Unit]
Description=AI Hacking Agent API Server
After=network.target

[Service]
Type=simple
User=aiagent
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/uvicorn api_server.app:app --host 0.0.0.0 --port $PORT
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable ai-hacking-agent

# --- 6. 防火墙 ---
echo "[6/8] 配置防火墙..."
if command -v ufw &>/dev/null; then
    ufw allow $PORT/tcp || true
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=$PORT/tcp || true
    firewall-cmd --reload || true
fi

# --- 7. 环境变量 ---
echo "[7/8] 配置环境变量..."
cat > /etc/profile.d/ai-hacking.sh <<EOF
export AI_HACKING_HOME=$INSTALL_DIR
export AI_HACKING_PORT=$PORT
EOF
chmod +x /etc/profile.d/ai-hacking.sh

# --- 8. 启动 ---
echo "[8/8] 启动服务..."
systemctl start ai-hacking-agent || true

echo ""
echo "=== 安装完成! ==="
echo "启动: systemctl start ai-hacking-agent"
echo "状态: systemctl status ai-hacking-agent"
echo "日志: journalctl -u ai-hacking-agent -f"
echo "访问: http://localhost:$PORT/api/v1/deploy/console"
"""


# =========================================================================== #
# 3. macOS 一键安装
# =========================================================================== #
def generate_macos_installer(port: int = 8000, install_dir: str = "/opt/ai-hacking-agent") -> str:
    """生成 macOS 安装脚本（brew + launchd）。"""
    return f"""#!/usr/bin/env bash
# ============================================================
# ai-hacking-agent macOS 一键安装脚本
# 生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}
# 用法: bash install_macos.sh
# ============================================================
set -euo pipefail

INSTALL_DIR="{install_dir}"
PORT={port}

echo "=== ai-hacking-agent macOS 一键安装 ==="

# --- 1. 检查 Homebrew ---
if ! command -v brew &>/dev/null; then
    echo "[!] 未安装 Homebrew，正在安装..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# --- 2. 安装 Python ---
echo "[1/6] 安装 Python..."
brew install python@3.14 git curl

# --- 3. 安装目录 ---
echo "[2/6] 创建安装目录 $INSTALL_DIR ..."
sudo mkdir -p $INSTALL_DIR
# sudo cp -r api_server deploy $INSTALL_DIR/
sudo chown -R $(whoami):admin $INSTALL_DIR

# --- 4. Python 依赖 ---
echo "[3/6] 创建虚拟环境并安装依赖..."
python3 -m venv $INSTALL_DIR/.venv
$INSTALL_DIR/.venv/bin/pip install --upgrade pip
$INSTALL_DIR/.venv/bin/pip install fastapi uvicorn pydantic pydantic-settings
$INSTALL_DIR/.venv/bin/pip install requests httpx aiohttp sqlalchemy aiosqlite
$INSTALL_DIR/.venv/bin/pip install redis celery numpy pandas scapy
$INSTALL_DIR/.venv/bin/pip install python-nmap paramiko cryptography pyyaml
$INSTALL_DIR/.venv/bin/pip install jinja2 python-multipart websockets
$INSTALL_DIR/.venv/bin/pip install plotly matplotlib networkx
$INSTALL_DIR/.venv/bin/pip install aiofiles orjson psutil

# --- 5. launchd 服务 ---
echo "[4/6] 配置 launchd 服务..."
PLIST=~/Library/LaunchAgents/com.aihacking.agent.plist
cat > $PLIST <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aihacking.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{INSTALL_DIR}/.venv/bin/uvicorn</string>
        <string>api_server.app:app</string>
        <string>--host</string>
        <string>0.0.0.0</string>
        <string>--port</string>
        <string>{PORT}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{INSTALL_DIR}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/ai-hacking-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/ai-hacking-agent.err</string>
</dict>
</plist>
PLIST
launchctl load $PLIST || true

# --- 6. 环境变量 ---
echo "[5/6] 配置环境变量..."
cat > ~/.ai-hacking-env.sh <<EOF
export AI_HACKING_HOME=$INSTALL_DIR
export AI_HACKING_PORT=$PORT
EOF
grep -q "ai-hacking-env" ~/.zshrc || echo "source ~/.ai-hacking-env.sh" >> ~/.zshrc

echo "[6/6] 完成!"
echo "启动: launchctl start com.aihacking.agent"
echo "停止: launchctl stop com.aihacking.agent"
echo "日志: tail -f /tmp/ai-hacking-agent.log"
echo "访问: http://localhost:$PORT/api/v1/deploy/console"
"""


# =========================================================================== #
# 4. Docker 一键部署
# =========================================================================== #
def generate_dockerfile(port: int = 8000) -> str:
    return f"""# ============================================================
# ai-hacking-agent Dockerfile
# 生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}
# ============================================================
FROM python:3.14-slim

LABEL maintainer="ai-hacking-agent"
LABEL description="AI Hacking Agent API Server"

ENV PYTHONUNBUFFERED=1 \\
    PYTHONDONTWRITEBYTECODE=1 \\
    PIP_NO_CACHE_DIR=1 \\
    AI_HACKING_PORT={port}

WORKDIR /app

# 系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc g++ libffi-dev libssl-dev git curl \\
    && rm -rf /var/lib/apt/lists/*

# Python 依赖（先拷 requirements 利用层缓存）
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# 项目代码
COPY api_server/ ./api_server/
COPY deploy/ ./deploy/
COPY agent/ ./agent/

EXPOSE {port}

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \\
    CMD curl -f http://localhost:{port}/api/v1/health || exit 1

CMD ["uvicorn", "api_server.app:app", "--host", "0.0.0.0", "--port", "{port}"]
"""


def generate_docker_compose(port: int = 8000) -> str:
    return f"""# ============================================================
# ai-hacking-agent docker-compose.yml
# 生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}
# ============================================================
version: "3.9"

services:
  api:
    build: .
    container_name: ai-hacking-api
    ports:
      - "{port}:{port}"
    environment:
      - AI_HACKING_ENV=production
      - AI_HACKING_PORT={port}
      - REDIS_URL=redis://redis:6379/0
      - DB_PATH=/data/app.db
    volumes:
      - app_data:/data
      - ./logs:/app/logs
    depends_on:
      redis:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:{port}/api/v1/health"]
      interval: 30s
      timeout: 5s
      retries: 3

  redis:
    image: redis:7-alpine
    container_name: ai-hacking-redis
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
    restart: unless-stopped

volumes:
  app_data:
  redis_data:
"""


# =========================================================================== #
# 5. K8s 部署清单
# =========================================================================== #
def generate_k8s_manifests(namespace: str = "ai-hacking", port: int = 8000) -> Dict[str, str]:
    """生成完整的 K8s 部署清单集合。"""
    ns = f"""# Namespace
apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
  labels:
    name: {namespace}
"""

    configmap = f"""# ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: ai-hacking-config
  namespace: {namespace}
data:
  AI_HACKING_ENV: "production"
  AI_HACKING_PORT: "{port}"
  LOG_LEVEL: "INFO"
  MAX_WORKERS: "4"
"""

    secret = f"""# Secret（生产环境请用 sealed-secrets 或外部 KMS 管理）
apiVersion: v1
kind: Secret
metadata:
  name: ai-hacking-secret
  namespace: {namespace}
type: Opaque
stringData:
  ADMIN_PASSWORD: "changeme-strong-password"
  JWT_SECRET: "change-me-to-random-32-bytes-hex"
  REDIS_PASSWORD: "changeme-redis-password"
"""

    deployment = f"""# Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-hacking-api
  namespace: {namespace}
  labels:
    app: ai-hacking-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ai-hacking-api
  template:
    metadata:
      labels:
        app: ai-hacking-api
    spec:
      containers:
        - name: api
          image: ai-hacking-agent:latest
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: {port}
          envFrom:
            - configMapRef:
                name: ai-hacking-config
            - secretRef:
                name: ai-hacking-secret
          resources:
            requests:
              cpu: "500m"
              memory: "512Mi"
            limits:
              cpu: "2000m"
              memory: "2Gi"
          livenessProbe:
            httpGet:
              path: /api/v1/health
              port: {port}
            initialDelaySeconds: 15
            periodSeconds: 20
          readinessProbe:
            httpGet:
              path: /api/v1/health
              port: {port}
            initialDelaySeconds: 5
            periodSeconds: 10
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: ai-hacking-pvc
"""

    service = f"""# Service
apiVersion: v1
kind: Service
metadata:
  name: ai-hacking-svc
  namespace: {namespace}
spec:
  type: ClusterIP
  selector:
    app: ai-hacking-api
  ports:
    - port: 80
      targetPort: {port}
      protocol: TCP
"""

    ingress = f"""# Ingress
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ai-hacking-ingress
  namespace: {namespace}
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
    - hosts:
        - api.example.com
      secretName: ai-hacking-tls
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ai-hacking-svc
                port:
                  number: 80
"""

    pvc = f"""# PVC
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ai-hacking-pvc
  namespace: {namespace}
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
"""

    hpa = f"""# HPA
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ai-hacking-hpa
  namespace: {namespace}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ai-hacking-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
"""

    rbac = f"""# RBAC
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ai-hacking-sa
  namespace: {namespace}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ai-hacking-role
  namespace: {namespace}
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "configmaps", "secrets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ai-hacking-binding
  namespace: {namespace}
subjects:
  - kind: ServiceAccount
    name: ai-hacking-sa
    namespace: {namespace}
roleRef:
  kind: Role
  name: ai-hacking-role
  apiGroup: rbac.authorization.k8s.io
"""

    return {
        "namespace.yaml": ns,
        "configmap.yaml": configmap,
        "secret.yaml": secret,
        "deployment.yaml": deployment,
        "service.yaml": service,
        "ingress.yaml": ingress,
        "pvc.yaml": pvc,
        "hpa.yaml": hpa,
        "rbac.yaml": rbac,
        "apply_all.sh": f"#!/bin/bash\nkubectl apply -f {namespace}\n",
    }


# =========================================================================== #
# 6. 离线安装包
# =========================================================================== #
def generate_offline_package_info(port: int = 8000) -> Dict[str, Any]:
    """生成离线安装包元信息 + 校验和。"""
    scripts = {
        "windows_install.ps1": generate_windows_installer(port),
        "linux_install.sh": generate_linux_installer(port),
        "macos_install.sh": generate_macos_installer(port),
        "Dockerfile": generate_dockerfile(port),
        "docker-compose.yml": generate_docker_compose(port),
    }
    k8s = generate_k8s_manifests(port=port)
    scripts.update(k8s)

    checksums: Dict[str, str] = {}
    for name, content in scripts.items():
        h = hashlib.sha256(content.encode("utf-8")).hexdigest()
        checksums[name] = h

    manifest = {
        "package_name": "ai-hacking-agent-offline",
        "version": "20.1.0",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_port": port,
        "files": list(scripts.keys()),
        "checksums_sha256": checksums,
        "total_files": len(scripts),
        "total_size_bytes": sum(len(c) for c in scripts.values()),
        "installation_order": [
            "1. 选择对应平台脚本",
            "2. 运行安装脚本（管理员/root）",
            "3. 等待依赖安装完成",
            "4. 启动服务",
            "5. 访问 http://localhost:{port}/api/v1/deploy/console".format(port=port),
        ],
    }
    return {"manifest": manifest, "scripts": scripts}


# =========================================================================== #
# 7. 统一入口
# =========================================================================== #
def generate_installer(platform: str = "windows", port: int = 8000) -> Dict[str, Any]:
    """根据平台生成安装脚本集合。"""
    platform = platform.lower()
    if platform == "windows":
        return {"platform": "windows", "files": {"install.ps1": generate_windows_installer(port)}}
    if platform == "linux":
        return {"platform": "linux", "files": {"install.sh": generate_linux_installer(port)}}
    if platform == "macos":
        return {"platform": "macos", "files": {"install.sh": generate_macos_installer(port)}}
    if platform == "docker":
        return {
            "platform": "docker",
            "files": {
                "Dockerfile": generate_dockerfile(port),
                "docker-compose.yml": generate_docker_compose(port),
            },
        }
    if platform == "k8s":
        return {"platform": "k8s", "files": generate_k8s_manifests(port=port)}
    if platform == "offline":
        info = generate_offline_package_info(port)
        return {"platform": "offline", "files": info["scripts"], "manifest": info["manifest"]}
    return {"error": f"未知平台: {platform}，支持: windows/linux/macos/docker/k8s/offline"}
