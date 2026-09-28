"""
v9.2 靶场管理 - 一键部署和管理测试靶场
"""
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v9/range", tags=["v9-range"])

RANGES = {
    "juice_shop": {
        "name": "OWASP Juice Shop",
        "description": "现代Web应用安全训练靶场，包含OWASP Top 10漏洞",
        "port": 3000,
        "docker_image": "bkimminich/juice-shop:latest",
        "difficulty": "入门",
        "url": "http://127.0.0.1:3000"
    },
    "dvwa": {
        "name": "DVWA (Damn Vulnerable Web Application)",
        "description": "经典PHP漏洞靶场，SQL注入/XSS/文件上传等",
        "port": 8081,
        "docker_image": "vulnerables/web-dvwa:latest",
        "difficulty": "入门",
        "url": "http://127.0.0.1:8081"
    },
    "webgoat": {
        "name": "OWASP WebGoat",
        "description": "OWASP官方Java安全训练靶场",
        "port": 8082,
        "docker_image": "webgoat/webgoat:latest",
        "difficulty": "中级",
        "url": "http://127.0.0.1:8082/WebGoat"
    },
    "mutillidae": {
        "name": "Mutillidae",
        "description": "OWASP Broken Web Applications Project靶场",
        "port": 8083,
        "docker_image": "citizenstig/nowasp:latest",
        "difficulty": "中级",
        "url": "http://127.0.0.1:8083/mutillidae"
    }
}


@router.get("/list")
async def list_ranges():
    """列出所有可用靶场"""
    return {
        "ranges": RANGES,
        "note": "使用Docker一键启动，需要本地安装Docker",
        "timestamp": datetime.now().isoformat()
    }


@router.post("/start/{range_id}")
async def start_range(range_id: str):
    """启动指定靶场"""
    if range_id not in RANGES:
        return JSONResponse(status_code=404, content={"error": f"未知靶场: {range_id}"})
    
    r = RANGES[range_id]
    container_name = f"pentest-range-{range_id}"
    
    # 检查是否已在运行
    try:
        check = subprocess.run(
            ["docker", "ps", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        if container_name in check.stdout:
            return {"status": "already_running", "range": r, "url": r["url"]}
    except FileNotFoundError:
        return {"error": "Docker未安装，请先安装Docker Desktop", "range": r}
    
    # 启动容器
    try:
        proc = subprocess.run(
            ["docker", "run", "-d", "--name", container_name,
             "-p", f"{r['port']}:3000" if range_id == "juice_shop" else f"{r['port']}:80",
             r["docker_image"]],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0:
            return {
                "status": "started",
                "range": r,
                "container_id": proc.stdout.strip()[:12],
                "url": r["url"],
                "note": "首次启动需要拉取镜像，等待10-30秒后访问"
            }
        else:
            return {"error": proc.stderr, "range": r}
    except Exception as e:
        return {"error": str(e), "range": r}


@router.post("/stop/{range_id}")
async def stop_range(range_id: str):
    """停止靶场"""
    if range_id not in RANGES:
        return JSONResponse(status_code=404, content={"error": f"未知靶场: {range_id}"})
    
    container_name = f"pentest-range-{range_id}"
    try:
        subprocess.run(["docker", "stop", container_name], capture_output=True, timeout=10)
        subprocess.run(["docker", "rm", container_name], capture_output=True, timeout=10)
        return {"status": "stopped", "range_id": range_id}
    except Exception as e:
        return {"error": str(e)}


@router.get("/status")
async def range_status():
    """查看靶场运行状态"""
    status = {}
    for rid, r in RANGES.items():
        container_name = f"pentest-range-{rid}"
        try:
            check = subprocess.run(
                ["docker", "ps", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5
            )
            status[rid] = {
                "running": container_name in check.stdout,
                "url": r["url"]
            }
        except:
            status[rid] = {"running": False, "url": r["url"]}
    
    return {"ranges": status, "timestamp": datetime.now().isoformat()}
