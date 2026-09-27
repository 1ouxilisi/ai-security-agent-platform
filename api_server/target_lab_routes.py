# -*- coding: utf-8 -*-
"""靶场一键部署管理 - DVWA/Juice Shop/WebGoat"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict
import subprocess

router = APIRouter(prefix="/api/v1/target-lab", tags=["靶场部署"])

RANGES = {
    "dvwa": {"name": "DVWA", "image": "vulnerables/web-dvwa", "port": 8080, "container_port": 80, "description": "PHP/MySQL漏洞Web应用", "creds": "admin/password"},
    "juice": {"name": "OWASP Juice Shop", "image": "bkimminich/juice-shop", "port": 3000, "container_port": 3000, "description": "Node.js现代漏洞Web应用", "creds": "无需登录"},
    "webgoat": {"name": "WebGoat", "image": "webgoat/webgoat-8.0", "port": 8081, "container_port": 8080, "description": "Java教学型漏洞应用", "creds": "guest/guest"}
}

def _docker_available():
    try:
        r = subprocess.run(["docker", "version"], capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except: return False

def _run_docker(args, timeout=120):
    try:
        r = subprocess.run(["docker"] + args, capture_output=True, text=True, timeout=timeout)
        return {"success": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.get("/list")
def list_ranges():
    return {"success": True, "data": {"ranges": RANGES, "docker_available": _docker_available()}}

@router.get("/status")
def range_status():
    if not _docker_available():
        return {"success": False, "error": "Docker不可用"}
    r = _run_docker(["ps", "-a", "--format", "{{.Names}}|{{.Image}}|{{.Status}}"])
    containers = []
    if r.get("success"):
        for line in r.get("stdout", "").strip().split(chr(10)):
            if line and "|" in line:
                parts = line.split("|")
                containers.append({"name": parts[0], "image": parts[1], "status": parts[2]})
    return {"success": True, "data": {"containers": containers, "count": len(containers)}}

class DeployReq(BaseModel):
    name: str
    port: Optional[int] = None

@router.post("/deploy")
def deploy_range(req: DeployReq):
    if req.name not in RANGES:
        return {"success": False, "error": f"未知靶场: {req.name}"}
    if not _docker_available():
        return {"success": False, "error": "Docker不可用，请先安装Docker"}
    cfg = RANGES[req.name]
    port = req.port or cfg["port"]
    cn = f"ai-hacking-{req.name}"
    _run_docker(["stop", cn], timeout=30)
    _run_docker(["rm", cn], timeout=30)
    r = _run_docker(["run", "-d", "--name", cn, "-p", f"{port}:{cfg[chr(99)+chr(111)+chr(110)+chr(116)+chr(97)+chr(105)+chr(110)+chr(101)+chr(114)+chr(95)+chr(112)+chr(111)+chr(114)+chr(116)]}", cfg["image"]], timeout=300)
    if r.get("success"):
        return {"success": True, "data": {"name": req.name, "url": f"http://127.0.0.1:{port}", "creds": cfg["creds"]}}
    return {"success": False, "error": r.get("stderr", "部署失败"), "cmd": f"docker run -d -p {port}:{cfg[chr(99)+chr(111)+chr(110)+chr(116)+chr(97)+chr(105)+chr(110)+chr(101)+chr(114)+chr(95)+chr(112)+chr(111)+chr(114)+chr(116)]} {cfg[chr(105)+chr(109)+chr(97)+chr(103)+chr(101)]}"}

@router.post("/stop/{name}")
def stop_range(name: str):
    cn = f"ai-hacking-{name}"
    r = _run_docker(["stop", cn], timeout=30)
    _run_docker(["rm", cn], timeout=30)
    return {"success": r.get("success", False), "data": {"name": name}}
