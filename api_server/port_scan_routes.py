"""
真实端口扫描API路由 - 第四轮升级P0
- /api/v1/port-scan/common - 常见端口快速扫描
- /api/v1/port-scan/full - 全端口(1-1000)扫描
- /api/v1/port-scan/status - 扫描任务状态
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any
import sys
import os
import uuid
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm.real_port_scanner import RealPortScanner

router = APIRouter(prefix="/api/v1/port-scan", tags=["真实端口扫描"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")

# 任务存储
_scan_tasks = {}


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


class PortScanRequest(BaseModel):
    target: str
    timeout: float = 2.0
    max_threads: int = 50


def _run_scan(task_id: str, target: str, scan_type: str, timeout: float, max_threads: int):
    """后台执行扫描"""
    try:
        scanner = RealPortScanner(target, timeout, max_threads)
        if scan_type == "common":
            result = scanner.scan_common_ports()
        else:
            result = scanner.scan_full()
        
        _scan_tasks[task_id] = {
            "task_id": task_id,
            "status": "completed",
            "result": result,
            "completed_at": time.time()
        }
    except Exception as e:
        _scan_tasks[task_id] = {
            "task_id": task_id,
            "status": "failed",
            "error": str(e),
            "completed_at": time.time()
        }


@router.post("/common")
async def scan_common_ports(
    request: PortScanRequest,
    x_api_key: Optional[str] = Header(None)
):
    """快速扫描常见端口（39个常用端口，1-2秒完成）"""
    verify_api_key(x_api_key)
    try:
        scanner = RealPortScanner(request.target, request.timeout, request.max_threads)
        result = scanner.scan_common_ports()
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/full")
async def scan_full_ports(
    request: PortScanRequest,
    x_api_key: Optional[str] = Header(None)
):
    """扫描1-1000端口（后台异步任务）"""
    verify_api_key(x_api_key)
    try:
        task_id = f"portscan_{uuid.uuid4().hex[:8]}"
        _scan_tasks[task_id] = {
            "task_id": task_id,
            "status": "running",
            "target": request.target,
            "started_at": time.time()
        }
        
        thread = threading.Thread(
            target=_run_scan,
            args=(task_id, request.target, "full", request.timeout, request.max_threads),
            daemon=True
        )
        thread.start()
        
        return {"status": "started", "task_id": task_id, "message": "全端口扫描已启动，使用 /api/v1/port-scan/status/{task_id} 查询"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{task_id}")
async def get_scan_status(
    task_id: str,
    x_api_key: Optional[str] = Header(None)
):
    """查询扫描任务状态"""
    verify_api_key(x_api_key)
    task = _scan_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"status": "success", "data": task}


@router.get("/list")
async def list_scan_tasks(
    x_api_key: Optional[str] = Header(None)
):
    """列出所有扫描任务"""
    verify_api_key(x_api_key)
    return {"status": "success", "data": list(_scan_tasks.values())}
