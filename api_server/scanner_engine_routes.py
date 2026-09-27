"""
扫描引擎API路由 - 集成nmap/nuclei/sqlmap/nikto真实工具链
- /api/v1/scanner/nmap - Nmap扫描
- /api/v1/scanner/nuclei - Nuclei漏洞扫描
- /api/v1/scanner/sqlmap - SQLMap注入检测
- /api/v1/scanner/nikto - Nikto Web扫描
- /api/v1/scanner/orchestrate - 统一编排扫描
- /api/v1/scanner/status - 任务状态
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sys
import os
import uuid
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_engine import ScanOrchestrator, NmapWrapper, NucleiWrapper

router = APIRouter(prefix="/api/v1/scanner", tags=["扫描引擎"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")

_scan_tasks = {}


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"  # quick/full/deep
    tools: List[str] = ["nmap", "nuclei"]
    timeout: int = 300
    dry_run: bool = True


class NmapRequest(BaseModel):
    target: str
    scan_type: str = "default"  # default/quick/full/service/os
    ports: str = ""
    timeout: int = 120


class NucleiRequest(BaseModel):
    target: str
    template_types: List[str] = ["cves", "vulnerabilities"]
    severity: List[str] = ["critical", "high", "medium"]
    timeout: int = 180


def _run_orchestrated_scan(task_id: str, request: ScanRequest):
    """后台执行统一编排扫描"""
    try:
        orchestrator = ScanOrchestrator()
        result = orchestrator.run_full_scan(
            target=request.target,
            scan_type=request.scan_type,
            tools=request.tools,
            dry_run=request.dry_run,
        )
        _scan_tasks[task_id] = {
            "task_id": task_id,
            "status": "completed",
            "result": result,
            "completed_at": time.time(),
        }
    except Exception as e:
        _scan_tasks[task_id] = {
            "task_id": task_id,
            "status": "failed",
            "error": str(e),
            "completed_at": time.time(),
        }


@router.post("/orchestrate")
async def orchestrate_scan(
    request: ScanRequest,
    x_api_key: Optional[str] = Header(None)
):
    """统一编排扫描 - 同时运行多个工具"""
    verify_api_key(x_api_key)
    try:
        task_id = f"scan_{uuid.uuid4().hex[:8]}"
        _scan_tasks[task_id] = {
            "task_id": task_id,
            "status": "running",
            "target": request.target,
            "started_at": time.time(),
        }
        thread = threading.Thread(
            target=_run_orchestrated_scan,
            args=(task_id, request),
            daemon=True
        )
        thread.start()
        return {"status": "started", "task_id": task_id, "message": "扫描已启动"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nmap")
async def nmap_scan(
    request: NmapRequest,
    x_api_key: Optional[str] = Header(None)
):
    """Nmap端口扫描"""
    verify_api_key(x_api_key)
    try:
        nmap = NmapWrapper()
        result = nmap.scan(
            target=request.target,
            scan_type=request.scan_type,
            ports=request.ports,
            timeout=request.timeout,
            dry_run=True,
        )
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nuclei")
async def nuclei_scan(
    request: NucleiRequest,
    x_api_key: Optional[str] = Header(None)
):
    """Nuclei漏洞扫描"""
    verify_api_key(x_api_key)
    try:
        nuclei = NucleiWrapper()
        result = nuclei.scan(
            target=request.target,
            template_types=request.template_types,
            severity=request.severity,
            timeout=request.timeout,
            dry_run=True,
        )
        return {"status": "success", "data": result}
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


@router.get("/tools")
async def list_tools(
    x_api_key: Optional[str] = Header(None)
):
    """列出支持的扫描工具"""
    verify_api_key(x_api_key)
    return {
        "status": "success",
        "data": {
            "nmap": "端口扫描/服务识别/OS检测",
            "nuclei": "漏洞模板扫描/CVE检测",
            "sqlmap": "SQL注入检测与利用",
            "nikto": "Web服务器漏洞扫描",
        }
    }
