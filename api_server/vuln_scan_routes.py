"""
漏洞扫描引擎API路由
- /api/v1/vuln-scan/scan - 执行漏洞扫描
- /api/v1/vuln-scan/templates - 列出所有模板
- /api/v1/vuln-scan/template/{template_id} - 查看模板详情
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm.nuclei_engine import NucleiEngine

router = APIRouter(prefix="/api/v1/vuln-scan", tags=["漏洞扫描引擎"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


class ScanRequest(BaseModel):
    target: str
    timeout: int = 5
    max_threads: int = 10
    template_ids: Optional[list] = None  # 指定模板ID，为空则全部扫描


@router.post("/scan")
async def run_vuln_scan(
    request: ScanRequest,
    x_api_key: Optional[str] = Header(None)
):
    """执行漏洞扫描（Nuclei风格模板引擎）"""
    verify_api_key(x_api_key)
    try:
        engine = NucleiEngine(request.target, request.timeout, request.max_threads)

        # 如果指定了模板，过滤
        if request.template_ids:
            engine.templates = [t for t in engine.templates if t["id"] in request.template_ids]

        result = engine.scan_all()
        return {
            "status": "success",
            "target": request.target,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates")
async def list_templates(x_api_key: Optional[str] = Header(None)):
    """列出所有漏洞扫描模板"""
    verify_api_key(x_api_key)
    try:
        engine = NucleiEngine("http://127.0.0.1")
        templates = engine.list_templates()
        return {
            "status": "success",
            "total": len(templates),
            "templates": templates
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/template/{template_id}")
async def get_template(template_id: str, x_api_key: Optional[str] = Header(None)):
    """查看模板详情"""
    verify_api_key(x_api_key)
    try:
        engine = NucleiEngine("http://127.0.0.1")
        template = next((t for t in engine.templates if t["id"] == template_id), None)
        if not template:
            raise HTTPException(status_code=404, detail="模板不存在")
        return {
            "status": "success",
            "template": template
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
