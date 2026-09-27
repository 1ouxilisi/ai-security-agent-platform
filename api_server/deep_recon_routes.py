"""
深度侦察与靶场管理API路由
- /api/v1/deep-recon/subdomain - 子域名爆破
- /api/v1/deep-recon/directory - 目录扫描
- /api/v1/deep-recon/api-endpoints - API端点发现
- /api/v1/deep-recon/tech-stack - 技术栈深度识别
- /api/v1/deep-recon/all - 全部深度侦察
- /api/v1/ranges - 靶场列表
- /api/v1/ranges/{id}/status - 靶场状态
- /api/v1/ranges/{id}/deploy - 部署靶场
- /api/v1/ranges/{id}/start - 启动靶场
- /api/v1/ranges/{id}/stop - 停止靶场
- /api/v1/ranges/{id}/remove - 删除靶场
- /api/v1/ranges/{id}/vulnerabilities - 靶场漏洞列表
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm.deep_recon import DeepRecon
from asm.range_manager import RangeManager

router = APIRouter(prefix="/api/v1", tags=["深度侦察与靶场管理"])

# 认证Key（从环境变量或默认值）
API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """验证API Key"""
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


# ============ 请求模型 ============

class SubdomainRequest(BaseModel):
    target: str
    timeout: int = 3
    max_threads: int = 50


class DirectoryRequest(BaseModel):
    target: str
    timeout: int = 3
    max_threads: int = 50


class ApiEndpointRequest(BaseModel):
    target: str
    timeout: int = 3
    max_threads: int = 50


class TechStackRequest(BaseModel):
    target: str
    timeout: int = 3


class DeepReconRequest(BaseModel):
    target: str
    timeout: int = 3
    max_threads: int = 50


class DeployRequest(BaseModel):
    range_id: str
    custom_port: Optional[int] = None


# ============ 深度侦察API ============

@router.post("/deep-recon/subdomain")
async def subdomain_bruteforce(
    request: SubdomainRequest,
    x_api_key: Optional[str] = Header(None)
):
    """子域名爆破"""
    verify_api_key(x_api_key)
    try:
        recon = DeepRecon(request.target, request.timeout, request.max_threads)
        result = recon._subdomain_bruteforce()
        return {
            "status": "success",
            "target": request.target,
            "subdomains_found": len(result),
            "subdomains": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/deep-recon/directory")
async def directory_scan(
    request: DirectoryRequest,
    x_api_key: Optional[str] = Header(None)
):
    """目录扫描"""
    verify_api_key(x_api_key)
    try:
        recon = DeepRecon(request.target, request.timeout, request.max_threads)
        result = recon._directory_scan()
        return {
            "status": "success",
            "target": request.target,
            "directories_found": len(result),
            "directories": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/deep-recon/api-endpoints")
async def api_endpoint_discovery(
    request: ApiEndpointRequest,
    x_api_key: Optional[str] = Header(None)
):
    """API端点发现"""
    verify_api_key(x_api_key)
    try:
        recon = DeepRecon(request.target, request.timeout, request.max_threads)
        result = recon._api_endpoint_discovery()
        return {
            "status": "success",
            "target": request.target,
            "api_endpoints_found": len(result),
            "api_endpoints": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/deep-recon/tech-stack")
async def deep_tech_stack_detect(
    request: TechStackRequest,
    x_api_key: Optional[str] = Header(None)
):
    """技术栈深度识别"""
    verify_api_key(x_api_key)
    try:
        recon = DeepRecon(request.target, request.timeout)
        result = recon._deep_tech_stack_detect()
        return {
            "status": "success",
            "target": request.target,
            "tech_stack": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/deep-recon/all")
async def full_deep_recon(
    request: DeepReconRequest,
    x_api_key: Optional[str] = Header(None)
):
    """全部深度侦察（子域名+目录+API端点+技术栈）"""
    verify_api_key(x_api_key)
    try:
        recon = DeepRecon(request.target, request.timeout, request.max_threads)
        result = recon.run_all()
        return {
            "status": "success",
            "target": request.target,
            "results": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ 靶场管理API ============

@router.get("/ranges")
async def list_ranges(x_api_key: Optional[str] = Header(None)):
    """列出所有支持的靶场"""
    verify_api_key(x_api_key)
    try:
        manager = RangeManager()
        return manager.list_ranges()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ranges/{range_id}/status")
async def get_range_status(range_id: str, x_api_key: Optional[str] = Header(None)):
    """获取靶场状态"""
    verify_api_key(x_api_key)
    try:
        manager = RangeManager()
        return manager.get_range_status(range_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ranges/deploy")
async def deploy_range(
    request: DeployRequest,
    x_api_key: Optional[str] = Header(None)
):
    """部署靶场"""
    verify_api_key(x_api_key)
    try:
        manager = RangeManager()
        return manager.deploy_range(request.range_id, request.custom_port)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ranges/{range_id}/start")
async def start_range(range_id: str, x_api_key: Optional[str] = Header(None)):
    """启动靶场"""
    verify_api_key(x_api_key)
    try:
        manager = RangeManager()
        return manager.start_range(range_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ranges/{range_id}/stop")
async def stop_range(range_id: str, x_api_key: Optional[str] = Header(None)):
    """停止靶场"""
    verify_api_key(x_api_key)
    try:
        manager = RangeManager()
        return manager.stop_range(range_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/ranges/{range_id}")
async def remove_range(range_id: str, x_api_key: Optional[str] = Header(None)):
    """删除靶场"""
    verify_api_key(x_api_key)
    try:
        manager = RangeManager()
        return manager.remove_range(range_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ranges/{range_id}/vulnerabilities")
async def get_range_vulnerabilities(range_id: str, x_api_key: Optional[str] = Header(None)):
    """获取靶场漏洞列表"""
    verify_api_key(x_api_key)
    try:
        manager = RangeManager()
        return manager.get_vulnerability_list(range_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
