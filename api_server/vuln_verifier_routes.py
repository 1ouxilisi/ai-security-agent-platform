"""
漏洞验证框架API路由（第二轮升级）
- /api/v1/vuln-verifier/verify - 验证单个漏洞
- /api/v1/vuln-verifier/verify-batch - 批量验证漏洞
- /api/v1/vuln-verifier/check-auth - 检查目标是否在授权范围内
- /api/v1/vuln-verifier/methods - 列出所有验证方法
- /api/v1/vuln-verifier/summary - 获取验证汇总
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm.vulnerability_verifier import VulnerabilityVerifier, AuthorizationScope

router = APIRouter(prefix="/api/v1/vuln-verifier", tags=["漏洞验证框架"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


def get_verifier():
    """创建验证器实例（默认授权范围：仅本地和测试域名）"""
    auth = AuthorizationScope(
        authorized_targets=["http://127.0.0.1", "http://localhost", "http://test.com"],
        authorized_ips=["127.0.0.1", "localhost"],
        authorization_id="default-api-auth",
        max_rate=20,
    )
    return VulnerabilityVerifier(authorization=auth)


class VulnerabilityItem(BaseModel):
    id: str
    name: str
    category: str  # SQL注入/XSS/命令执行/CORS/安全头/路径遍历/SSRF/XXE/文件上传/文件包含/信息泄露/点击劫持/开放重定向
    severity: str = "medium"
    url: Optional[str] = ""
    parameters: Optional[Dict] = None


class VerifyRequest(BaseModel):
    vulnerability: VulnerabilityItem
    target: str


class VerifyBatchRequest(BaseModel):
    vulnerabilities: List[VulnerabilityItem]
    target: str


class CheckAuthRequest(BaseModel):
    target: str


@router.post("/verify")
async def verify_vulnerability(
    request: VerifyRequest,
    x_api_key: Optional[str] = Header(None)
):
    """验证单个漏洞（仅在授权范围内执行，未授权直接拒绝）"""
    verify_api_key(x_api_key)
    try:
        verifier = get_verifier()
        vuln = request.vulnerability.model_dump()
        result = verifier.verify(vuln, request.target)
        return {
            "status": "success",
            "target": request.target,
            "vulnerability_id": request.vulnerability.id,
            "verification_status": result.status,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "error": result.error
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify-batch")
async def verify_batch(
    request: VerifyBatchRequest,
    x_api_key: Optional[str] = Header(None)
):
    """批量验证漏洞"""
    verify_api_key(x_api_key)
    try:
        verifier = get_verifier()
        vulns = [v.model_dump() for v in request.vulnerabilities]
        results = verifier.verify_batch(vulns, request.target)
        result_data = [
            {
                "vulnerability_id": r.vulnerability_id,
                "status": r.status,
                "confidence": r.confidence,
                "evidence": r.evidence,
                "error": r.error
            }
            for r in results
        ]
        confirmed = sum(1 for r in results if r.status == "confirmed")
        return {
            "status": "success",
            "target": request.target,
            "total": len(results),
            "confirmed": confirmed,
            "results": result_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/check-auth")
async def check_authorization(
    request: CheckAuthRequest,
    x_api_key: Optional[str] = Header(None)
):
    """检查目标是否在授权范围内"""
    verify_api_key(x_api_key)
    try:
        verifier = get_verifier()
        is_auth = verifier.is_authorized(request.target)
        return {
            "status": "success",
            "target": request.target,
            "authorized": is_auth,
            "message": "目标在授权范围内，可以验证" if is_auth else "目标不在授权范围内，拒绝验证"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/methods")
async def list_verification_methods(x_api_key: Optional[str] = Header(None)):
    """列出所有内置验证方法（12种）"""
    verify_api_key(x_api_key)
    try:
        verifier = get_verifier()
        methods = verifier.verification_methods
        return {
            "status": "success",
            "total": len(methods),
            "methods": list(methods.keys())
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary")
async def get_summary(x_api_key: Optional[str] = Header(None)):
    """获取验证汇总统计"""
    verify_api_key(x_api_key)
    try:
        verifier = get_verifier()
        summary = verifier.get_summary()
        return {
            "status": "success",
            "summary": summary
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
