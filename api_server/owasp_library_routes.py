"""
OWASP测试用例库API路由 - 120+测试用例
- /api/v1/owasp/cases - 列出用例
- /api/v1/owasp/cases/{id} - 获取用例详情
- /api/v1/owasp/categories - 分类统计
- /api/v1/owasp/plan - 生成测试计划
- /api/v1/owasp/stats - 统计信息
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from owasp_library import OWASPCaseLibrary

router = APIRouter(prefix="/api/v1/owasp", tags=["OWASP测试用例库"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")

_library = OWASPCaseLibrary()


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


class PlanRequest(BaseModel):
    categories: List[str] = []
    severity_filter: List[str] = []
    automated_only: bool = False


@router.get("/cases")
async def list_cases(
    category: str = "",
    severity: str = "",
    automated: str = "",
    x_api_key: Optional[str] = Header(None)
):
    """列出测试用例"""
    verify_api_key(x_api_key)
    cases = _library.list_cases(
        category=category or None,
        severity=severity or None,
        automated=automated.lower() == "true" if automated else None,
    )
    return {
        "status": "success",
        "total": len(cases),
        "data": [
            {
                "case_id": c.case_id,
                "name": c.name,
                "category": c.category,
                "severity": c.severity,
                "automated": c.automated,
                "cwe_id": c.cwe_id,
            }
            for c in cases
        ]
    }


@router.get("/cases/{case_id}")
async def get_case(
    case_id: str,
    x_api_key: Optional[str] = Header(None)
):
    """获取测试用例详情"""
    verify_api_key(x_api_key)
    case = _library.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="用例不存在")
    return {
        "status": "success",
        "data": {
            "case_id": case.case_id,
            "name": case.name,
            "category": case.category,
            "category_name": case.category_name,
            "description": case.description,
            "severity": case.severity,
            "automated": case.automated,
            "cwe_id": case.cwe_id,
            "preconditions": case.preconditions,
            "test_method": case.test_method,
            "test_steps": case.test_steps,
            "expected_result": case.expected_result,
            "recommended_tools": case.recommended_tools,
            "payloads": case.payloads,
            "references": case.references,
        }
    }


@router.get("/categories")
async def get_categories(
    x_api_key: Optional[str] = Header(None)
):
    """获取分类列表"""
    verify_api_key(x_api_key)
    return {"status": "success", "data": _library.get_categories()}


@router.post("/plan")
async def generate_plan(
    request: PlanRequest,
    x_api_key: Optional[str] = Header(None)
):
    """生成测试计划"""
    verify_api_key(x_api_key)
    plan = _library.generate_test_plan(
        categories=request.categories,
        severity_filter=request.severity_filter,
        automated_only=request.automated_only,
    )
    return {
        "status": "success",
        "total": len(plan),
        "data": [
            {
                "case_id": c.case_id,
                "name": c.name,
                "category": c.category,
                "severity": c.severity,
                "automated": c.automated,
            }
            for c in plan
        ]
    }


@router.get("/stats")
async def get_stats(
    x_api_key: Optional[str] = Header(None)
):
    """获取统计信息"""
    verify_api_key(x_api_key)
    return {"status": "success", "data": _library.get_stats()}


@router.get("/top10")
async def get_top10(
    x_api_key: Optional[str] = Header(None)
):
    """获取OWASP Top 10概览"""
    verify_api_key(x_api_key)
    return {
        "status": "success",
        "data": {
            "A01": "失效的访问控制 (Broken Access Control)",
            "A02": "加密失败 (Cryptographic Failures)",
            "A03": "注入 (Injection)",
            "A04": "不安全的设计 (Insecure Design)",
            "A05": "安全配置错误 (Security Misconfiguration)",
            "A06": "易受攻击和过时的组件 (Vulnerable and Outdated Components)",
            "A07": "身份识别和认证失败 (Identification and Authentication Failures)",
            "A08": "软件和数据完整性失败 (Software and Data Integrity Failures)",
            "A09": "安全日志和监控失败 (Security Logging and Monitoring Failures)",
            "A10": "服务器端请求伪造 (Server-Side Request Forgery)",
        }
    }
