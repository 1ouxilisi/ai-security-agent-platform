"""
智能层API路由 - 领域知识注入 + 攻击链推理 + 上下文守卫
- /api/v1/intelligence/system-prompt - 获取系统提示词
- /api/v1/intelligence/attack-chain - 攻击链推理
- /api/v1/intelligence/select-tools - 工具选择
- /api/v1/intelligence/guard - 输出守卫检查
- /api/v1/intelligence/normalize - 输出规范化
- /api/v1/intelligence/test-plan - 生成测试计划
- /api/v1/intelligence/phase - 设置/获取当前阶段
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence_layer import IntelligenceLayer, TestPhase

router = APIRouter(prefix="/api/v1/intelligence", tags=["智能层"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")

_intelligence = IntelligenceLayer()


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


class AttackChainRequest(BaseModel):
    target_type: str = "web_application"
    context: Dict = {}


class ToolSelectRequest(BaseModel):
    phase: str = "scan"
    context: Dict = {}


class GuardRequest(BaseModel):
    response: str


class NormalizeRequest(BaseModel):
    output: str


class TestPlanRequest(BaseModel):
    target: str
    target_type: str = "web_application"
    scope: Dict = {}


class PhaseSetRequest(BaseModel):
    phase: str
    target: str = ""


@router.get("/system-prompt")
async def get_system_prompt(
    x_api_key: Optional[str] = Header(None)
):
    """获取智能层系统提示词"""
    verify_api_key(x_api_key)
    prompt = _intelligence.build_system_prompt()
    return {"status": "success", "data": {"prompt": prompt, "length": len(prompt)}}


@router.post("/attack-chain")
async def attack_chain(
    request: AttackChainRequest,
    x_api_key: Optional[str] = Header(None)
):
    """攻击链推理"""
    verify_api_key(x_api_key)
    try:
        chain = _intelligence.reason_attack_chain(request.target_type)
        return {
            "status": "success",
            "data": {
                "target_type": request.target_type,
                "steps": chain,
                "total_steps": len(chain),
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/select-tools")
async def select_tools(
    request: ToolSelectRequest,
    x_api_key: Optional[str] = Header(None)
):
    """根据阶段选择推荐工具"""
    verify_api_key(x_api_key)
    try:
        phase_map = {
            "recon": TestPhase.RECON,
            "scan": TestPhase.SCAN,
            "exploit": TestPhase.EXPLOIT,
            "post_exploit": TestPhase.POST_EXPLOIT,
            "report": TestPhase.REPORT,
        }
        phase = phase_map.get(request.phase, TestPhase.SCAN)
        tools = _intelligence.select_tools(phase, request.context)
        return {"status": "success", "data": {"phase": request.phase, "tools": tools}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/guard")
async def guard_response(
    request: GuardRequest,
    x_api_key: Optional[str] = Header(None)
):
    """输出守卫检查"""
    verify_api_key(x_api_key)
    safe, reason = _intelligence.guard_response(request.response)
    return {
        "status": "success",
        "data": {
            "safe": safe,
            "reason": reason,
            "blocked": not safe,
        }
    }


@router.post("/normalize")
async def normalize_output(
    request: NormalizeRequest,
    x_api_key: Optional[str] = Header(None)
):
    """输出规范化（JSON/Markdown自动解析）"""
    verify_api_key(x_api_key)
    result = _intelligence.normalize_output(request.output)
    return {
        "status": "success",
        "data": {
            "parse_success": result.parse_success,
            "format": result.format.value,
            "data": result.data,
            "raw": result.raw,
        }
    }


@router.post("/test-plan")
async def generate_test_plan(
    request: TestPlanRequest,
    x_api_key: Optional[str] = Header(None)
):
    """生成测试计划"""
    verify_api_key(x_api_key)
    try:
        plan = _intelligence.generate_test_plan(
            target=request.target,
            target_type=request.target_type,
            scope=request.scope,
        )
        return {"status": "success", "data": plan}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/phase")
async def get_phase(
    x_api_key: Optional[str] = Header(None)
):
    """获取当前测试阶段"""
    verify_api_key(x_api_key)
    return {
        "status": "success",
        "data": {
            "phase": _intelligence.current_phase.value,
            "target": _intelligence.current_target,
        }
    }


@router.post("/phase")
async def set_phase(
    request: PhaseSetRequest,
    x_api_key: Optional[str] = Header(None)
):
    """设置当前测试阶段"""
    verify_api_key(x_api_key)
    phase_map = {
        "recon": TestPhase.RECON,
        "scan": TestPhase.SCAN,
        "exploit": TestPhase.EXPLOIT,
        "post_exploit": TestPhase.POST_EXPLOIT,
        "report": TestPhase.REPORT,
    }
    phase = phase_map.get(request.phase)
    if not phase:
        raise HTTPException(status_code=400, detail=f"无效阶段: {request.phase}")
    _intelligence.set_phase(phase, request.target)
    return {"status": "success", "data": {"phase": request.phase, "target": request.target}}


@router.get("/phases")
async def list_phases(
    x_api_key: Optional[str] = Header(None)
):
    """列出所有测试阶段"""
    verify_api_key(x_api_key)
    return {
        "status": "success",
        "data": [
            {"phase": p.value, "name": p.name, "description": _intelligence.phase_descriptions.get(p, "")}
            for p in TestPhase
        ]
    }


@router.get("/knowledge/vulnerability-patterns")
async def get_vulnerability_patterns(
    x_api_key: Optional[str] = Header(None)
):
    """获取漏洞模式库"""
    verify_api_key(x_api_key)
    return {"status": "success", "data": _intelligence.vulnerability_patterns}


@router.get("/knowledge/methodology")
async def get_methodology(
    x_api_key: Optional[str] = Header(None)
):
    """获取OWASP测试方法论"""
    verify_api_key(x_api_key)
    return {"status": "success", "data": _intelligence.test_methodology}
