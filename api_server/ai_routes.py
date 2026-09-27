# -*- coding: utf-8 -*-
"""
api_server/ai_routes.py — AI 功能 API 路由

提供 AI 相关 REST 接口：自然语言对话、漏洞自动验证、修复方案生成、
AI 安全助手对话、对话历史管理与服务状态。每个端点都做异常兜底，
不向调用方暴露堆栈；导入 AI 模块时也带降级，任一模块缺失不影响整体
服务启动。

合法定位：所有接口均服务于授权安全评估的检测/验证/修复/知识场景。
"""
import time
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/ai", tags=["AI智能"])

# 服务启动时间（用于 uptime）
_START_TIME = time.time()

# ---------------------------------------------------------------------------
# AI 模块导入（全部 try-except 降级）
# ---------------------------------------------------------------------------
_MODULES: Dict[str, Any] = {}

try:
    from ai.natural_language import NaturalLanguageEngine  # type: ignore
    _NL_ENGINE: Optional[NaturalLanguageEngine] = NaturalLanguageEngine()
    _MODULES["natural_language"] = True
except Exception as _e:  # pragma: no cover
    _NL_ENGINE = None
    _MODULES["natural_language"] = False

try:
    from ai.vuln_verifier import VulnerabilityVerifier  # type: ignore
    _VERIFIER: Optional[VulnerabilityVerifier] = VulnerabilityVerifier()
    _MODULES["vuln_verifier"] = True
except Exception as _e:  # pragma: no cover
    _VERIFIER = None
    _MODULES["vuln_verifier"] = False

try:
    from ai.remediation_generator import RemediationGenerator  # type: ignore
    _REMED: Optional[RemediationGenerator] = RemediationGenerator()
    _MODULES["remediation_generator"] = True
except Exception as _e:  # pragma: no cover
    _REMED = False
    _MODULES["remediation_generator"] = False

try:
    from ai.security_assistant import SecurityAssistant  # type: ignore
    _ASSISTANT: Optional[SecurityAssistant] = SecurityAssistant()
    _MODULES["security_assistant"] = True
except Exception as _e:  # pragma: no cover
    _ASSISTANT = None
    _MODULES["security_assistant"] = False


def _require(module_flag: str) -> Any:
    """检查某模块是否加载，未加载则抛 503。"""
    if not _MODULES.get(module_flag):
        raise HTTPException(status_code=503, detail=f"AI 模块 {module_flag} 未加载")
    return True


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------
class ChatRequest(BaseModel):
    """自然语言对话请求体。"""
    message: str
    session_id: Optional[str] = "default"


class VerifyRequest(BaseModel):
    """漏洞验证请求体。"""
    vuln_description: str
    target: str
    cve: Optional[str] = ""


class RemediationRequest(BaseModel):
    """修复方案生成请求体。"""
    vuln_description: str
    vuln_type: str
    target_env: Optional[Dict[str, Any]] = None


class AssistantRequest(BaseModel):
    """AI 助手对话请求体。"""
    message: str
    session_id: Optional[str] = "default"


class ClearChatRequest(BaseModel):
    """清空对话请求体。"""
    session_id: Optional[str] = "default"


# ---------------------------------------------------------------------------
# 端点
# ---------------------------------------------------------------------------
@router.post("/chat", summary="自然语言对话/交互")
async def ai_chat(request: ChatRequest):
    """自然语言交互：意图识别 -> 参数提取 -> 执行 -> 解释。"""
    try:
        _require("natural_language")
        result = _NL_ENGINE.chat(request.message, request.session_id or "default")
        return {
            "status": "success",
            "intent": result.get("intent"),
            "params": result.get("params"),
            "result": result.get("result"),
            "explanation": result.get("explanation"),
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:  # 不暴露堆栈
        raise HTTPException(status_code=500, detail="自然语言处理失败，请稍后重试")


@router.post("/verify", summary="漏洞自动验证")
async def ai_verify(request: VerifyRequest):
    """漏洞非破坏性自动验证（仅检测，不利用）。"""
    try:
        _require("vuln_verifier")
        verification = _VERIFIER.verify(
            vuln_description=request.vuln_description,
            target=request.target,
            cve=request.cve or "",
        )
        report = _VERIFIER.generate_verification_report(verification)
        return {
            "status": "success",
            "verification_result": verification,
            "verification_report": report,
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="漏洞验证失败，请检查目标与描述")


@router.post("/remediation", summary="修复方案生成")
async def ai_remediation(request: RemediationRequest):
    """根据漏洞生成修复方案。"""
    try:
        _require("remediation_generator")
        plan = _REMED.generate(
            vuln_description=request.vuln_description,
            vuln_type=request.vuln_type,
            target_env=request.target_env or {},
        )
        return {
            "status": "success",
            "remediation_plan": plan,
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="修复方案生成失败")


@router.post("/assistant", summary="AI 安全助手对话")
async def ai_assistant(request: AssistantRequest):
    """AI 安全分析师助手对话。"""
    try:
        _require("security_assistant")
        out = _ASSISTANT.chat(request.message, request.session_id or "default")
        return {
            "status": "success",
            "reply": out.get("reply"),
            "related_knowledge": out.get("related_knowledge", []),
            "intent": out.get("intent"),
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="助手回复生成失败")


@router.get("/chat/history", summary="对话历史")
async def ai_chat_history(session_id: str = "default", limit: int = 20):
    """获取自然语言引擎的对话历史。"""
    try:
        _require("natural_language")
        history = _NL_ENGINE.get_context(session_id)
        if limit:
            history = history[-limit:]
        return {"status": "success", "session_id": session_id,
                "total": len(history), "history": history}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="读取对话历史失败")


@router.post("/chat/clear", summary="清空对话")
async def ai_chat_clear(request: ClearChatRequest):
    """清空指定会话的对话历史（自然语言引擎 + 助手）。"""
    try:
        sid = request.session_id or "default"
        nl_cleared = _NL_ENGINE.clear_context(sid) if _MODULES.get("natural_language") else False
        as_cleared = _ASSISTANT.clear_history(sid) if _MODULES.get("security_assistant") else False
        return {"status": "success", "session_id": sid,
                "cleared": bool(nl_cleared or as_cleared)}
    except Exception as e:
        raise HTTPException(status_code=500, detail="清空对话失败")


@router.get("/status", summary="AI 服务状态")
async def ai_status():
    """返回 AI 服务状态与 LLM 连接状态。"""
    try:
        # 汇总 LLM 可用性：任一引擎可用即视为可用
        llm_available = False
        model = ""
        for eng in (_NL_ENGINE, _VERIFIER, _REMED, _ASSISTANT):
            if eng is not None and getattr(eng, "llm_available", False):
                llm_available = True
                model = getattr(eng, "model", "") or model
                break
        loaded = [k for k, v in _MODULES.items() if v]
        return {
            "llm_available": llm_available,
            "model": model,
            "modules_loaded": loaded,
            "modules_total": len(_MODULES),
            "uptime_seconds": round(time.time() - _START_TIME, 1),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="获取 AI 状态失败")
