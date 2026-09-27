# -*- coding: utf-8 -*-
"""
api_server/llm_config_routes.py — LLM 配置管理 API 路由

提供 LLM 真实接入（P1-2）所需的全部 REST 端点：
    GET  /api/v1/llm-config/providers        支持的提供商清单
    GET  /api/v1/llm-config/status           当前配置状态
    POST /api/v1/llm-config/save              保存配置到 .env
    POST /api/v1/llm-config/test             测试连接
    POST /api/v1/llm-config/test/chat        测试 AI 助手对话
    POST /api/v1/llm-config/test/vuln-analysis  测试漏洞智能分析
    POST /api/v1/llm-config/test/remediation    测试修复方案生成

统一响应结构：{success: bool, data: Any, error: str|None}
所有端点均有异常兜底，无 Key 时返回「未配置」而不抛 500。
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/llm-config", tags=["LLM配置"])


# ---------------------------------------------------------------------------
# 统一响应辅助
# ---------------------------------------------------------------------------
def _ok(data: Any = None) -> Dict[str, Any]:
    return {"success": True, "data": data, "error": None}


def _err(message: str, data: Any = None) -> Dict[str, Any]:
    return {"success": False, "data": data, "error": message}


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------
class SaveConfigRequest(BaseModel):
    """保存 LLM 配置请求体（所有字段可选，只更新传入项）。"""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(default=None, ge=256, le=16384)


class TestConnectionRequest(BaseModel):
    """测试连接请求体（可选临时参数，不传则用当前已保存配置）。"""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None


class ChatTestRequest(BaseModel):
    """AI 对话测试请求体。"""
    message: str = "你好，请用一句话介绍你能为安全测试做什么。"


class VulnTestRequest(BaseModel):
    """漏洞分析测试请求体。"""
    vuln_description: str = "用户登录接口的 password 参数存在 SQL 注入"
    target: str = "http://example.com/login"
    cve: str = ""


class RemediationTestRequest(BaseModel):
    """修复方案测试请求体。"""
    vuln_description: str = "登录接口 SQL 注入"
    vuln_type: str = "sql_injection"
    target_env: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# 内部：重载所有依赖单例
# ---------------------------------------------------------------------------
def _reload_all_clients() -> None:
    """保存配置后，重置统一客户端与各 AI 模块单例，使新配置立即生效。"""
    try:
        from llm_integration import reset_llm_client, reload_config
        reload_config()
        reset_llm_client()
    except Exception:
        pass
    # 重置各 AI 模块的模块级单例
    for mod_name, var in (
        ("ai.security_assistant", "_assistant"),
        ("ai.vuln_verifier", "_verifier"),
        ("ai.remediation_generator", "_gen"),
        ("ai.natural_language", "_engine"),
    ):
        try:
            import importlib
            mod = importlib.import_module(mod_name)
            if hasattr(mod, var):
                setattr(mod, var, None)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 端点 1：提供商清单
# ---------------------------------------------------------------------------
@router.get("/providers", summary="获取支持的 LLM 提供商列表")
async def list_providers() -> Dict[str, Any]:
    """返回智谱/DeepSeek/硅基流动/OpenAI兼容 的预填参数与申请引导。"""
    try:
        from llm_integration import list_providers as _lp
        return _ok({"providers": _lp()})
    except Exception as e:  # noqa: BLE001
        return _err(f"获取提供商列表失败: {e}")


# ---------------------------------------------------------------------------
# 端点 2：当前配置状态
# ---------------------------------------------------------------------------
@router.get("/status", summary="获取当前 LLM 配置状态")
async def get_status() -> Dict[str, Any]:
    """返回是否已配置、脱敏后的 Key、当前 Base URL / Model。"""
    try:
        from llm_integration import get_config_manager, get_llm_client
        status = get_config_manager().status()
        # 附带一次真实客户端自检（不发请求，只看本地配置是否齐套）
        client = get_llm_client()
        status["client_available"] = bool(client.llm_available)
        return _ok(status)
    except Exception as e:  # noqa: BLE001
        return _err(f"读取配置状态失败: {e}")


# ---------------------------------------------------------------------------
# 端点 3：保存配置
# ---------------------------------------------------------------------------
@router.post("/save", summary="保存 LLM 配置")
async def save_config(req: SaveConfigRequest) -> Dict[str, Any]:
    """保存到 .env，并热重载所有客户端单例。"""
    try:
        from llm_integration import get_config_manager
        result = get_config_manager().save_config(
            api_key=req.api_key,
            base_url=req.base_url,
            model=req.model,
            temperature=req.temperature,
            max_tokens=req.max_tokens,
        )
        if not result.get("success"):
            return _err(result.get("error", "保存失败"), result.get("data"))
        _reload_all_clients()
        return _ok(result.get("data"))
    except Exception as e:  # noqa: BLE001
        return _err(f"保存配置失败: {e}")


# ---------------------------------------------------------------------------
# 端点 4：测试连接
# ---------------------------------------------------------------------------
@router.post("/test", summary="测试 LLM 连接")
async def test_connection(req: TestConnectionRequest) -> Dict[str, Any]:
    """用（可选临时）参数发一个 ping，验证鉴权/网络/模型可用性。"""
    try:
        from llm_integration import LLMClient
        # 优先用请求里临时参数，否则用当前配置
        client = LLMClient(
            api_key=req.api_key or None,
            base_url=req.base_url or None,
            model=req.model or None,
        )
        result = client.test_connection()
        if result["success"]:
            return _ok(result["data"])
        return _err(result.get("error", "连接测试失败"), result.get("data"))
    except Exception as e:  # noqa: BLE001
        return _err(f"连接测试异常: {e}")


# ---------------------------------------------------------------------------
# 端点 5：测试 AI 对话
# ---------------------------------------------------------------------------
@router.post("/test/chat", summary="测试 AI 助手对话")
async def test_chat(req: ChatTestRequest) -> Dict[str, Any]:
    """调用 SecurityAssistant 生成真实回答（未配置则返回降级提示）。"""
    try:
        from llm_integration import get_config_manager
        if not get_config_manager().is_configured():
            return _err("未配置 API Key，请先在「保存配置」中填写",
                        {"fallback": True})
        from ai.security_assistant import SecurityAssistant
        assistant = SecurityAssistant()  # 取最新客户端
        out = assistant.chat(req.message, session_id="llm_config_test")
        return _ok({
            "reply": out.get("reply"),
            "intent": out.get("intent"),
            "llm_used": bool(assistant.llm_available),
        })
    except Exception as e:  # noqa: BLE001
        return _err(f"AI 对话测试失败: {e}")


# ---------------------------------------------------------------------------
# 端点 6：测试漏洞智能分析
# ---------------------------------------------------------------------------
@router.post("/test/vuln-analysis", summary="测试漏洞智能分析")
async def test_vuln_analysis(req: VulnTestRequest) -> Dict[str, Any]:
    """调用 VulnerabilityVerifier 分析漏洞类型并生成验证报告。"""
    try:
        from llm_integration import get_config_manager
        if not get_config_manager().is_configured():
            return _err("未配置 API Key，请先在「保存配置」中填写",
                        {"fallback": True})
        from ai.vuln_verifier import VulnerabilityVerifier
        verifier = VulnerabilityVerifier()
        result = verifier.verify(req.vuln_description, req.target, req.cve)
        report = verifier.generate_verification_report(result)
        return _ok({
            "detected_type": result.get("detected_type"),
            "status": result.get("status"),
            "confidence": result.get("confidence"),
            "evidence": result.get("evidence", []),
            "report": report,
            "llm_used": bool(verifier.llm_available),
        })
    except Exception as e:  # noqa: BLE001
        return _err(f"漏洞分析测试失败: {e}")


# ---------------------------------------------------------------------------
# 端点 7：测试修复方案生成
# ---------------------------------------------------------------------------
@router.post("/test/remediation", summary="测试修复方案生成")
async def test_remediation(req: RemediationTestRequest) -> Dict[str, Any]:
    """调用 RemediationGenerator 生成修复方案（含 LLM 润色）。"""
    try:
        from llm_integration import get_config_manager
        if not get_config_manager().is_configured():
            return _err("未配置 API Key，请先在「保存配置」中填写",
                        {"fallback": True})
        from ai.remediation_generator import RemediationGenerator
        gen = RemediationGenerator()
        plan = gen.generate(req.vuln_description, req.vuln_type,
                            req.target_env or {})
        return _ok({
            "vuln_type": plan.get("vuln_type"),
            "category": plan.get("category"),
            "priority": plan.get("priority"),
            "steps": plan.get("steps", []),
            "verification_method": plan.get("verification_method"),
            "llm_enhanced": plan.get("llm_enhanced"),
            "llm_used": bool(gen.llm_available),
        })
    except Exception as e:  # noqa: BLE001
        return _err(f"修复方案测试失败: {e}")
