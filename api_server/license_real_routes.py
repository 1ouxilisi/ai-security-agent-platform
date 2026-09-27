# -*- coding: utf-8 -*-
"""
license_real_routes.py — License 授权系统 API（v30.0 真实 License）。

提供 16 个端点：
    POST /api/v1/license/activate        激活 License
    GET  /api/v1/license/status          当前 License 状态
    POST /api/v1/license/verify          验证 License
    GET  /api/v1/license/features        当前版本功能列表
    POST /api/v1/license/generate        生成 License（管理员）
    POST /api/v1/license/reissue         重新签发（管理员，与 generate 同语义）
    POST /api/v1/license/deactivate      卸载 License
    GET  /api/v1/license/history         签发/激活历史
    GET  /api/v1/license/machine-code   当前主机机器码
    GET  /api/v1/license/tiers           版本对比表
    POST /api/v1/license/check-feature   检查功能是否解锁
    GET  /api/v1/license/quota           今日 API 配额
    POST /api/v1/license/consume-quota   消耗 API 配额
    GET  /api/v1/license/upgrade-guide   升级/续费引导
    GET  /api/v1/license/health          健康探针
    GET  /license-management             深色主题管理控制台（HTML）

统一响应: {"success": bool, "data": ..., "error": {"code","message"} | None}
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

# 让 api_server 包外的模块可被导入
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from license_system.feature_gating import get_gate        # noqa: E402
from license_system.license_manager import get_manager      # noqa: E402
from license_system.license_verifier import get_verifier   # noqa: E402
from license_system.license_generator import (            # noqa: E402
    REAL_TIERS,
    VALID_TIER_CODES,
    generate_machine_code,
)

router = APIRouter(prefix="/api/v1/license", tags=["License 授权系统 v30"])

_CONSOLE_HTML = Path(__file__).parent / "license_console.html"


# ============================ 统一响应辅助 ============================
def _ok(data) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _err(code: str, message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"success": False, "data": None,
                 "error": {"code": code, "message": message}},
    )


# ============================ 请求模型 ============================
class ActivateRequest(BaseModel):
    license_key: str = Field(..., description="完整 License 字符串")


class VerifyRequest(BaseModel):
    license_key: str = Field(..., description="待验证的 License 字符串")
    expected_machine_code: Optional[str] = Field(
        None, description="期望机器码；默认使用当前主机机器码")


class GenerateRequest(BaseModel):
    tier: str = Field("pro", description="版本等级: free/pro/enterprise")
    customer: str = Field("Anonymous", description="授权客户名称")
    duration_days: int = Field(365, description="有效期（天）")
    machine_code: Optional[str] = Field(
        None, description="绑定机器码；默认使用当前主机机器码")


class CheckFeatureRequest(BaseModel):
    feature: str = Field(..., description="功能标识，如 ai_analysis")


class CheckModuleRequest(BaseModel):
    module: str = Field(..., description="模块标识，如 vuln_scan")


class ConsumeQuotaRequest(BaseModel):
    amount: int = Field(1, description="消耗额度", ge=1)
    customer: str = Field("default", description="客户标识")


# ============================ 端点 ============================

@router.post("/activate")
def activate(req: ActivateRequest):
    """激活 License Key。"""
    mgr = get_manager()
    result = mgr.activate(req.license_key.strip())
    if not result["success"]:
        code = result["error"]["code"]
        status = 400 if code in {"invalid_format", "bad_signature",
                                 "unknown_tier"} else 402
        return _err(code, result["error"]["message"], status)
    return _ok(result["data"])


@router.get("/status")
def status():
    """获取当前 License 状态。"""
    return _ok(get_manager().status())


@router.post("/verify")
def verify(req: VerifyRequest):
    """验证一份 License 是否有效（不改变当前激活状态）。"""
    result = get_verifier().verify(
        req.license_key.strip(),
        expected_machine_code=req.expected_machine_code,
    )
    if not result["valid"]:
        return _err(result["code"], result["reason"], 400)
    return _ok({
        "valid": True,
        "days_remaining": result["days_remaining"],
        "payload": result["payload"],
    })


@router.get("/features")
def features():
    """当前版本功能列表 + 全版本对比。"""
    return _ok(get_manager().features())


@router.post("/generate")
def generate(req: GenerateRequest):
    """【管理员】生成一份 License。"""
    if req.tier not in REAL_TIERS:
        return _err("unknown_tier",
                    f"未知版本等级 {req.tier}，可选 {VALID_TIER_CODES}", 400)
    result = get_manager().issue_license(
        machine_code=req.machine_code,
        tier=req.tier,
        customer=req.customer,
        duration_days=req.duration_days,
    )
    if not result["success"]:
        return _err(result["error"]["code"], result["error"]["message"])
    return _ok(result["data"])


@router.post("/reissue")
def reissue(req: GenerateRequest):
    """【管理员】重新签发一份 License（语义同 generate）。"""
    return generate(req)


@router.post("/deactivate")
def deactivate():
    """卸载当前 License。"""
    return _ok(get_manager().deactivate()["data"])


@router.get("/history")
def history():
    """签发 / 激活历史记录。"""
    return _ok(get_manager().history())


@router.get("/machine-code")
def machine_code():
    """获取当前主机机器码（用于向供应商申请 License）。"""
    return _ok({
        "machine_code": generate_machine_code(),
        "hint": "将此机器码发给供应商生成 License，"
                "或在生成接口中传入 machine_code 字段。",
    })


@router.get("/tiers")
def tiers():
    """版本对比表（Free / Pro / Enterprise）。"""
    from license_system.feature_gating import TIER_COMPARISON
    return _ok({"tiers": TIER_COMPARISON,
                "valid_codes": list(VALID_TIER_CODES)})


@router.post("/check-feature")
def check_feature(req: CheckFeatureRequest):
    """检查某功能是否在当前版本解锁。"""
    mgr = get_manager()
    active = mgr.status()
    payload = None
    if active.get("activated"):
        # 重新构造 payload 供 gate 使用
        payload = {
            "tier": active["tier"],
            "features": active.get("features", []),
            "modules": active.get("modules", []),
        }
    gate = get_gate()
    ok_flag = gate.has_feature(payload, req.feature)
    return _ok({
        "feature": req.feature,
        "unlocked": ok_flag,
        "tier": active.get("tier", "free"),
    })


@router.post("/check-module")
def check_module(req: CheckModuleRequest):
    """检查某模块是否在当前版本解锁。"""
    mgr = get_manager()
    active = mgr.status()
    payload = None
    if active.get("activated"):
        payload = {
            "tier": active["tier"],
            "features": active.get("features", []),
            "modules": active.get("modules", []),
        }
    gate = get_gate()
    ok_flag = gate.has_module(payload, req.module)
    return _ok({
        "module": req.module,
        "unlocked": ok_flag,
        "tier": active.get("tier", "free"),
    })


@router.get("/quota")
def quota(customer: str = "default"):
    """查询今日 API 配额。"""
    mgr = get_manager()
    active = mgr.status()
    payload = None
    if active.get("activated"):
        payload = {"tier": active["tier"]}
    return _ok(get_gate().check_quota(payload, customer))


@router.post("/consume-quota")
def consume_quota(req: ConsumeQuotaRequest):
    """消耗 API 配额（内部中间件调用）。"""
    mgr = get_manager()
    active = mgr.status()
    payload = None
    if active.get("activated"):
        payload = {"tier": active["tier"]}
    result = get_gate().consume_quota(payload, req.customer, req.amount)
    if result["exceeded"]:
        return _err(
            "quota_exceeded",
            f"今日 API 配额已用尽（{result['used']}/{result['limit']}），"
            f"请升级到专业版 / 企业版",
            429,
        )
    return _ok(result)


@router.get("/upgrade-guide")
def upgrade_guide():
    """升级 / 续费引导。"""
    return _ok(get_manager().status().get("upgrade_guide"))


@router.get("/health")
def health():
    """License 子系统健康探针。"""
    return _ok({
        "ok": True,
        "tier_loaded": list(VALID_TIER_CODES),
        "machine_code": generate_machine_code(),
    })


# ============================ HTML 控制台页面 ============================
@router.get("/license-management", include_in_schema=False)
def license_management_page():
    """深色主题 License 管理控制台页面。"""
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise HTTPException(status_code=500,
                            detail="license_console.html 未找到")
    return HTMLResponse(content=html)


# 同时在根路径注册一个别名，方便用户访问
root_router = APIRouter(tags=["License 授权系统 v30"])


@root_router.get("/license-management", include_in_schema=False)
def license_management_page_root():
    return license_management_page()
