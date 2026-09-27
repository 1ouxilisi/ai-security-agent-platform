# -*- coding: utf-8 -*-
"""
zero_trust_routes.py — 零信任安全 REST API（第13轮升级模块）。

路由前缀：/api/v1/zero-trust
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典模拟异步任务（task_id -> status/results）。
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 可选 logger
try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

# 核心模块 try-import
try:
    from zero_trust.identity_access import get_identity_access_manager
    from zero_trust.continuous_verification import get_continuous_verifier
    from zero_trust.microsegmentation import get_microsegmentation_manager
    from zero_trust.device_trust import get_device_trust_manager
    from zero_trust.application_api_security import get_application_api_security_manager
    from zero_trust.zero_trust_maturity import get_zero_trust_maturity_assessor
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("zero_trust_routes: 模块导入失败: %s", _e)
    get_identity_access_manager = None  # type: ignore
    get_continuous_verifier = None  # type: ignore
    get_microsegmentation_manager = None  # type: ignore
    get_device_trust_manager = None  # type: ignore
    get_application_api_security_manager = None  # type: ignore
    get_zero_trust_maturity_assessor = None  # type: ignore
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/zero-trust", tags=["零信任安全"])


# ==================== 响应工具 ====================

# 清理无效 Unicode（控制字符等）
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, list):
        return [_clean(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": err})


# ==================== 内存任务存储 ====================

TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(),
    }
    return tid


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return TASKS.get(task_id)


def _run_task(task_type: str, func) -> str:
    tid = _new_task(task_type)
    TASKS[tid]["status"] = "running"
    try:
        result = func()
        TASKS[tid]["status"] = "success"
        TASKS[tid]["result"] = result
    except Exception as e:  # pragma: no cover
        TASKS[tid]["status"] = "failed"
        TASKS[tid]["error"] = str(e)
    return tid


# ==================== 请求模型 ====================

class IdentityAssessReq(BaseModel):
    scope: str = "all"          # all / privileged / dormant
    include_report: bool = True


class VerificationEvaluateReq(BaseModel):
    username: str = "user0001"
    device_id: str = "dev-0001"
    ip: str = "10.0.0.1"
    country: str = "CN"
    app: str = "app_1"


class MicrosegAnalyzeReq(BaseModel):
    deep: bool = True
    include_flows: bool = True


class DeviceAssessReq(BaseModel):
    device_id: Optional[str] = None
    include_inventory: bool = True


class ApplicationAssessReq(BaseModel):
    include_services: bool = True
    include_gateway: bool = True


class MaturityAssessReq(BaseModel):
    industry: str = "金融"
    target_stage: int = 4


# ==================== 1. 身份与访问 API ====================

@router.post("/identity/assess")
def identity_assess(req: IdentityAssessReq):
    try:
        if not _MODULES_OK:
            return _fail("零信任模块未正确加载", {"task_id": None})
        mgr = get_identity_access_manager()
        tid = _run_task("identity", lambda: mgr.full_assessment())
        return _ok({"task_id": tid, "message": "身份与访问评估任务已启动"})
    except Exception as e:
        return _fail(f"身份评估启动失败: {e}")


@router.get("/identity/{task_id}/status")
def identity_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/identity/{task_id}/results")
def identity_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成，当前状态: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/identity/{task_id}/report")
def identity_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        r = t["result"] or {}
        return _ok({
            "report_title": r.get("report_title", "身份与访问安全评估报告"),
            "generated_at": r.get("generated_at"),
            "overall_score": r.get("overall_score"),
            "executive_summary": r.get("executive_summary"),
            "top_remediations": r.get("top_remediations"),
            "mfa": r.get("mfa"),
            "sso": r.get("sso"),
            "pam": r.get("pam"),
            "lifecycle": r.get("lifecycle"),
        })
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/identity/users")
def identity_users(limit: int = Query(100, ge=1, le=500)):
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_identity_access_manager()
        return _ok({"users": mgr.list_users(limit), "total": len(mgr.users)})
    except Exception as e:
        return _fail(f"获取用户列表失败: {e}")


@router.get("/identity/privileged")
def identity_privileged():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_identity_access_manager()
        pv = mgr.list_privileged()
        return _ok({"privileged_users": pv, "count": len(pv)})
    except Exception as e:
        return _fail(f"获取特权账户失败: {e}")


# ==================== 2. 持续验证 API ====================

@router.post("/verification/evaluate")
def verification_evaluate(req: VerificationEvaluateReq):
    try:
        if not _MODULES_OK:
            return _fail("零信任模块未正确加载", {"task_id": None})
        ver = get_continuous_verifier()

        def _run():
            rt = ver.realtime_risk(req.username, req.device_id, req.ip,
                                   req.country, app=req.app)
            return {"realtime": rt, "report": ver.full_report()}

        tid = _run_task("verification", _run)
        return _ok({"task_id": tid, "message": "持续验证评估已启动"})
    except Exception as e:
        return _fail(f"持续验证启动失败: {e}")


@router.get("/verification/{task_id}/status")
def verification_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/verification/{task_id}/results")
def verification_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/verification/{task_id}/report")
def verification_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok((t["result"] or {}).get("report"))
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/verification/risk-scores")
def verification_risk_scores():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        ver = get_continuous_verifier()
        return _ok(ver.session_monitor())
    except Exception as e:
        return _fail(f"获取风险评分失败: {e}")


@router.get("/verification/policies")
def verification_policies():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        ver = get_continuous_verifier()
        sample = ver.adaptive_policy(70, 60, 50, 55)
        return _ok({"adaptive_actions": sample, "step_up_thresholds": ver._action.__doc__ or "..."})
    except Exception as e:
        return _fail(f"获取策略失败: {e}")


# ==================== 3. 微隔离 API ====================

@router.post("/microsegmentation/analyze")
def microseg_analyze(req: MicrosegAnalyzeReq):
    try:
        if not _MODULES_OK:
            return _fail("零信任模块未正确加载", {"task_id": None})
        mgr = get_microsegmentation_manager()
        tid = _run_task("microseg", lambda: mgr.full_report())
        return _ok({"task_id": tid, "message": "微隔离分析已启动"})
    except Exception as e:
        return _fail(f"微隔离分析启动失败: {e}")


@router.get("/microsegmentation/{task_id}/status")
def microseg_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/microsegmentation/{task_id}/results")
def microseg_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/microsegmentation/{task_id}/report")
def microseg_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        r = t["result"] or {}
        return _ok({
            "report_title": r.get("report_title"),
            "overall_score": r.get("overall_score"),
            "topology": r.get("topology"),
            "policies": r.get("policies"),
            "ztna": r.get("ztna"),
            "sdp": r.get("sdp"),
            "summary": r.get("summary"),
        })
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/microsegmentation/topology")
def microseg_topology():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_microsegmentation_manager()
        return _ok(mgr.analyze_topology())
    except Exception as e:
        return _fail(f"获取拓扑失败: {e}")


@router.get("/microsegmentation/policies")
def microseg_policies():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_microsegmentation_manager()
        return _ok(mgr.assess_policies())
    except Exception as e:
        return _fail(f"获取策略失败: {e}")


# ==================== 4. 设备信任 API ====================

@router.post("/device/assess")
def device_assess(req: DeviceAssessReq):
    try:
        if not _MODULES_OK:
            return _fail("零信任模块未正确加载", {"task_id": None})
        mgr = get_device_trust_manager()
        tid = _run_task("device", lambda: mgr.full_report())
        return _ok({"task_id": tid, "message": "设备信任评估已启动"})
    except Exception as e:
        return _fail(f"设备评估启动失败: {e}")


@router.get("/device/{task_id}/status")
def device_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/device/{task_id}/results")
def device_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/device/{task_id}/report")
def device_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        r = t["result"] or {}
        return _ok({
            "report_title": r.get("report_title"),
            "overall_score": r.get("overall_score"),
            "compliance": r.get("compliance"),
            "edr": r.get("edr"),
            "jailbreak_root": r.get("jailbreak_root"),
            "byod": r.get("byod"),
            "summary": r.get("summary"),
        })
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/device/inventory")
def device_inventory():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_device_trust_manager()
        inv = mgr.list_inventory()
        return _ok({"inventory": inv, "total": len(inv)})
    except Exception as e:
        return _fail(f"获取设备清单失败: {e}")


@router.get("/device/compliance")
def device_compliance():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_device_trust_manager()
        return _ok(mgr.compliance_check())
    except Exception as e:
        return _fail(f"获取合规状态失败: {e}")


# ==================== 5. 应用与API安全 API ====================

@router.post("/application/assess")
def application_assess(req: ApplicationAssessReq):
    try:
        if not _MODULES_OK:
            return _fail("零信任模块未正确加载", {"task_id": None})
        mgr = get_application_api_security_manager()
        tid = _run_task("appapi", lambda: mgr.full_report())
        return _ok({"task_id": tid, "message": "应用与API安全评估已启动"})
    except Exception as e:
        return _fail(f"应用评估启动失败: {e}")


@router.get("/application/{task_id}/status")
def application_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/application/{task_id}/results")
def application_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/application/{task_id}/report")
def application_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        r = t["result"] or {}
        return _ok({
            "report_title": r.get("report_title"),
            "overall_score": r.get("overall_score"),
            "mtls_mesh": r.get("mtls_mesh"),
            "api_gateway": r.get("api_gateway"),
            "service_accounts": r.get("service_accounts"),
            "summary": r.get("summary"),
        })
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/application/services")
def application_services():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_application_api_security_manager()
        sv = mgr.list_services()
        return _ok({"services": sv, "total": len(sv)})
    except Exception as e:
        return _fail(f"获取服务清单失败: {e}")


@router.get("/application/api-gateway")
def application_api_gateway():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_application_api_security_manager()
        return _ok(mgr.api_gateway_assessment())
    except Exception as e:
        return _fail(f"获取 API 网关状态失败: {e}")


# ==================== 6. 成熟度评估 API ====================

@router.post("/maturity/assess")
def maturity_assess(req: MaturityAssessReq):
    try:
        if not _MODULES_OK:
            return _fail("零信任模块未正确加载", {"task_id": None})
        mgr = get_zero_trust_maturity_assessor()
        tid = _run_task("maturity", lambda: mgr.full_assessment(req.industry))
        return _ok({"task_id": tid, "message": "成熟度评估已启动"})
    except Exception as e:
        return _fail(f"成熟度评估启动失败: {e}")


@router.get("/maturity/{task_id}/status")
def maturity_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/maturity/{task_id}/results")
def maturity_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/maturity/{task_id}/report")
def maturity_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        r = t["result"] or {}
        return _ok({
            "report_title": r.get("report_title"),
            "overall": r.get("overall"),
            "dimensions": r.get("dimensions"),
            "gap_analysis": r.get("gap_analysis"),
            "roadmap": r.get("roadmap"),
            "benchmark": r.get("benchmark"),
            "summary": r.get("summary"),
        })
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/maturity/roadmap")
def maturity_roadmap():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_zero_trust_maturity_assessor()
        return _ok(mgr.roadmap())
    except Exception as e:
        return _fail(f"获取路线图失败: {e}")


@router.get("/maturity/history")
def maturity_history():
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        mgr = get_zero_trust_maturity_assessor()
        return _ok({"history": mgr.list_history()})
    except Exception as e:
        return _fail(f"获取历史失败: {e}")
