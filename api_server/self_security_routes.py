# -*- coding: utf-8 -*-
"""
self_security_routes.py — 自身安全加固大提升 REST API（第19轮升级方向2）。

路由前缀: /api/v1/self-security
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

安全边界：所有"渗透测试"均为对本平台自身代码 / 配置的只读静态评估，
不对任何外部目标发起攻击。
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/self-security", tags=["安全加固"])

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
# 业务模块加载（try-import，失败回退模拟数据）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    import sys
    if _PROJECT_ROOT not in sys.path:
        sys.path.insert(0, _PROJECT_ROOT)
    from self_security import (api_security_hardening, code_security_audit,
                               data_security_privacy, runtime_protection,
                               security_dashboard, self_pentest)
    from self_security.common import clean
    _MOD_AVAILABLE = True
    logger.info("self_security_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("self_security_routes: load failed: %s", e)

    def clean(obj: Any) -> Any:  # type: ignore[misc]
        return obj


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    _TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in _TASKS:
        t = _TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return _TASKS.get(task_id)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("自身安全模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class WAFInspectRequest(BaseModel):
    payload: str = Field(default="", description="待检测输入片段")
    source: str = "query"


class ScanConfigRequest(BaseModel):
    depth: str = Query(default="normal", description="quick/normal/deep")  # type: ignore
    modules: List[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# 控制台 HTML 页（不修改 app.py，直接由本路由挂载）
# --------------------------------------------------------------------------- #
@router.get("/console", include_in_schema=False)
def console_page():
    try:
        page = os.path.join(os.path.dirname(__file__), "self_security_console.html")
        if not os.path.exists(page):
            return fail("控制台页面不存在", 404)
        return FileResponse(page, media_type="text/html; charset=utf-8")
    except Exception as e:
        return fail(f"打开控制台失败: {e}", 500)


# =========================================================================== #
# 1. 自身渗透测试（6 个端点）
# =========================================================================== #
@router.get("/pentest/scan")
def pentest_scan(depth: str = Query(default="normal")):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("pentest.scan")
        result = self_pentest.get_pentest_scanner().run_full_scan()
        result["depth"] = depth
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:
        logger.exception("pentest_scan error")
        return fail(f"渗透扫描失败: {e}", 500)


@router.get("/pentest/injection")
def pentest_injection():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(self_pentest.get_pentest_scanner().injection_detection())
    except Exception as e:
        return fail(f"注入检测失败: {e}", 500)


@router.get("/pentest/authz")
def pentest_authz():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(self_pentest.get_pentest_scanner().authz_test())
    except Exception as e:
        return fail(f"认证授权测试失败: {e}", 500)


@router.get("/pentest/disclosure")
def pentest_disclosure():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(self_pentest.get_pentest_scanner().sensitive_disclosure())
    except Exception as e:
        return fail(f"敏感信息泄露检测失败: {e}", 500)


@router.get("/pentest/config")
def pentest_config():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(self_pentest.get_pentest_scanner().config_audit())
    except Exception as e:
        return fail(f"配置安全检查失败: {e}", 500)


@router.get("/pentest/owasp")
def pentest_owasp():
    try:
        return ok({"owasp_top10_2021": self_pentest.OWASP_TOP10})
    except Exception as e:
        return fail(f"OWASP 列表失败: {e}", 500)


# =========================================================================== #
# 2. 代码安全审计（6 个端点）
# =========================================================================== #
@router.get("/audit/deps")
def audit_deps():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(code_security_audit.get_auditor().dependency_scan())
    except Exception as e:
        return fail(f"依赖扫描失败: {e}", 500)


@router.get("/audit/sast-rules")
def audit_sast_rules():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(code_security_audit.get_auditor().sast_rules_library())
    except Exception as e:
        return fail(f"SAST 规则库失败: {e}", 500)


@router.get("/audit/sast-scan")
def audit_sast_scan():
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("audit.scan")
        result = code_security_audit.get_auditor().static_analysis()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"SAST 扫描失败: {e}", 500)


@router.get("/audit/complexity")
def audit_complexity():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(code_security_audit.get_auditor().complexity_analysis())
    except Exception as e:
        return fail(f"复杂度分析失败: {e}", 500)


@router.get("/audit/standards")
def audit_standards():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(code_security_audit.get_auditor().coding_standards_check())
    except Exception as e:
        return fail(f"规范检查失败: {e}", 500)


@router.get("/audit/full")
def audit_full():
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("audit.full")
        result = code_security_audit.get_auditor().full_audit()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"完整审计失败: {e}", 500)


# =========================================================================== #
# 3. API 安全加固（6 个端点）
# =========================================================================== #
@router.get("/hardening/auth")
def hardening_auth():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(api_security_hardening.get_hardener().auth_hardening())
    except Exception as e:
        return fail(f"认证强化分析失败: {e}", 500)


@router.get("/hardening/authz")
def hardening_authz():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(api_security_hardening.get_hardener().authz_hardening())
    except Exception as e:
        return fail(f"授权强化分析失败: {e}", 500)


@router.get("/hardening/input")
def hardening_input():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(api_security_hardening.get_hardener().input_validation())
    except Exception as e:
        return fail(f"输入验证分析失败: {e}", 500)


@router.get("/hardening/rate-limit")
def hardening_rate():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(api_security_hardening.get_hardener().rate_limit_analysis())
    except Exception as e:
        return fail(f"速率限制分析失败: {e}", 500)


@router.get("/hardening/headers")
def hardening_headers():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(api_security_hardening.get_hardener().security_headers())
    except Exception as e:
        return fail(f"安全头检查失败: {e}", 500)


@router.get("/hardening/overview")
def hardening_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(api_security_hardening.get_hardener().hardening_overview())
    except Exception as e:
        return fail(f"加固总览失败: {e}", 500)


# =========================================================================== #
# 4. 数据安全与隐私（5 个端点）
# =========================================================================== #
@router.get("/data/discover")
def data_discover():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_privacy.get_privacy_guard().discover_sensitive_data())
    except Exception as e:
        return fail(f"敏感数据识别失败: {e}", 500)


@router.get("/data/encryption")
def data_encryption():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_privacy.get_privacy_guard().encryption_assessment())
    except Exception as e:
        return fail(f"加密评估失败: {e}", 500)


@router.get("/data/masking")
def data_masking():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_privacy.get_privacy_guard().masking_demo())
    except Exception as e:
        return fail(f"脱敏示例失败: {e}", 500)


@router.get("/data/access-audit")
def data_access_audit():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_privacy.get_privacy_guard().access_audit())
    except Exception as e:
        return fail(f"访问审计失败: {e}", 500)


@router.get("/data/privacy")
def data_privacy():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(data_security_privacy.get_privacy_guard().privacy_compliance())
    except Exception as e:
        return fail(f"隐私合规失败: {e}", 500)


# =========================================================================== #
# 5. 运行时安全防护（6 个端点）
# =========================================================================== #
@router.get("/runtime/waf")
def runtime_waf():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(runtime_protection.get_protector().waf_rules())
    except Exception as e:
        return fail(f"WAF 规则查询失败: {e}", 500)


@router.post("/runtime/waf/inspect")
def runtime_waf_inspect(req: WAFInspectRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(runtime_protection.get_protector().waf_inspect(req.payload))
    except Exception as e:
        return fail(f"WAF 检测失败: {e}", 500)


@router.get("/runtime/ids")
def runtime_ids():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(runtime_protection.get_protector().intrusion_detection())
    except Exception as e:
        return fail(f"入侵检测失败: {e}", 500)


@router.get("/runtime/logs")
def runtime_logs():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(runtime_protection.get_protector().log_audit())
    except Exception as e:
        return fail(f"日志审计失败: {e}", 500)


@router.get("/runtime/ueba")
def runtime_ueba():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(runtime_protection.get_protector().ueba())
    except Exception as e:
        return fail(f"异常行为检测失败: {e}", 500)


@router.get("/runtime/incident")
def runtime_incident():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(runtime_protection.get_protector().incident_response())
    except Exception as e:
        return fail(f"应急响应失败: {e}", 500)


# =========================================================================== #
# 6. 安全仪表盘与报告（6 个端点）
# =========================================================================== #
@router.get("/dashboard/posture")
def dash_posture():
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("dash.posture")
        result = security_dashboard.get_dashboard().posture_overview()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"态势大屏失败: {e}", 500)


@router.get("/dashboard/score")
def dash_score():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(security_dashboard.get_dashboard().compute_score())
    except Exception as e:
        return fail(f"安全评分失败: {e}", 500)


@router.get("/dashboard/vulns")
def dash_vulns():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(security_dashboard.get_dashboard().vuln_management())
    except Exception as e:
        return fail(f"漏洞管理失败: {e}", 500)


@router.get("/dashboard/report")
def dash_report():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(security_dashboard.get_dashboard().report())
    except Exception as e:
        return fail(f"安全报告失败: {e}", 500)


@router.get("/dashboard/baseline")
def dash_baseline():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(security_dashboard.get_dashboard().baseline_check())
    except Exception as e:
        return fail(f"基线检查失败: {e}", 500)


@router.get("/dashboard/training")
def dash_training():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(security_dashboard.get_dashboard().training())
    except Exception as e:
        return fail(f"安全培训失败: {e}", 500)


# =========================================================================== #
# 任务查询（2 个端点）
# =========================================================================== #
@router.get("/tasks/{task_id}")
def task_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({"task_id": t["task_id"], "kind": t["kind"], "status": t["status"],
                   "created_at": t["created_at"], "finished_at": t["finished_at"]})
    except Exception as e:
        return fail(f"任务查询失败: {e}", 500)


@router.get("/tasks/{task_id}/result")
def task_result(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"任务结果查询失败: {e}", 500)


@router.get("/meta")
def meta_info():
    try:
        from self_security.api_routes import ENDPOINT_INDEX
        return ok({
            "module": "self_security",
            "version": "19.2.0",
            "endpoints": len(ENDPOINT_INDEX) + 3,
            "note": "自身安全加固：所有检测均为只读静态分析，不对外部目标发起攻击",
        })
    except Exception as e:
        return fail(f"元信息失败: {e}", 500)
