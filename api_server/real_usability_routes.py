# -*- coding: utf-8 -*-
"""real_usability_routes.py — 真实可用性大升级 REST API（25+ 端点）。

路由前缀: /api/v1/real-usability
统一响应: {"success": bool, "data": ..., "error": ...}
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/real-usability",
                   tags=["真实可用性大升级"])

# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from real_usability import (
        FPRealTester, FalsePositiveOptimizer, FP_RULES, TARGET_RANGES,
        E2ERunner, E2E_STAGES,
        RangeManager, KNOWN_RANGES,
        QualityChecker, QUALITY_RUBRIC,
        UsabilityDashboard, USABILITY_SCORE_BASELINE,
    )
    _DASH = UsabilityDashboard()
    _MOD_AVAILABLE = True
    logger.info("real_usability_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("real_usability_routes: load failed: %s", e)
    _DASH = None  # type: ignore
    FP_RULES: List[Dict[str, Any]] = []  # type: ignore
    TARGET_RANGES: List[Dict[str, Any]] = []  # type: ignore
    E2E_STAGES: List[Dict[str, Any]] = []  # type: ignore
    KNOWN_RANGES: List[Dict[str, Any]] = []  # type: ignore
    QUALITY_RUBRIC: List[Dict[str, Any]] = []  # type: ignore
    USABILITY_SCORE_BASELINE: Dict[str, Any] = {}  # type: ignore


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def fail(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": msg},
                        status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE or _DASH is None:
        return fail("真实可用性模块未加载", 503)
    return None


# --------------------------------------------------------------------------- #
# 1. 总览 / 评分（3 端点）
# --------------------------------------------------------------------------- #
@router.get("/overview")
def overview():
    """可用性总览（7.5 → 9.5）。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.overview())


@router.get("/score")
def score():
    """可用性评分。"""
    g = _guard()
    if g:
        return g
    return ok(USABILITY_SCORE_BASELINE)


@router.get("/rubric")
def rubric():
    """输出质量评分细则。"""
    g = _guard()
    if g:
        return g
    return ok(QUALITY_RUBRIC)


# --------------------------------------------------------------------------- #
# 2. 误报率优化（7 端点）
# --------------------------------------------------------------------------- #
@router.get("/fp/rules")
def fp_rules():
    """误报抑制规则。"""
    g = _guard()
    if g:
        return g
    return ok(FP_RULES)


@router.get("/fp/ranges")
def fp_ranges():
    """10 个靶场清单。"""
    g = _guard()
    if g:
        return g
    return ok(TARGET_RANGES)


@router.post("/fp/run/{range_id}")
def fp_run_range(range_id: str):
    """在指定靶场上跑验证。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.fp_tester.run_range(range_id))


@router.get("/fp/run-all")
def fp_run_all():
    """列出全部靶场。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.fp_tester.run_all())


@router.post("/fp/observe")
def fp_observe(
    vuln_type: str = Body(...),
    evidence: str = Body(...),
    range_id: str = Body(...),
):
    """记录一个观察到的误报。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.fp_opt.add_observed_fp(vuln_type, evidence, range_id))


@router.post("/fp/rate")
def fp_rate(
    total: int = Body(...),
    fp: int = Body(...),
):
    """计算误报率。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.fp_opt.compute_fp_rate(total, fp))


@router.get("/fp/report")
def fp_report():
    """误报率优化报告。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.fp_report())


# --------------------------------------------------------------------------- #
# 3. 端到端跑通（5 端点）
# --------------------------------------------------------------------------- #
@router.post("/e2e/start")
def e2e_start(
    target: str = Body("http://testphp.vulnweb.com", embed=True),
):
    """启动端到端跑通（默认 testphp.vulnweb.com）。"""
    g = _guard()
    if g:
        return g
    tid = _DASH.run_e2e(target)
    return ok({"task_id": tid, "target": target})


@router.get("/e2e/status/{task_id}")
def e2e_status(task_id: str):
    t = _DASH.get_e2e(task_id)
    if not t:
        return fail("task not found", 404)
    return ok(t)


@router.get("/e2e/stages")
def e2e_stages():
    """E2E 阶段定义。"""
    g = _guard()
    if g:
        return g
    return ok(E2E_STAGES)


@router.get("/e2e/report/{task_id}")
def e2e_report(task_id: str):
    t = _DASH.get_e2e(task_id)
    if not t:
        return fail("task not found", 404)
    return ok({"report": t.get("report"), "status": t.get("status")})


@router.get("/e2e/list")
def e2e_list():
    """所有 E2E 任务。"""
    g = _guard()
    if g:
        return g
    return ok(list(_DASH.e2e.tasks.values()))


# --------------------------------------------------------------------------- #
# 4. 靶场管理（6 端点）
# --------------------------------------------------------------------------- #
@router.get("/ranges/list")
def ranges_list():
    """靶场列表。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.ranges.list())


@router.get("/ranges/{range_id}")
def ranges_get(range_id: str):
    r = _DASH.ranges.get(range_id)
    if not r:
        return fail("range not found", 404)
    return ok(r)


@router.post("/ranges/add")
def ranges_add(
    range_id: str = Body(...),
    name: str = Body(...),
    url: str = Body(...),
):
    g = _guard()
    if g:
        return g
    return ok(_DASH.ranges.add(range_id, name, url))


@router.get("/ranges/{range_id}/status")
def ranges_status(range_id: str):
    """真实检测靶场是否在线（curl）。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.ranges.status(range_id))


@router.post("/ranges/{range_id}/verify")
def ranges_verify(range_id: str):
    g = _guard()
    if g:
        return g
    return ok(_DASH.ranges.verify(range_id))


@router.get("/ranges/verify-all")
def ranges_verify_all():
    g = _guard()
    if g:
        return g
    return ok(_DASH.ranges.verify_all())


# --------------------------------------------------------------------------- #
# 5. 输出质量检查（5 端点）
# --------------------------------------------------------------------------- #
@router.post("/quality/check")
def quality_check(finding: Dict[str, Any] = Body(...)):
    """检查单条漏洞质量。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.qc.check_finding(finding))


@router.post("/quality/upgrade")
def quality_upgrade(finding: Dict[str, Any] = Body(...)):
    """用模板升级漏洞到客户付费级。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.qc.upgrade(finding))


@router.post("/quality/check-report")
def quality_check_report(findings: List[Dict[str, Any]] = Body(...)):
    """整份报告质量检查。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.qc.check_report(findings))


@router.get("/quality/templates")
def quality_templates():
    """漏洞详情模板。"""
    g = _guard()
    if g:
        return g
    return ok(_DASH.qc.templates)


@router.get("/quality/rubric")
def quality_rubric():
    g = _guard()
    if g:
        return g
    return ok(QUALITY_RUBRIC)
