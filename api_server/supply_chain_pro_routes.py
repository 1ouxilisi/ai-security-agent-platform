# -*- coding: utf-8 -*-
"""
supply_chain_pro_routes.py — 方向2 供应链安全 Pro REST API（40+ 端点）。

路由前缀: /api/v1/supply-chain-pro
WebSocket: /api/v1/supply-chain-pro/ws/{task_id}
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/supply-chain-pro",
                   tags=["供应链安全Pro-方向2"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from supply_chain_pro import (
        get_orchestrator, get_dashboard,
        get_sbom_phase, get_component_analysis_phase,
        get_license_phase, get_dependency_phase,
        get_risk_phase, get_remediation_phase,
        get_ai_analysis, get_report_generator,
        STAGES, REPORTS_DIR,
    )
    from supply_chain_pro.realtime_push import ws_chain, snapshot, \
        LEVEL_COLORS
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _MOD_AVAILABLE = True
    logger.info("supply_chain_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("supply_chain_pro_routes: load failed: %s", e)
    _ORCH = None  # type: ignore
    _DASH = None  # type: ignore


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": message}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE or _ORCH is None:
        return fail("供应链安全 Pro 模块未加载", 503)
    return None


# =========================================================================== #
# WebSocket
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_supply_chain(websocket: WebSocket, task_id: str):
    """实时推送扫描进度/日志/思考/依赖树事件。"""
    await ws_chain(websocket, task_id)


# =========================================================================== #
# 1. 任务管理
# =========================================================================== #
@router.post("/start")
def start_scan(target: str = Body(..., embed=True,
                                  description="项目目录路径或镜像名"),
               out_format: str = Body(default="cyclonedx"),
               use_osv: bool = Body(default=True),
               use_snyk: bool = Body(default=False)):
    """启动六阶段供应链安全扫描（后台线程）。"""
    g = _guard()
    if g:
        return g
    t = _ORCH.create_task(target)
    threading.Thread(
        target=_ORCH.run_full,
        args=(target, t.task_id),
        kwargs={"out_format": out_format,
                "use_osv": use_osv, "use_snyk": use_snyk},
        daemon=True).start()
    return ok({"task_id": t.task_id, "target": target,
               "status": t.status, "stage": t.stage,
               "progress": t.progress})


@router.get("/tasks")
def list_tasks():
    g = _guard()
    if g:
        return g
    return ok({"tasks": _ORCH.list_tasks()})


@router.get("/task/{task_id}")
def task_detail(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.to_dict())


@router.get("/task/{task_id}/status")
def task_status(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok({"task_id": task_id, "status": t.status,
               "stage": t.stage, "progress": t.progress,
               "log": t.log[-30:]})


@router.get("/task/{task_id}/results")
def task_results(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.to_dict())


@router.delete("/task/{task_id}")
def cancel_task(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    t.status = "cancelled"
    t.log.append("[!] 任务被用户取消")
    return ok({"task_id": task_id, "status": "cancelled"})


@router.get("/task/{task_id}/events")
def task_events(task_id: str):
    g = _guard()
    if g:
        return g
    return ok(snapshot(task_id))


# =========================================================================== #
# 2. 阶段1 SBOM
# =========================================================================== #
@router.post("/sbom/generate")
def sbom_generate(target: str = Body(..., embed=True),
                  out_format: str = Body(default="cyclonedx"),
                  engine: str = Body(default="auto")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.step_sbom(target, out_format=out_format))
    except Exception as e:  # noqa: BLE001
        return fail(f"SBOM 生成失败: {e}")


@router.get("/sbom/tools")
def sbom_tools():
    g = _guard()
    if g:
        return g
    return ok(get_sbom_phase().tools_status())


@router.get("/sbom/{task_id}")
def sbom_of_task(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.sbom)


# =========================================================================== #
# 3. 阶段2 组件分析
# =========================================================================== #
@router.post("/component/analyze")
def component_analyze(components: List[Dict[str, Any]] = Body(...),
                      use_osv: bool = Body(default=True),
                      use_snyk: bool = Body(default=False)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.analysis.analyze(
            components, use_osv=use_osv, use_snyk=use_snyk).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"组件分析失败: {e}")


@router.get("/component/tools")
def component_tools():
    g = _guard()
    if g:
        return g
    return ok(get_component_analysis_phase().tools_status())


@router.get("/component/{task_id}")
def component_of_task(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.component_analysis)


# =========================================================================== #
# 4. 阶段3 许可证合规
# =========================================================================== #
@router.post("/license/check")
def license_check(components: List[Dict[str, Any]] = Body(...),
                  project_license: str = Body(default="Proprietary")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.license_.check(
            components, project_license=project_license).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"许可证检查失败: {e}")


@router.get("/license/matrix")
def license_matrix():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.license_.matrix())


@router.get("/license/{task_id}")
def license_of_task(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.license_report)


# =========================================================================== #
# 5. 阶段4 依赖分析
# =========================================================================== #
@router.post("/dependency/analyze")
def dependency_analyze(components: List[Dict[str, Any]] = Body(...),
                       vulns: Optional[List[Dict[str, Any]]] = Body(
                           default=None)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.dep.analyze(
            components, vulns=vulns or []).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"依赖分析失败: {e}")


@router.get("/dependency/tools")
def dependency_tools():
    g = _guard()
    if g:
        return g
    return ok(get_dependency_phase().tools_status())


@router.get("/dependency/{task_id}")
def dependency_of_task(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.dep_report)


# =========================================================================== #
# 6. 阶段5 风险评级
# =========================================================================== #
@router.post("/risk/rate")
def risk_rate(sbom: Dict[str, Any] = Body(...),
              analysis: Dict[str, Any] = Body(...),
              license_: Dict[str, Any] = Body(default_factory=dict,
                                              alias="license"),
              dep: Dict[str, Any] = Body(default_factory=dict)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.risk.rate(
            sbom.get("components", []),
            analysis.get("vulns", []),
            license_report=license_,
            dep_report=dep).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"风险评级失败: {e}")


@router.get("/risk/tools")
def risk_tools():
    g = _guard()
    if g:
        return g
    return ok(get_risk_phase().tools_status())


@router.get("/risk/{task_id}")
def risk_of_task(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.risk_report)


# =========================================================================== #
# 7. 阶段6 整改建议
# =========================================================================== #
@router.post("/remediation/generate")
def remediation_generate(analysis: Dict[str, Any] = Body(...),
                         license_: Dict[str, Any] = Body(
                             default_factory=dict, alias="license"),
                         dep: Dict[str, Any] = Body(default_factory=dict)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.remediation.generate(
            analysis.get("vulns", []),
            license_issues=license_.get("issues", []),
            dep_report=dep).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"整改建议生成失败: {e}")


@router.get("/remediation/tools")
def remediation_tools():
    g = _guard()
    if g:
        return g
    return ok(get_remediation_phase().tools_status())


@router.get("/remediation/{task_id}")
def remediation_of_task(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.remediation)


# =========================================================================== #
# 8. AI 分析
# =========================================================================== #
@router.post("/ai/analyze")
def ai_analyze(payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        out = _ORCH.ai.analyze(
            sbom=payload.get("sbom", {}),
            component_analysis=payload.get("component_analysis", {}),
            license_report=payload.get("license_report", {}),
            dep_report=payload.get("dep_report", {}),
            risk_report=payload.get("risk_report", {}),
            remediation=payload.get("remediation", {}),
        )
        return ok(out.to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"AI 分析失败: {e}")


@router.get("/ai/{task_id}")
def ai_of_task(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.ai)


# =========================================================================== #
# 9. 报告
# =========================================================================== #
@router.get("/report/{task_id}")
def get_report(task_id: str, fmt: str = Query(default="html")):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    if fmt == "md":
        return ok({"markdown": t.report_markdown,
                   "path": t.report_path})
    return ok({"html": t.report_html, "path": t.report_path})


@router.post("/report/{task_id}/regen")
def regen_report(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    from supply_chain_pro.report_generator import ReportData
    rd = ReportData(
        task_id=t.task_id, target=t.target,
        started_at=t.created_at,
        finished_at=t.finished_at or "",
        sbom=t.sbom, component_analysis=t.component_analysis,
        license_report=t.license_report, dep_report=t.dep_report,
        risk_report=t.risk_report, remediation=t.remediation,
        ai=t.ai)
    import os
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = _ORCH.report.save(rd, REPORTS_DIR, "html")
    t.report_path = path
    return ok({"path": path,
               "markdown": _ORCH.report.generate_markdown(rd),
               "html": _ORCH.report.generate_html(rd)})


# =========================================================================== #
# 10. 仪表盘
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    g = _guard()
    if g:
        return g
    return ok(_DASH.overview())


@router.get("/dashboard/recent")
def dash_recent(limit: int = Query(default=10)):
    g = _guard()
    if g:
        return g
    return ok({"tasks": _DASH.recent_tasks(limit)})


@router.get("/dashboard/stages")
def dash_stages():
    g = _guard()
    if g:
        return g
    return ok({"stages": [{"key": k, "label": n, "progress": p}
                          for k, n, p in STAGES]})


@router.get("/dashboard/tools")
def dash_tools():
    g = _guard()
    if g:
        return g
    return ok(_DASH.tools_status())


# =========================================================================== #
# 11. 单步快速触发
# =========================================================================== #
@router.post("/step/sbom")
def step_sbom(target: str = Body(...),
              out_format: str = Body(default="cyclonedx")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.step_sbom(target, out_format=out_format))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/step/analysis")
def step_analysis(components: List[Dict[str, Any]] = Body(...),
                  use_osv: bool = Body(default=True)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.step_analysis(components, use_osv=use_osv))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/step/license")
def step_license(components: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.step_license(components))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/step/dependency")
def step_dependency(components: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.step_dependency(components))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/step/risk")
def step_risk(sbom: Dict[str, Any] = Body(...),
              analysis: Dict[str, Any] = Body(...),
              license_: Dict[str, Any] = Body(default_factory=dict,
                                              alias="license"),
              dep: Dict[str, Any] = Body(default_factory=dict)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.step_risk(sbom, analysis, license_, dep))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/step/remediation")
def step_remediation(analysis: Dict[str, Any] = Body(...),
                     license_: Dict[str, Any] = Body(
                         default_factory=dict, alias="license"),
                     dep: Dict[str, Any] = Body(default_factory=dict)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.step_remediation(analysis, license_, dep))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 12. 健康检查
# =========================================================================== #
@router.get("/health")
def health():
    return ok({"module": "supply_chain_pro",
               "available": _MOD_AVAILABLE,
               "stages": [k for k, _, _ in STAGES]})
