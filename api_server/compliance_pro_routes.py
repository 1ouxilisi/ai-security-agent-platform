# -*- coding: utf-8 -*-
"""
compliance_pro_routes.py — 方向1 合规审计做深 REST API（50+ 端点 + WebSocket）。

路由前缀: /api/v1/compliance-pro
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/compliance-pro",
                   tags=["CompliancePro-方向1"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from compliance_pro import (
        get_orchestrator, get_dashboard, get_realtime_push,
        get_asset_inventory_phase, get_baseline_check_phase,
        get_compliance_assessment_phase, get_gap_analysis_phase,
        get_remediation_tracking_phase, get_retest_verification_phase,
        get_compliance_report_phase, get_ai_analysis,
        get_report_generator, STAGES, REPORTS_DIR, FRAMEWORKS,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _RT = get_realtime_push()
    _INV = get_asset_inventory_phase()
    _BASE = get_baseline_check_phase()
    _CA = get_compliance_assessment_phase()
    _GAP = get_gap_analysis_phase()
    _RM = get_remediation_tracking_phase()
    _RET = get_retest_verification_phase()
    _REPP = get_compliance_report_phase()
    _AI = get_ai_analysis()
    _REP = get_report_generator()
    _MOD_AVAILABLE = True
    logger.info("compliance_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("compliance_pro_routes: load failed: %s", e)
    _ORCH = _DASH = _RT = None  # type: ignore
    _INV = _BASE = _CA = _GAP = None  # type: ignore
    _RM = _RET = _REPP = _AI = _REP = None  # type: ignore


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c == "\n" or c == "\t"
                       or ord(c) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data),
                         "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE or _ORCH is None:
        return fail("合规审计 Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 任务管理（七阶段一键全流程）
# =========================================================================== #
@router.post("/start")
def start_audit(name: str = Body("合规审计全流程", embed=True)):
    g = _guard()
    if g:
        return g
    t = _ORCH.create_task(name)
    threading.Thread(target=_ORCH.run_full,
                     args=(t.task_id,), daemon=True).start()
    return ok({"task_id": t.task_id, "name": name,
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


@router.get("/stages")
def stages():
    g = _guard()
    if g:
        return g
    return ok({"stages": [{"key": k, "label": n, "progress": p}
                          for k, n, p in STAGES]})


# =========================================================================== #
# 1. 阶段1 资产盘点
# =========================================================================== #
@router.get("/assets")
def asset_list(asset_type: Optional[str] = Query(None),
               criticality: Optional[str] = Query(None),
               business_line: Optional[str] = Query(None),
               keyword: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"assets": _INV.list_assets(asset_type, criticality,
                                          business_line, keyword)})


@router.post("/assets")
def asset_add(name: str = Body(...), ip: str = Body(...),
              asset_type: str = Body("server"), owner: str = Body(""),
              business_line: str = Body("核心业务"),
              criticality: str = Body("medium")):
    g = _guard()
    if g:
        return g
    return ok(_INV.add_asset(name, ip, asset_type, owner=owner,
                             business_line=business_line,
                             criticality=criticality))


@router.get("/assets/{asset_id}")
def asset_detail(asset_id: str):
    g = _guard()
    if g:
        return g
    a = _INV.get_asset(asset_id)
    if a is None:
        return fail("asset not found", 404)
    return ok(a)


@router.put("/assets/{asset_id}")
def asset_update(asset_id: str, payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    r = _INV.update_asset(asset_id, **payload)
    if r is None:
        return fail("asset not found", 404)
    return ok(r)


@router.delete("/assets/{asset_id}")
def asset_delete(asset_id: str):
    g = _guard()
    if g:
        return g
    return ok({"deleted": _INV.delete_asset(asset_id)})


@router.post("/assets/discover")
def asset_discover(cidr: str = Body("10.10.1.0/24", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_INV.discover_subnet(cidr))


@router.get("/assets/classify")
def asset_classify():
    g = _guard()
    if g:
        return g
    return ok(_INV.classify_summary())


@router.get("/assets/value")
def asset_value():
    g = _guard()
    if g:
        return g
    return ok({"ranking": _INV.value_assessment()})


@router.get("/assets/change-monitor")
def asset_change():
    g = _guard()
    if g:
        return g
    return ok(_INV.change_monitor())


@router.get("/assets/export")
def asset_export(fmt: str = Query("json")):
    g = _guard()
    if g:
        return g
    return ok(_INV.export_inventory(fmt))


@router.get("/assets/tools")
def asset_tools():
    g = _guard()
    if g:
        return g
    return ok(_INV.tool_status())


# =========================================================================== #
# 2. 阶段2 基线检查
# =========================================================================== #
@router.get("/baseline/rules")
def base_rules(category: Optional[str] = Query(None),
               target: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"rules": _BASE.list_rules(category, target),
               "total": _BASE.rule_count()})


@router.post("/baseline/rules/{rule_id}/toggle")
def base_toggle(rule_id: str, enabled: bool = Body(True, embed=True)):
    g = _guard()
    if g:
        return g
    return ok({"ok": _BASE.toggle_rule(rule_id, enabled)})


@router.post("/baseline/run")
def base_run(asset_id: str = Body(...),
             target_filter: Optional[str] = Body(None)):
    g = _guard()
    if g:
        return g
    return ok(_BASE.run_check(asset_id, target_filter))


@router.get("/baseline/results")
def base_results(asset_id: Optional[str] = Query(None),
                 status: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"results": _BASE.list_results(asset_id, status)})


@router.get("/baseline/stats")
def base_stats():
    g = _guard()
    if g:
        return g
    return ok(_BASE.stats())


@router.get("/baseline/tools")
def base_tools():
    g = _guard()
    if g:
        return g
    return ok(_BASE.tool_status())


# =========================================================================== #
# 3. 阶段3 合规评估
# =========================================================================== #
@router.get("/compliance/frameworks")
def comp_frameworks():
    g = _guard()
    if g:
        return g
    return ok({"frameworks": FRAMEWORKS})


@router.get("/compliance/items")
def comp_items(framework: Optional[str] = Query(None),
               domain: Optional[str] = Query(None),
               status: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"items": _CA.list_items(framework, domain, status)})


@router.post("/compliance/items/{item_id}/status")
def comp_set_status(item_id: str, status: str = Body(...),
                    note: str = Body("")):
    g = _guard()
    if g:
        return g
    r = _CA.set_status(item_id, status, note)
    if r is None:
        return fail("invalid status or item not found")
    return ok(r)


@router.post("/compliance/assess")
def comp_assess():
    g = _guard()
    if g:
        return g
    return ok(_CA.auto_assess())


@router.get("/compliance/score")
def comp_score():
    g = _guard()
    if g:
        return g
    return ok(_CA.overall_score())


@router.get("/compliance/score/{framework}")
def comp_score_fw(framework: str):
    g = _guard()
    if g:
        return g
    from compliance_pro.compliance_assessment_phase import FRAMEWORKS as FW
    if framework not in FW:
        return fail("framework not found", 404)
    return ok(_CA._framework_score(framework))


# =========================================================================== #
# 4. 阶段4 差距分析
# =========================================================================== #
@router.post("/gap/analyze")
def gap_analyze():
    g = _guard()
    if g:
        return g
    return ok(_GAP.analyze())


@router.get("/gap/list")
def gap_list(severity: Optional[str] = Query(None),
             framework: Optional[str] = Query(None),
             status: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"gaps": _GAP.list_gaps(severity, framework, status)})


@router.get("/gap/{gap_id}")
def gap_detail(gap_id: str):
    g = _guard()
    if g:
        return g
    r = _GAP.get_gap(gap_id)
    if r is None:
        return fail("gap not found", 404)
    return ok(r)


@router.put("/gap/{gap_id}")
def gap_update(gap_id: str, payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    r = _GAP.update_gap(gap_id, **payload)
    if r is None:
        return fail("gap not found", 404)
    return ok(r)


@router.get("/gap/stats")
def gap_stats():
    g = _guard()
    if g:
        return g
    return ok(_GAP.stats())


@router.get("/gap/trend")
def gap_trend():
    g = _guard()
    if g:
        return g
    return ok({"trend": _GAP.trend()})


@router.get("/gap/report")
def gap_report():
    g = _guard()
    if g:
        return g
    return ok(_GAP.gap_report())


# =========================================================================== #
# 5. 阶段5 整改跟踪
# =========================================================================== #
@router.post("/remediation/tasks")
def rm_create(title: str = Body(...), gap_id: str = Body(""),
              assignee: str = Body(""), severity: str = Body("medium"),
              priority: str = Body("medium"),
              due_in_days: int = Body(30)):
    g = _guard()
    if g:
        return g
    return ok(_RM.create_task(title, gap_id, assignee, severity,
                              priority, due_in_days))


@router.get("/remediation/tasks")
def rm_list(status: Optional[str] = Query(None),
            assignee: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"tasks": _RM.list_tasks(status, assignee)})


@router.get("/remediation/tasks/{task_id}")
def rm_detail(task_id: str):
    g = _guard()
    if g:
        return g
    r = _RM.get_task(task_id)
    if r is None:
        return fail("task not found", 404)
    return ok(r)


@router.put("/remediation/tasks/{task_id}")
def rm_update(task_id: str, payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    r = _RM.update_task(task_id, **payload)
    if r is None:
        return fail("task not found", 404)
    return ok(r)


@router.delete("/remediation/tasks/{task_id}")
def rm_delete(task_id: str):
    g = _guard()
    if g:
        return g
    return ok({"deleted": _RM.delete_task(task_id)})


@router.post("/remediation/tasks/{task_id}/evidence")
def rm_evidence(task_id: str, evidence: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok({"ok": _RM.add_evidence(task_id, evidence)})


@router.post("/remediation/tasks/{task_id}/approve")
def rm_approve(task_id: str):
    g = _guard()
    if g:
        return g
    r = _RM.approve(task_id)
    if r is None:
        return fail("task not found", 404)
    return ok(r)


@router.get("/remediation/sla")
def rm_sla():
    g = _guard()
    if g:
        return g
    return ok(_RM.sla_stats())


@router.get("/remediation/report")
def rm_report():
    g = _guard()
    if g:
        return g
    return ok(_RM.progress_report())


# =========================================================================== #
# 6. 阶段6 复测验证
# =========================================================================== #
@router.post("/retest/gap/{gap_id}")
def retest_gap(gap_id: str, task_id: str = Body("", embed=True),
               evidence: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_RET.retest_gap(gap_id, task_id, evidence))


@router.post("/retest/batch")
def retest_batch(gap_ids: List[str] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_RET.retest_batch(gap_ids))


@router.get("/retest/records")
def retest_records(result: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"records": _RET.list_records(result)})


@router.get("/retest/stats")
def retest_stats():
    g = _guard()
    if g:
        return g
    return ok(_RET.stats())


@router.get("/retest/report")
def retest_report():
    g = _guard()
    if g:
        return g
    return ok(_RET.retest_report())


# =========================================================================== #
# 7. 阶段7 合规报告
# =========================================================================== #
@router.get("/report/build")
def report_build():
    g = _guard()
    if g:
        return g
    return ok(_REPP.build())


# =========================================================================== #
# 8. AI 分析
# =========================================================================== #
@router.post("/ai/gap-prioritize")
def ai_prioritize():
    g = _guard()
    if g:
        return g
    return ok(_AI.analyze_gaps())


@router.get("/ai/risk-assessment")
def ai_risk():
    g = _guard()
    if g:
        return g
    return ok(_AI.risk_assessment())


@router.get("/ai/forecast")
def ai_forecast(window: str = Query("30d")):
    g = _guard()
    if g:
        return g
    return ok(_AI.trend_forecast(window))


@router.get("/ai/alerts")
def ai_alerts():
    g = _guard()
    if g:
        return g
    return ok({"alerts": _AI.risk_alert()})


@router.get("/ai/history")
def ai_history(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"history": _AI.history(limit)})


# =========================================================================== #
# 9. 合规大屏仪表盘
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    g = _guard()
    if g:
        return g
    return ok(_DASH.overview())


@router.get("/dashboard/full")
def dash_full():
    g = _guard()
    if g:
        return g
    return ok(_DASH.full_screen())


@router.get("/dashboard/trend")
def dash_trend(window: str = Query("30d")):
    g = _guard()
    if g:
        return g
    return ok(_DASH.compliance_trend(window))


@router.get("/dashboard/gap-dist")
def dash_gapdist():
    g = _guard()
    if g:
        return g
    return ok(_DASH.gap_distribution())


@router.get("/dashboard/frameworks")
def dash_frameworks():
    g = _guard()
    if g:
        return g
    return ok({"frameworks": _DASH.framework_comparison()})


@router.get("/dashboard/top-gaps")
def dash_top(n: int = Query(10)):
    g = _guard()
    if g:
        return g
    return ok({"top": _DASH.top_gaps(n)})


# =========================================================================== #
# 10. 报告生成
# =========================================================================== #
@router.post("/report/generate")
def report_gen(fmt: str = Body("both", embed=True)):
    g = _guard()
    if g:
        return g
    r = _REP.generate(fmt)
    return ok({k: v for k, v in r.items() if k != "html"})


@router.get("/report/latest")
def report_latest():
    g = _guard()
    if g:
        return g
    if not os.path.isdir(REPORTS_DIR):
        return ok({"files": []})
    files = sorted(os.listdir(REPORTS_DIR), reverse=True)
    return ok({"dir": REPORTS_DIR, "files": files[:20]})


# =========================================================================== #
# 11. WebSocket 实时推送
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_endpoint(websocket: WebSocket, task_id: str):
    """实时推送进度/日志/思考/差距/合规状态/结果。"""
    await websocket.accept()
    if not _MOD_AVAILABLE:
        await websocket.send_json({"type": "error",
                                   "message": "模块未加载"})
        await websocket.close()
        return
    _RT.subscribe(task_id, websocket)
    for ev in _RT.history(task_id):
        try:
            await websocket.send_json(ev)
        except Exception:
            break
    try:
        sent_index = len(_RT.history(task_id))
        while True:
            hist = _RT.history(task_id)
            if len(hist) > sent_index:
                for ev in hist[sent_index:]:
                    await websocket.send_json(ev)
                sent_index = len(hist)
            await websocket.send_json({"type": "ping",
                                       "ts": time.time()})
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _RT.unsubscribe(task_id, websocket)
