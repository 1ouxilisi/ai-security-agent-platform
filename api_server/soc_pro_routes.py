# -*- coding: utf-8 -*-
"""
soc_pro_routes.py — 方向1 SOC Pro REST API（50+ 端点 + WebSocket）。

路由前缀: /api/v1/soc-pro
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/soc-pro",
                   tags=["SOCPro-方向1"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from soc_pro import (
        get_orchestrator, get_dashboard, get_realtime_push,
        get_log_collection_phase, get_log_parsing_phase,
        get_correlation_phase, get_alert_generation_phase,
        get_incident_response_phase, get_threat_hunting_phase,
        get_postmortem_phase, get_ai_analysis,
        get_report_generator, STAGES, REPORTS_DIR, DETECTION_RULES,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _RT = get_realtime_push()
    _COL = get_log_collection_phase()
    _PARSE = get_log_parsing_phase()
    _COR = get_correlation_phase()
    _ALERT = get_alert_generation_phase()
    _IR = get_incident_response_phase()
    _HUNT = get_threat_hunting_phase()
    _PM = get_postmortem_phase()
    _AI = get_ai_analysis()
    _REP = get_report_generator()
    _MOD_AVAILABLE = True
    logger.info("soc_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("soc_pro_routes: load failed: %s", e)
    _ORCH = _DASH = _RT = None  # type: ignore
    _COL = _PARSE = _COR = _ALERT = None  # type: ignore
    _IR = _HUNT = _PM = _AI = _REP = None  # type: ignore


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
        return fail("SOC Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 任务管理（七阶段一键全流程）
# =========================================================================== #
@router.post("/start")
def start_soc(name: str = Body("SOC 全流程巡检", embed=True)):
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


@router.get("/stages")
def stages():
    g = _guard()
    if g:
        return g
    return ok({"stages": [{"key": k, "label": n, "progress": p}
                          for k, n, p in STAGES]})


# =========================================================================== #
# 1. 阶段1 日志收集
# =========================================================================== #
@router.get("/collection/status")
def coll_status():
    g = _guard()
    if g:
        return g
    return ok(_COL.status())


@router.get("/collection/sources")
def coll_list_sources():
    g = _guard()
    if g:
        return g
    return ok({"sources": _COL.list_sources()})


@router.post("/collection/sources")
def coll_add_source(name: str = Body(...),
                    source_type: str = Body("system"),
                    protocol: str = Body("file"),
                    path: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_COL.add_source(name, source_type, protocol, path))


@router.delete("/collection/sources/{source_id}")
def coll_del_source(source_id: str):
    g = _guard()
    if g:
        return g
    return ok({"deleted": _COL.remove_source(source_id)})


@router.put("/collection/sources/{source_id}")
def coll_upd_source(source_id: str,
                    payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    r = _COL.update_source(source_id, **payload)
    if r is None:
        return fail("source not found", 404)
    return ok(r)


@router.post("/collection/start")
def coll_start(source_id: Optional[str] = Body(None, embed=True),
               count: int = Body(200, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_COL.start_collect(source_id, count))


@router.get("/collection/logs")
def coll_logs(limit: int = Query(100),
              source_id: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"logs": _COL.recent_logs(limit, source_id)})


@router.get("/collection/tools")
def coll_tools():
    g = _guard()
    if g:
        return g
    return ok(_COL.tool_status())


# =========================================================================== #
# 2. 阶段2 日志解析
# =========================================================================== #
@router.get("/parsing/rules")
def parse_rules():
    g = _guard()
    if g:
        return g
    return ok({"rules": _PARSE.list_rules()})


@router.post("/parsing/rules")
def parse_add_rule(name: str = Body(...),
                   pattern_type: str = Body("regex"),
                   pattern: str = Body(...),
                   fields: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_PARSE.add_rule(name, pattern_type, pattern, fields))


@router.post("/parsing/rules/{rule_id}/toggle")
def parse_toggle_rule(rule_id: str,
                      enabled: bool = Body(True, embed=True)):
    g = _guard()
    if g:
        return g
    return ok({"ok": _PARSE.toggle_rule(rule_id, enabled)})


@router.delete("/parsing/rules/{rule_id}")
def parse_del_rule(rule_id: str):
    g = _guard()
    if g:
        return g
    return ok({"deleted": _PARSE.remove_rule(rule_id)})


@router.post("/parsing/run")
def parse_run(limit: int = Body(500, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_PARSE.parse_batch(limit=limit))


@router.get("/parsing/recent")
def parse_recent(limit: int = Query(100)):
    g = _guard()
    if g:
        return g
    return ok({"parsed": _PARSE.recent_parsed(limit)})


@router.get("/parsing/quality")
def parse_quality():
    g = _guard()
    if g:
        return g
    return ok(_PARSE.quality_stats())


# =========================================================================== #
# 3. 阶段3 关联分析（50+ 规则）
# =========================================================================== #
@router.get("/correlation/rules")
def corr_rules(category: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"rules": _COR.list_rules(category),
               "total": len(DETECTION_RULES)})


@router.post("/correlation/rules")
def corr_add_rule(name: str = Body(...), category: str = Body("custom"),
                  severity: str = Body("medium"),
                  condition: str = Body(""),
                  threshold: int = Body(1),
                  mitre: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_COR.add_rule(name, category, severity, condition,
                            threshold, mitre))


@router.post("/correlation/rules/{rule_id}/toggle")
def corr_toggle(rule_id: str,
                enabled: bool = Body(True, embed=True)):
    g = _guard()
    if g:
        return g
    return ok({"ok": _COR.toggle_rule(rule_id, enabled)})


@router.put("/correlation/rules/{rule_id}/threshold")
def corr_threshold(rule_id: str,
                   threshold: int = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok({"ok": _COR.update_threshold(rule_id, threshold)})


@router.post("/correlation/run")
def corr_run():
    g = _guard()
    if g:
        return g
    return ok(_COR.correlate())


@router.get("/correlation/hits")
def corr_hits(limit: int = Query(100)):
    g = _guard()
    if g:
        return g
    return ok({"hits": _COR.recent_hits(limit)})


@router.get("/correlation/top-rules")
def corr_top(n: int = Query(10)):
    g = _guard()
    if g:
        return g
    return ok({"top": _COR.rule_hit_top(n)})


@router.get("/correlation/stats")
def corr_stats():
    g = _guard()
    if g:
        return g
    return ok(_COR.stats())


# =========================================================================== #
# 4. 阶段4 告警生成
# =========================================================================== #
@router.post("/alerts/generate")
def alerts_generate():
    g = _guard()
    if g:
        return g
    return ok(_ALERT.generate_from_hits())


@router.get("/alerts")
def alerts_list(status: Optional[str] = Query(None),
                severity: Optional[str] = Query(None),
                limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok({"alerts": _ALERT.list_alerts(status, severity, limit)})


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: str):
    g = _guard()
    if g:
        return g
    a = _ALERT.get_alert(alert_id)
    if a is None:
        return fail("alert not found", 404)
    return ok(a)


@router.post("/alerts/{alert_id}/status")
def alert_status(alert_id: str,
                 status: str = Body(...),
                 note: str = Body("")):
    g = _guard()
    if g:
        return g
    r = _ALERT.update_status(alert_id, status, note)
    if r is None:
        return fail("invalid status or alert not found")
    return ok(r)


@router.post("/alerts/{alert_id}/assign")
def alert_assign(alert_id: str,
                 assignee: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    r = _ALERT.assign(alert_id, assignee)
    if r is None:
        return fail("alert not found", 404)
    return ok(r)


@router.post("/alerts/{alert_id}/notify")
def alert_notify(alert_id: str,
                 channels: List[str] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_ALERT.notify(alert_id, channels))


@router.get("/alerts/aggregate/summary")
def alert_aggregate():
    g = _guard()
    if g:
        return g
    return ok(_ALERT.aggregate())


@router.get("/notifications/log")
def notif_log():
    g = _guard()
    if g:
        return g
    return ok({"log": _ALERT.notification_log()})


# =========================================================================== #
# 5. 阶段5 事件响应（SOAR）
# =========================================================================== #
@router.get("/soar/playbooks")
def soar_list():
    g = _guard()
    if g:
        return g
    return ok({"playbooks": _IR.list_playbooks()})


@router.post("/soar/playbooks")
def soar_create(name: str = Body(...),
                description: str = Body(""),
                severity: str = Body("medium"),
                steps: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_IR.create_playbook(name, description, severity, steps))


@router.post("/soar/playbooks/{pb_id}/run")
def soar_run(pb_id: str,
             context: Dict[str, Any] = Body(default={})):
    g = _guard()
    if g:
        return g
    return ok(_IR.execute_playbook(pb_id, context))


@router.get("/soar/tools")
def soar_tools():
    g = _guard()
    if g:
        return g
    return ok(_IR.tool_status())


@router.post("/tickets")
def ticket_create(title: str = Body(...),
                  alert_id: str = Body(""),
                  priority: str = Body("medium"),
                  assignee: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_IR.create_ticket(title, alert_id, priority, assignee))


@router.get("/tickets")
def ticket_list(status: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"tickets": _IR.list_tickets(status)})


@router.post("/tickets/{ticket_id}/update")
def ticket_update(ticket_id: str,
                   status: str = Body(""),
                   note: str = Body(""),
                   assignee: str = Body("")):
    g = _guard()
    if g:
        return g
    r = _IR.update_ticket(ticket_id, status, note, assignee)
    if r is None:
        return fail("ticket not found", 404)
    return ok(r)


@router.get("/tickets/evidence")
def ticket_evidence():
    g = _guard()
    if g:
        return g
    return ok({"evidence": _IR.evidence_list()})


@router.get("/ir/stats")
def ir_stats():
    g = _guard()
    if g:
        return g
    return ok(_IR.stats())


# =========================================================================== #
# 6. 阶段6 威胁狩猎
# =========================================================================== #
@router.get("/hunting/queries")
def hunt_queries():
    g = _guard()
    if g:
        return g
    return ok({"queries": _HUNT.list_queries()})


@router.post("/hunting/run")
def hunt_run(qid: Optional[str] = Body(None),
             custom_query: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_HUNT.run_query(qid, custom_query))


@router.post("/hunting/ioc")
def hunt_ioc(ioc_type: str = Body(...),
             value: str = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_HUNT.ioc_match(ioc_type, value))


@router.get("/hunting/ioc-library")
def hunt_ioc_lib():
    g = _guard()
    if g:
        return g
    return ok(_HUNT.ioc_library())


@router.get("/hunting/attack-chain")
def hunt_chain():
    g = _guard()
    if g:
        return g
    return ok(_HUNT.attack_chain())


@router.get("/hunting/anomaly")
def hunt_anomaly():
    g = _guard()
    if g:
        return g
    return ok(_HUNT.anomaly_detect())


@router.get("/hunting/finds")
def hunt_finds(status: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"finds": _HUNT.list_finds(status)})


@router.post("/hunting/finds/{fid}/triage")
def hunt_triage(fid: str, status: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok({"ok": _HUNT.triage(fid, status)})


@router.get("/hunting/report")
def hunt_report():
    g = _guard()
    if g:
        return g
    return ok(_HUNT.hunting_report())


# =========================================================================== #
# 7. 阶段7 事件复盘
# =========================================================================== #
@router.post("/postmortem/generate")
def pm_generate(title: str = Body(...),
                incident: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_PM.generate(title, incident))


@router.get("/postmortem/list")
def pm_list():
    g = _guard()
    if g:
        return g
    return ok({"reports": _PM.list_reports()})


@router.get("/postmortem/{pm_id}")
def pm_detail(pm_id: str):
    g = _guard()
    if g:
        return g
    r = _PM.get_report(pm_id)
    if r is None:
        return fail("report not found", 404)
    return ok(r)


@router.post("/postmortem/{pm_id}/close")
def pm_close(pm_id: str):
    g = _guard()
    if g:
        return g
    return ok({"ok": _PM.close_report(pm_id)})


@router.post("/postmortem/kb")
def pm_kb_add(title: str = Body(...), content: str = Body(""),
              tags: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    return ok(_PM.add_kb(title, content, tags))


@router.get("/postmortem/kb")
def pm_kb_list(tag: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"kb": _PM.list_kb(tag)})


@router.get("/postmortem/improvements")
def pm_imp():
    g = _guard()
    if g:
        return g
    return ok({"improvements": _PM.improvement_track()})


# =========================================================================== #
# 8. AI 分析
# =========================================================================== #
@router.post("/ai/analert/{alert_id}")
def ai_analert(alert_id: str):
    g = _guard()
    if g:
        return g
    a = _ALERT.get_alert(alert_id)
    if a is None:
        return fail("alert not found", 404)
    return ok(_AI.analyze_alert(a))


@router.post("/ai/batch")
def ai_batch(limit: int = Body(20, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_AI.batch_analyze(_ALERT.list_alerts(limit=limit)))


@router.post("/ai/root-cause")
def ai_root_cause(incident: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_AI.root_cause_aux(incident))


@router.get("/ai/history")
def ai_history(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"history": _AI.history(limit)})


# =========================================================================== #
# 9. SOC 大屏仪表盘
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
def dash_trend(window: str = Query("24h")):
    g = _guard()
    if g:
        return g
    return ok(_DASH.alert_trend(window))


@router.get("/dashboard/map")
def dash_map():
    g = _guard()
    if g:
        return g
    return ok({"map": _DASH.attack_map()})


@router.get("/dashboard/top-types")
def dash_top():
    g = _guard()
    if g:
        return g
    return ok({"top": _DASH.top_attack_types()})


@router.get("/dashboard/recent-alerts")
def dash_recent(limit: int = Query(20)):
    g = _guard()
    if g:
        return g
    return ok({"alerts": _DASH.recent_alerts(limit)})


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
    import os
    if not os.path.isdir(REPORTS_DIR):
        return ok({"files": []})
    files = sorted(os.listdir(REPORTS_DIR), reverse=True)
    return ok({"dir": REPORTS_DIR, "files": files[:20]})


# =========================================================================== #
# 11. WebSocket 实时推送
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_endpoint(websocket: WebSocket, task_id: str):
    """实时推送进度/日志/思考/告警/结果。"""
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
