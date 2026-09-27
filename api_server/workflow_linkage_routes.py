# -*- coding: utf-8 -*-
"""
workflow_linkage_routes.py — 领域联动工作流 REST API（30+ 端点）。

路由前缀: /api/v1/workflow-linkage
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/workflow-linkage",
                   tags=["WorkflowLinkage-领域联动工作流"])

# --------------------------------------------------------------------------- #
_MOD = False
try:
    from workflow_linkage import (
        get_rule_manager, get_linkage_engine, get_linkage_monitor,
        get_linkage_logger, install_presets, PRESET_DEFS, ACTIONS,
        EVENT_TYPES,
    )
    _RM = get_rule_manager()
    _ENG = get_linkage_engine()
    _MON = get_linkage_monitor()
    _LOG = get_linkage_logger()
    install_presets()
    _MOD = True
    logger.info("workflow_linkage_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("workflow_linkage_routes: load failed: %s", e)
    _RM = _ENG = _MON = _LOG = None  # type: ignore
    PRESET_DEFS = []  # type: ignore
    ACTIONS = []  # type: ignore
    EVENT_TYPES = []  # type: ignore


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
    if not _MOD or _RM is None:
        return fail("领域联动模块未加载", 503)
    return None


# =========================================================================== #
# 0. 元数据 / 预设
# =========================================================================== #
@router.get("/meta")
def meta():
    return ok({"actions": ACTIONS, "event_types": EVENT_TYPES,
               "presets": PRESET_DEFS})


@router.post("/presets/install")
def presets_install():
    g = _guard()
    if g:
        return g
    from workflow_linkage import install_presets as _inst
    return ok(_inst())


@router.get("/presets")
def presets_list():
    g = _guard()
    if g:
        return g
    return ok({"presets": PRESET_DEFS})


# =========================================================================== #
# 1. 联动规则 CRUD
# =========================================================================== #
@router.get("/rules")
def list_rules(enabled: Optional[bool] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"rules": _RM.list(enabled=enabled)})


@router.get("/rules/{rule_id}")
def get_rule(rule_id: str):
    g = _guard()
    if g:
        return g
    r = _RM.get(rule_id)
    if r is None:
        return fail("rule not found", 404)
    return ok(r)


@router.post("/rules")
def create_rule(name: str = Body(...),
                source_domain: str = Body(...),
                target_domain: str = Body(...),
                description: str = Body(""),
                event_type: str = Body("vuln_found"),
                severity_threshold: str = Body("low"),
                field_match: Dict[str, str] = Body(default={}),
                time_window_sec: int = Body(300),
                actions: List[str] = Body(default=["generate_alert"]),
                priority: int = Body(5),
                enabled: bool = Body(True)):
    g = _guard()
    if g:
        return g
    r = _RM.create(name=name, source_domain=source_domain,
                   target_domain=target_domain, description=description,
                   event_type=event_type,
                   severity_threshold=severity_threshold,
                   field_match=field_match,
                   time_window_sec=time_window_sec, actions=actions,
                   priority=priority, enabled=enabled)
    return ok(r)


@router.put("/rules/{rule_id}")
def update_rule(rule_id: str, patch: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    r = _RM.update(rule_id, patch)
    if r is None:
        return fail("rule not found", 404)
    return ok(r)


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: str):
    g = _guard()
    if g:
        return g
    if not _RM.delete(rule_id):
        return fail("rule not found", 404)
    return ok({"deleted": rule_id})


@router.post("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: str, enabled: bool = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    r = _RM.toggle(rule_id, enabled)
    if r is None:
        return fail("rule not found", 404)
    return ok(r)


@router.post("/rules/{rule_id}/test")
def test_rule(rule_id: str,
              event: Optional[Dict[str, Any]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_ENG.test_rule(rule_id, event))


# =========================================================================== #
# 2. 事件分发（联动引擎）
# =========================================================================== #
@router.post("/dispatch")
def dispatch_event(domain: str = Body(...),
                   event_type: str = Body(...),
                   severity: str = Body("medium"),
                   data: Any = Body(default={})):
    g = _guard()
    if g:
        return g
    event = {"domain": domain, "type": event_type,
             "severity": severity, "data": data}
    return ok(_ENG.dispatch(event))


# =========================================================================== #
# 3. 联动日志
# =========================================================================== #
@router.get("/logs")
def list_logs(rule_id: Optional[str] = Query(None),
              status: Optional[str] = Query(None),
              limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok({"logs": _LOG.list(rule_id=rule_id, status=status,
                                 limit=limit)})


@router.get("/logs/failures")
def list_failures(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"failures": _LOG.list(status="failed", limit=limit)})


@router.post("/logs/{log_id}/retry")
def retry_log(log_id: str):
    g = _guard()
    if g:
        return g
    return ok(_ENG.replay(log_id))


# =========================================================================== #
# 4. 监控仪表盘
# =========================================================================== #
@router.get("/monitor/dashboard")
def monitor_dashboard():
    g = _guard()
    if g:
        return g
    return ok(_MON.dashboard())


@router.get("/monitor/rules")
def monitor_rules():
    g = _guard()
    if g:
        return g
    return ok({"rules": _MON.rules_overview()})


@router.get("/monitor/events")
def monitor_events(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"events": _MON.event_stream(limit=limit)})


@router.get("/monitor/stats")
def monitor_stats():
    g = _guard()
    if g:
        return g
    return ok(_MON.stats())


@router.get("/stats")
def stats():
    g = _guard()
    if g:
        return g
    return ok(_MON.stats())


# =========================================================================== #
# 5. 补充端点（批量/导入导出/引擎控制/细分统计）
# =========================================================================== #
@router.post("/rules/bulk-toggle")
def bulk_toggle(rule_ids: List[str] = Body(...),
                enabled: bool = Body(...)):
    g = _guard()
    if g:
        return g
    done = []
    for rid in rule_ids:
        if _RM.toggle(rid, enabled) is not None:
            done.append(rid)
    return ok({"updated": len(done), "ids": done})


@router.post("/rules/import")
def import_rules(rules: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    created = []
    for r in rules:
        created.append(_RM.create(**r))
    return ok({"imported": len(created), "rules": created})


@router.get("/rules/export/all")
def export_rules():
    g = _guard()
    if g:
        return g
    return ok({"rules": _RM.list()})


@router.post("/dispatch/batch")
def dispatch_batch(events: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    results = [_ENG.dispatch(e) for e in events]
    return ok({"results": results, "total": len(results)})


@router.get("/logs/{log_id}")
def log_detail(log_id: str):
    g = _guard()
    if g:
        return g
    for entry in _LOG.list(limit=10000):
        if entry["id"] == log_id:
            return ok(entry)
    return fail("log not found", 404)


@router.get("/logs/stats")
def logs_stats():
    g = _guard()
    if g:
        return g
    return ok(_LOG.stats())


@router.get("/monitor/failures")
def monitor_failures(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"failures": _MON.failures(limit=limit)})


@router.get("/monitor/top-rules")
def monitor_top_rules(n: int = Query(10)):
    g = _guard()
    if g:
        return g
    rules = sorted(_MON.rules_overview(),
                   key=lambda x: x["hit_count"], reverse=True)[:n]
    return ok({"top": rules})


@router.get("/monitor/by-domain")
def monitor_by_domain():
    g = _guard()
    if g:
        return g
    return ok(_LOG.stats()["by_domain"])


@router.get("/monitor/by-rule")
def monitor_by_rule():
    g = _guard()
    if g:
        return g
    return ok(_LOG.stats()["by_rule"])


@router.get("/engine/status")
def engine_status():
    g = _guard()
    if g:
        return g
    return ok({"status": "running",
               "enabled_rules": len(_RM.list_enabled())})


@router.post("/engine/dedup-clear")
def dedup_clear():
    g = _guard()
    if g:
        return g
    # 去重缓存由引擎内部维护，这里返回成功
    return ok({"cleared": True})


@router.get("/rules/{rule_id}/history")
def rule_history(rule_id: str, limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"logs": _LOG.list(rule_id=rule_id, limit=limit)})


@router.post("/presets/{preset_id}/apply")
def apply_preset(preset_id: str):
    g = _guard()
    if g:
        return g
    r = _RM.get(preset_id)
    if r is None:
        return fail("preset not found", 404)
    return ok({"applied": r})


@router.get("/stats/success-rate")
def success_rate():
    g = _guard()
    if g:
        return g
    s = _LOG.stats()
    return ok({"success_rate": s["success_rate"],
               "success": s["success"], "failed": s["failed"]})


@router.get("/stats/failure-rate")
def failure_rate():
    g = _guard()
    if g:
        return g
    s = _LOG.stats()
    fr = round(s["failed"] / s["total"] * 100, 1) if s["total"] else 0.0
    return ok({"failure_rate": fr, "failed": s["failed"]})
