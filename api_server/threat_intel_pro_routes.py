# -*- coding: utf-8 -*-
"""
threat_intel_pro_routes.py — 方向2 威胁情报 Pro REST API + WebSocket。

路由前缀: /api/v1/threat-intel-pro
WebSocket: /api/v1/threat-intel-pro/ws/{task_id}
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import logging
import threading
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threat-intel-pro",
                   tags=["威胁情报Pro-方向2"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from threat_intel_pro import (
        get_orchestrator, get_dashboard, get_collection_phase,
        get_management_phase, get_matching_phase, get_actor_phase,
        get_attack_surface_phase, get_darkweb_phase, get_analysis_phase,
        get_sharing_phase, get_ai_analyzer, get_report_generator,
        manager, LEVEL_COLORS, STAGES, REPORTS_DIR,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _MOD_AVAILABLE = True
    logger.info("threat_intel_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("threat_intel_pro_routes: load failed: %s", e)
    _ORCH = None  # type: ignore
    _DASH = None  # type: ignore


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": message},
                        status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE or _ORCH is None:
        return fail("威胁情报 Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 0. WebSocket 实时推送
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_intel(websocket: WebSocket, task_id: str):
    conn_id = "conn_" + uuid.uuid4().hex[:8]
    channel = f"intel:{task_id}"
    await manager.connect(websocket, channel, conn_id)
    try:
        await websocket.send_json({
            "type": "connected", "task_id": task_id, "conn_id": conn_id,
            "data": {"msg": "威胁情报实时通道已连接"}})
        snap = manager.snapshot()
        if snap:
            await websocket.send_json({"type": "snapshot",
                                       "task_id": task_id, "data": snap})
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(channel, conn_id)
    except Exception:  # noqa: BLE001
        manager.disconnect(channel, conn_id)


# =========================================================================== #
# 1. 任务管理（一键八阶段）
# =========================================================================== #
@router.post("/start")
def start_intel(target: str = Body("", embed=True,
                                   description="目标域名，可选")):
    """启动八阶段威胁情报任务（后台线程）。"""
    g = _guard()
    if g:
        return g
    t = _ORCH.create_task(target)
    threading.Thread(target=_ORCH.run_full,
                     args=(target, t.task_id), daemon=True).start()
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
               "log": t.log[-40:]})


# =========================================================================== #
# 2. 阶段1：IOC 收集
# =========================================================================== #
@router.get("/collection/sources")
def list_sources():
    g = _guard()
    if g:
        return g
    return ok({"sources": _ORCH.collection.list_sources()})


@router.post("/collection/sources")
def add_source(key: str = Body(...), name: str = Body(...),
               kind: str = Body("api"), api_url: str = Body(""),
               key_env: str = Body(""), enabled: bool = True):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.collection.add_source(key, name, kind, api_url,
                                          key_env, enabled))


@router.delete("/collection/sources/{key}")
def del_source(key: str):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.collection.remove_source(key))


@router.post("/collection/sources/{key}/config")
def config_source(key: str, api_url: Optional[str] = Body(default=None),
                  key_env: Optional[str] = Body(default=None),
                  enabled: Optional[bool] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.collection.configure_source(key, api_url, key_env,
                                                enabled))


@router.post("/collection/sources/{key}/run")
def run_source(key: str):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.collection.collect_source(key))


@router.post("/collection/run-all")
def run_all_sources(use_builtin: bool = Body(True, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.collection.collect_all(use_builtin))


@router.get("/collection/iocs")
def collection_iocs(limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok({"items": _ORCH.collection.list_iocs(limit),
               "total": _ORCH.collection.count()})


@router.post("/collection/manual")
def add_manual(type: str = Body(""), value: str = Body(...),
               tags: List[str] = Body(default_factory=list),
               confidence: int = 60):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.collection.add_manual(type, value, tags,
                                          confidence=confidence))


@router.post("/collection/schedule")
def schedule(interval_minutes: int = Body(60, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.collection.schedule(interval_minutes))


@router.get("/collection/jobs")
def list_jobs():
    g = _guard()
    if g:
        return g
    return ok({"jobs": _ORCH.collection.list_jobs()})


# =========================================================================== #
# 3. 阶段2：IOC 管理
# =========================================================================== #
@router.post("/management/ingest")
def ingest(items: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.management.ingest(items))


@router.get("/management/iocs")
def mgmt_search(keyword: str = Query(""), type: str = Query(""),
                tag: str = Query(""), lifecycle: str = Query(""),
                min_conf: int = Query(0), limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.management.search(keyword, type, tag, lifecycle,
                                      min_conf, limit))


@router.get("/management/ioc/{value}")
def mgmt_get(value: str):
    g = _guard()
    if g:
        return g
    d = _ORCH.management.get(value)
    if d is None:
        return fail("ioc not found", 404)
    return ok(d)


@router.delete("/management/ioc/{value}")
def mgmt_delete(value: str):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.management.delete(value))


@router.post("/management/ioc/{value}/lifecycle")
def mgmt_lifecycle(value: str, state: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.management.set_lifecycle(value, state))


@router.post("/management/expire")
def mgmt_expire(days: int = Body(30, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.management.expire_old(days))


@router.get("/management/stats")
def mgmt_stats():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.management.stats())


@router.get("/management/tags")
def mgmt_tags():
    g = _guard()
    if g:
        return g
    return ok({"tags": _ORCH.management.tag_stats()})


# =========================================================================== #
# 4. 阶段3：IOC 匹配
# =========================================================================== #
@router.post("/matching/logs")
def match_logs(logs: List[str] = Body(...),
               source_name: str = Body("syslog", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.matching.match_logs(logs, source_name))


@router.post("/matching/traffic")
def match_traffic(flows: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.matching.match_traffic(flows))


@router.post("/matching/assets")
def match_assets(assets: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.matching.match_assets(assets))


@router.post("/matching/emails")
def match_emails(emails: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.matching.match_emails(emails))


@router.get("/matching/alerts")
def match_alerts():
    g = _guard()
    if g:
        return g
    return ok({"alerts": _ORCH.matching.list_alerts()})


@router.post("/matching/alerts/{alert_id}/status")
def match_alert_status(alert_id: str,
                       status: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.matching.update_alert(alert_id, status))


@router.get("/matching/hits")
def match_hits(source_kind: str = Query(""), limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok({"hits": _ORCH.matching.list_hits(source_kind, limit)})


@router.get("/matching/stats")
def match_stats():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.matching.stats())


# =========================================================================== #
# 5. 阶段4：威胁 Actor
# =========================================================================== #
@router.get("/actors/list")
def actor_list(country: str = Query(""), capability: str = Query(""),
               motivation: str = Query(""), limit: int = Query(100)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.actors.list_actors(country, capability, motivation,
                                       limit))


@router.get("/actors/{actor_id}")
def actor_get(actor_id: str):
    g = _guard()
    if g:
        return g
    d = _ORCH.actors.get(actor_id)
    if d is None:
        return fail("actor not found", 404)
    return ok(d)


@router.get("/actors/search")
def actor_search(keyword: str = Query(...)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.actors.search(keyword))


@router.get("/actors/{actor_id}/correlate")
def actor_correlate(actor_id: str, min_shared: int = Query(1)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.actors.correlate(actor_id, min_shared))


@router.get("/actors/stats")
def actor_stats():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.actors.stats())


@router.post("/actors/infer")
def actor_infer(malware_names: List[str] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok({"inferred": _ORCH.actors.infer_from_iocs(malware_names)})


# =========================================================================== #
# 6. 阶段5：攻击面
# =========================================================================== #
@router.post("/surface/map")
def surface_map(domain: str = Body(...),
                do_port_scan: bool = Body(False)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_ORCH.surface.map_domain(domain, do_port_scan))
    except Exception as e:  # noqa: BLE001
        return fail(f"测绘失败: {e}")


@router.post("/surface/subdomains")
def surface_subdomains(domain: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok({"subdomains": _ORCH.surface.enum_subdomains(domain)})


@router.post("/surface/portscan")
def surface_portscan(host: str = Body(...),
                     ports: str = Body("21,22,80,443,445,3306,3389,8080")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.surface.port_scan(host, ports))


@router.post("/surface/fingerprint")
def surface_fp(url: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.surface.fingerprint_http(url))


@router.get("/surface/assets")
def surface_assets(domain: str = Query("")):
    g = _guard()
    if g:
        return g
    return ok({"assets": _ORCH.surface.list_assets(domain)})


@router.get("/surface/stats")
def surface_stats():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.surface.stats())


@router.post("/surface/shadow-it")
def shadow_it(registered: List[str] = Body(...),
              discovered: List[str] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok({"shadow_it": _ORCH.surface.detect_shadow_it(registered,
                                                          discovered)})


# =========================================================================== #
# 7. 阶段6：暗网监控
# =========================================================================== #
@router.post("/darkweb/configure")
def darkweb_configure(brands: List[str] = Body(...),
                      tor_proxy: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.darkweb.configure(brands, tor_proxy))


@router.post("/darkweb/scan")
def darkweb_scan(domain: str = Body(""),
                 employee_emails: List[str] = Body(default_factory=list)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.darkweb.scan(domain, employee_emails))


@router.get("/darkweb/hits")
def darkweb_hits(category: str = Query("")):
    g = _guard()
    if g:
        return g
    return ok({"hits": _ORCH.darkweb.list_hits(category)})


@router.get("/darkweb/alerts")
def darkweb_alerts():
    g = _guard()
    if g:
        return g
    return ok({"alerts": _ORCH.darkweb.list_alerts()})


@router.get("/darkweb/brand-protection")
def darkweb_brand():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.darkweb.brand_protection())


@router.get("/darkweb/stats")
def darkweb_stats():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.darkweb.stats())


# =========================================================================== #
# 8. 阶段7：情报分析
# =========================================================================== #
@router.post("/analysis/warnings")
def gen_warnings(ioc_stats: Dict[str, Any] = Body(...),
                 match_stats: Dict[str, Any] = Body(...),
                 dark_stats: Dict[str, Any] = Body(...),
                 actor_inference: Optional[List[Dict[str, Any]]] = Body(
                     default=None)):
    g = _guard()
    if g:
        return g
    return ok({"warnings": _ORCH.analysis.generate_warnings(
        ioc_stats, match_stats, dark_stats, actor_inference)})


@router.get("/analysis/warnings")
def list_warnings():
    g = _guard()
    if g:
        return g
    return ok({"warnings": _ORCH.analysis.list_warnings()})


@router.get("/analysis/trend")
def trend_predict(days: int = Query(7)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.analysis.predict_trends())


@router.post("/analysis/level")
def assess_level(ioc_count: int = Body(0), critical_iocs: int = Body(0),
                 open_alerts: int = Body(0), dark_critical: int = Body(0),
                 exposure_score: int = Body(0)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.analysis.assess_level(ioc_count, critical_iocs,
                                          open_alerts, dark_critical,
                                          exposure_score))


@router.get("/analysis/industry")
def industry_dist():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.analysis.industry_distribution(_ORCH.actors.stats()))


@router.post("/analysis/correlate")
def correlate_intel(iocs: List[Dict[str, Any]] = Body(...),
                   actors: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok({"related": _ORCH.analysis.correlate(iocs, actors)})


@router.get("/analysis/stats")
def analysis_stats():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.analysis.stats())


# =========================================================================== #
# 9. 阶段8：情报共享 STIX/TAXII
# =========================================================================== #
@router.post("/sharing/stix/export")
def stix_export(iocs: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.sharing.export_bundle(iocs))


@router.post("/sharing/stix/import")
def stix_import(bundle: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.sharing.import_stix(bundle))


@router.get("/sharing/taxii/discovery")
def taxii_discovery():
    g = _guard()
    if g:
        return g
    return ok(_ORCH.sharing.taxii_discovery())


@router.get("/sharing/taxii/collections")
def taxii_collections():
    g = _guard()
    if g:
        return g
    return ok({"collections": _ORCH.sharing.list_collections()})


@router.post("/sharing/groups")
def create_group(name: str = Body(...), scope: str = Body("internal"),
                 members: List[str] = Body(default_factory=list)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.sharing.create_group(name, scope, members))


@router.get("/sharing/groups")
def list_groups():
    g = _guard()
    if g:
        return g
    return ok({"groups": _ORCH.sharing.list_groups()})


@router.post("/sharing/quality")
def quality(ioc: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.sharing.quality_score(ioc))


@router.post("/sharing/provenance")
def provenance(ioc_value: str = Body(...), source: str = Body(""),
               raw_ref: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.sharing.set_provenance(ioc_value, source, raw_ref))


# =========================================================================== #
# 10. AI 分析
# =========================================================================== #
@router.post("/ai/analyze")
def ai_analyze(iocs: List[Dict[str, Any]] = Body(...),
               matches: List[Dict[str, Any]] = Body(default_factory=list),
               actors: List[Dict[str, Any]] = Body(default_factory=list),
               surface: Dict[str, Any] = Body(default_factory=dict)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.ai.analyze_intel(iocs, matches, actors, surface))


@router.post("/ai/forecast")
def ai_forecast(series: List[int] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_ORCH.ai.trend_forecast(series))


@router.get("/ai/thoughts")
def ai_thoughts():
    g = _guard()
    if g:
        return g
    return ok({"thoughts": _ORCH.ai.thoughts()})


# =========================================================================== #
# 11. 仪表盘 / 大屏
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    g = _guard()
    if g:
        return g
    return ok(_DASH.overview())


@router.get("/dashboard/ioc-trend")
def dash_trend(days: int = Query(7)):
    g = _guard()
    if g:
        return g
    return ok(_DASH.ioc_trend(days))


@router.get("/dashboard/geo")
def dash_geo():
    g = _guard()
    if g:
        return g
    return ok(_DASH.geo_distribution())


@router.get("/dashboard/top-actors")
def dash_actors(limit: int = Query(10)):
    g = _guard()
    if g:
        return g
    return ok(_DASH.top_actors(limit))


@router.get("/dashboard/industry")
def dash_industry():
    g = _guard()
    if g:
        return g
    return ok(_DASH.industry_distribution())


@router.get("/dashboard/ioc-types")
def dash_types():
    g = _guard()
    if g:
        return g
    return ok({"distribution": _DASH.ioc_type_distribution()})


@router.get("/dashboard/threat-level")
def dash_level():
    g = _guard()
    if g:
        return g
    return ok({"distribution": _DASH.threat_level_distribution()})


@router.get("/dashboard/alerts")
def dash_alerts():
    g = _guard()
    if g:
        return g
    return ok(_DASH.alert_stats())


@router.get("/dashboard/live-feed")
def dash_feed(limit: int = Query(20)):
    g = _guard()
    if g:
        return g
    return ok(_DASH.live_ioc_feed(limit))


@router.get("/dashboard/stages")
def dash_stages():
    g = _guard()
    if g:
        return g
    return ok({"stages": [{"key": k, "label": n, "progress": p}
                         for k, n, p in STAGES]})


# =========================================================================== #
# 12. 报告
# =========================================================================== #
@router.get("/report/{task_id}")
def get_report(task_id: str, fmt: str = Query("html")):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    if fmt == "md":
        return ok({"markdown": t.report_markdown, "path": t.report_path})
    return ok({"html": t.report_html, "path": t.report_path})


@router.post("/report/{task_id}/regen")
def regen_report(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok({"path": t.report_path,
               "markdown": t.report_markdown,
               "html": t.report_html})


# =========================================================================== #
# 13. 健康
# =========================================================================== #
@router.get("/health")
def health():
    g = _guard()
    if g:
        return g
    return ok({"status": "ok", "stages": len(STAGES),
               "ws": manager.stats(),
               "reports_dir": REPORTS_DIR})
