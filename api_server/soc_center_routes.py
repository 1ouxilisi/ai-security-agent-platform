# -*- coding: utf-8 -*-
"""
soc_center_routes.py — 统一安全运营中心 SOC Center REST API（50+ 端点 + 统一 WebSocket）。

路由前缀: /api/v1/soc-center
统一响应: {"success": bool, "data": ..., "error": ...}
WebSocket: /api/v1/soc-center/ws
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/soc-center",
                   tags=["SOCCenter-统一安全运营中心"])

# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD = False
try:
    from soc_center import (
        get_soc_center, get_aggregator, get_dashboard, get_task_list,
        get_alert_center, get_operation_log, get_global_search,
        get_notification_center, get_configuration_center, DOMAINS,
    )
    _SC = get_soc_center()
    _AGG = get_aggregator()
    _DASH = get_dashboard()
    _TASKS = get_task_list()
    _ALERTS = get_alert_center()
    _LOGS = get_operation_log()
    _SEARCH = get_global_search()
    _NOTIF = get_notification_center()
    _CONF = get_configuration_center()
    _MOD = True
    logger.info("soc_center_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("soc_center_routes: load failed: %s", e)
    _SC = _AGG = _DASH = _TASKS = None  # type: ignore
    _ALERTS = _LOGS = _SEARCH = _NOTIF = _CONF = None  # type: ignore
    DOMAINS = []  # type: ignore


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
    if not _MOD or _SC is None:
        return fail("SOC Center 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 概览 / 导航 / 健康
# =========================================================================== #
@router.get("/home")
def home():
    g = _guard()
    if g:
        return g
    return ok(_SC.home())


@router.get("/domains")
def domains_nav():
    g = _guard()
    if g:
        return g
    return ok({"domains": DOMAINS})


@router.get("/modules/status")
def modules_status():
    g = _guard()
    if g:
        return g
    return ok(_SC.modules_status())


@router.get("/health")
def health():
    return ok({"status": "ok", "ts": time.time()})


# =========================================================================== #
# 1. 统一仪表盘
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


@router.get("/dashboard/score")
def dash_score():
    g = _guard()
    if g:
        return g
    return ok(_AGG.security_score())


@router.get("/dashboard/trend")
def dash_trend(days: int = Query(7)):
    g = _guard()
    if g:
        return g
    return ok(_AGG.trend(days))


@router.get("/dashboard/domain-health")
def dash_domain_health():
    g = _guard()
    if g:
        return g
    return ok({"domains": _AGG.domain_health()})


@router.get("/dashboard/realtime-events")
def dash_realtime(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok(_AGG.list_events(limit=limit))


# =========================================================================== #
# 2. 统一任务列表
# =========================================================================== #
@router.get("/tasks")
def list_tasks(domain: Optional[str] = Query(None),
               status: Optional[str] = Query(None),
               keyword: Optional[str] = Query(None),
               limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok(_TASKS.list(domain=domain, status=status,
                          keyword=keyword, limit=limit))


@router.get("/tasks/stats")
def tasks_stats():
    g = _guard()
    if g:
        return g
    return ok(_TASKS.stats())


@router.post("/tasks")
def create_task(title: str = Body(...),
                domain: str = Body("soc-pro"),
                owner: str = Body("system")):
    g = _guard()
    if g:
        return g
    t = _AGG.ingest_task({"title": title, "domain": domain,
                          "owner": owner, "status": "pending"})
    return ok(t)


# =========================================================================== #
# 3. 统一告警中心
# =========================================================================== #
@router.get("/alerts")
def list_alerts(domain: Optional[str] = Query(None),
                severity: Optional[str] = Query(None),
                status: Optional[str] = Query(None),
                limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok(_ALERTS.list(domain=domain, severity=severity,
                           status=status, limit=limit))


@router.get("/alerts/summary")
def alerts_summary():
    g = _guard()
    if g:
        return g
    return ok(_ALERTS.summary())


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: str):
    g = _guard()
    if g:
        return g
    a = _ALERTS.detail(alert_id)
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
    r = _ALERTS.update_status(alert_id, status, note)
    if r is None:
        return fail("invalid status or alert not found")
    return ok(r)


@router.post("/alerts/{alert_id}/assign")
def alert_assign(alert_id: str,
                 assignee: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    r = _ALERTS.assign(alert_id, assignee)
    if r is None:
        return fail("alert not found", 404)
    return ok(r)


@router.post("/alerts/{alert_id}/false-positive")
def alert_false_positive(alert_id: str):
    g = _guard()
    if g:
        return g
    r = _ALERTS.update_status(alert_id, "false_positive", "标记误报")
    if r is None:
        return fail("alert not found", 404)
    return ok(r)


@router.post("/alerts")
def create_alert(title: str = Body(...),
                 domain: str = Body("soc-pro"),
                 severity: str = Body("medium"),
                 detail: str = Body("")):
    g = _guard()
    if g:
        return g
    a = _AGG.ingest_alert({"title": title, "domain": domain,
                           "severity": severity, "detail": detail})
    _NOTIF.publish("alert", domain, a, source="manual")
    return ok(a)


# =========================================================================== #
# 4. 漏洞 / 资产
# =========================================================================== #
@router.get("/vulns")
def list_vulns(domain: Optional[str] = Query(None),
               severity: Optional[str] = Query(None),
               status: Optional[str] = Query(None),
               limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok({"vulns": _AGG.list_vulns(domain=domain, severity=severity,
                                        status=status, limit=limit)})


@router.get("/vulns/summary")
def vulns_summary():
    g = _guard()
    if g:
        return g
    return ok(_AGG.stats_summary()["vulns"])


@router.get("/assets")
def list_assets(domain: Optional[str] = Query(None),
                status: Optional[str] = Query(None),
                limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok({"assets": _AGG.list_assets(domain=domain, status=status,
                                         limit=limit)})


@router.get("/assets/summary")
def assets_summary():
    g = _guard()
    if g:
        return g
    return ok(_AGG.stats_summary()["assets"])


# =========================================================================== #
# 5. 事件流 / 操作日志
# =========================================================================== #
@router.get("/events")
def list_events(domain: Optional[str] = Query(None),
                limit: int = Query(100)):
    g = _guard()
    if g:
        return g
    return ok({"events": _AGG.list_events(domain=domain, limit=limit)})


@router.get("/logs")
def list_logs(keyword: Optional[str] = Query(None),
              user: Optional[str] = Query(None),
              limit: int = Query(200)):
    g = _guard()
    if g:
        return g
    return ok(_LOGS.list(keyword=keyword, user=user, limit=limit))


@router.post("/logs")
def record_log(user: str = Body(...),
               action: str = Body(...),
               target: str = Body(""),
               domain: str = Body(""),
               detail: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_LOGS.record(user, action, target, domain, detail))


# =========================================================================== #
# 6. 全局搜索
# =========================================================================== #
@router.get("/search")
def global_search(q: str = Query(...),
                  limit_per: int = Query(20)):
    g = _guard()
    if g:
        return g
    return ok(_SEARCH.search(q, limit_per=limit_per))


# =========================================================================== #
# 7. 统一通知中心
# =========================================================================== #
@router.get("/notifications")
def list_notifications(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok(_NOTIF.notifications(limit=limit))


@router.get("/notifications/unread")
def unread_count():
    g = _guard()
    if g:
        return g
    n = _NOTIF.notifications(limit=1)
    return ok({"unread": n["unread"]})


@router.post("/notifications/read")
def mark_read(nid: Optional[str] = Body(None)):
    g = _guard()
    if g:
        return g
    return ok(_NOTIF.mark_read(nid))


@router.post("/notifications/publish")
def publish_notification(msg_type: str = Body("notification"),
                         domain: str = Body("system"),
                         data: Any = Body(...),
                         source: str = Body("manual")):
    g = _guard()
    if g:
        return g
    m = _NOTIF.publish(msg_type, domain, data, source=source)
    return ok(m)


@router.get("/notifications/history")
def notification_history(limit: int = Query(100)):
    g = _guard()
    if g:
        return g
    return ok({"history": _NOTIF.history(limit=limit)})


# =========================================================================== #
# 8. 统一配置中心
# =========================================================================== #
@router.get("/config")
def get_config(domain: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok(_CONF.get(domain))


@router.get("/config/domains")
def config_domains():
    g = _guard()
    if g:
        return g
    return ok(_CONF.list_domains())


@router.put("/config/{domain}")
def update_config(domain: str, patch: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_CONF.update(domain, patch))


@router.post("/config/{domain}/reset")
def reset_config(domain: str):
    g = _guard()
    if g:
        return g
    return ok(_CONF.reset(domain))


# =========================================================================== #
# 9. 统计聚合
# =========================================================================== #
@router.get("/stats/summary")
def stats_summary():
    g = _guard()
    if g:
        return g
    return ok(_AGG.stats_summary())


@router.get("/stats/by-domain")
def stats_by_domain():
    g = _guard()
    if g:
        return g
    return ok({"domains": _AGG.domain_health()})


# =========================================================================== #
# 10. 数据摄入（供其他领域/联动引擎调用）
# =========================================================================== #
@router.post("/ingest/event")
def ingest_event(domain: str = Body(...),
                 event_type: str = Body("info"),
                 message: str = Body(""),
                 detail: str = Body("")):
    g = _guard()
    if g:
        return g
    e = _AGG.ingest_event({"domain": domain, "type": event_type,
                           "message": message, "detail": detail})
    _NOTIF.publish("event", domain, e, source="ingest")
    return ok(e)


@router.post("/ingest/vuln")
def ingest_vuln(domain: str = Body(...),
                title: str = Body(...),
                severity: str = Body("medium"),
                cve: str = Body(""),
                asset: str = Body("")):
    g = _guard()
    if g:
        return g
    v = _AGG.ingest_vuln({"domain": domain, "title": title,
                          "severity": severity, "cve": cve, "asset": asset})
    _NOTIF.publish("vuln", domain, v, source="ingest")
    return ok(v)


# =========================================================================== #
# 10b. 补充端点（任务/漏洞/资产详情、批量操作、Top 排行）
# =========================================================================== #
@router.get("/tasks/{task_id}")
def task_detail(task_id: str):
    g = _guard()
    if g:
        return g
    for t in _AGG.list_tasks(limit=10000):
        if t["id"] == task_id:
            return ok(t)
    return fail("task not found", 404)


@router.get("/vulns/{vuln_id}")
def vuln_detail(vuln_id: str):
    g = _guard()
    if g:
        return g
    for v in _AGG.list_vulns(limit=10000):
        if v["id"] == vuln_id:
            return ok(v)
    return fail("vuln not found", 404)


@router.get("/assets/{asset_id}")
def asset_detail(asset_id: str):
    g = _guard()
    if g:
        return g
    for a in _AGG.list_assets(limit=10000):
        if a["id"] == asset_id:
            return ok(a)
    return fail("asset not found", 404)


@router.post("/alerts/bulk-status")
def bulk_status(alert_ids: List[str] = Body(...),
                status: str = Body(...)):
    g = _guard()
    if g:
        return g
    done = []
    for aid in alert_ids:
        r = _ALERTS.update_status(aid, status, "批量处理")
        if r:
            done.append(aid)
    return ok({"updated": len(done), "ids": done})


@router.get("/dashboard/alerts-top")
def alerts_top(n: int = Query(10)):
    g = _guard()
    if g:
        return g
    return ok({"top": _AGG.list_alerts(limit=n)})


@router.get("/dashboard/vulns-top")
def vulns_top(n: int = Query(10)):
    g = _guard()
    if g:
        return g
    return ok({"top": _AGG.list_vulns(limit=n)})


@router.get("/dashboard/assets-risk")
def assets_risk():
    g = _guard()
    if g:
        return g
    return ok({"risk": _AGG.list_assets(status="risk", limit=50)})


@router.get("/config/all")
def config_all():
    g = _guard()
    if g:
        return g
    return ok(_CONF.get())


@router.post("/ingest/alert")
def ingest_alert(domain: str = Body(...),
                title: str = Body(...),
                severity: str = Body("medium"),
                detail: str = Body("")):
    g = _guard()
    if g:
        return g
    a = _AGG.ingest_alert({"domain": domain, "title": title,
                           "severity": severity, "detail": detail})
    _NOTIF.publish("alert", domain, a, source="ingest")
    return ok(a)


@router.post("/ingest/asset")
def ingest_asset(domain: str = Body(...),
                 name: str = Body(...),
                 ip: str = Body(""),
                 type: str = Body("host")):
    g = _guard()
    if g:
        return g
    a = _AGG.ingest_asset({"domain": domain, "name": name,
                           "ip": ip, "type": type})
    return ok(a)


@router.post("/notifications/read-all")
def read_all():
    g = _guard()
    if g:
        return g
    return ok(_NOTIF.mark_read(None))


@router.get("/stats/trend")
def stats_trend(days: int = Query(7)):
    g = _guard()
    if g:
        return g
    return ok(_AGG.trend(days))


# =========================================================================== #
# 11. 统一 WebSocket 推送
# =========================================================================== #
@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    """统一 WebSocket 端点。

    客户端可发 JSON: {"action": "subscribe", "domains": [...], "types": [...]}
    """
    await websocket.accept()
    if not _MOD:
        await websocket.send_json({"type": "error",
                                   "message": "模块未加载"})
        await websocket.close()
        return
    _NOTIF.add(websocket)
    # 推送历史
    for ev in _NOTIF.history(50):
        try:
            await websocket.send_json(ev)
        except Exception:
            break
    try:
        sent_index = len(_NOTIF.history(100))
        while True:
            hist = _NOTIF.history(100)
            if len(hist) > sent_index:
                for ev in hist[sent_index:]:
                    await websocket.send_json(ev)
                sent_index = len(hist)
            await websocket.send_json({"type": "ping",
                                       "ts": time.time()})
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _NOTIF.remove(websocket)
