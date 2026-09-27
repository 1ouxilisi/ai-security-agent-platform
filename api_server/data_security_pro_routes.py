# -*- coding: utf-8 -*-
"""
data_security_pro_routes.py — 方向3 数据安全 Pro REST API（50+ 端点）。

路由前缀: /api/v1/data-security-pro
WebSocket: /api/v1/data-security-pro/ws/{task_id}
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/data-security-pro",
                   tags=["数据安全Pro-方向3"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from data_security_pro import (
        get_orchestrator, get_dashboard,
        get_data_discovery_phase, get_data_classification_phase,
        get_data_asset_phase, get_dlp_phase,
        get_privacy_compliance_phase, get_encryption_key_phase,
        get_access_audit_phase, get_risk_rating_phase,
        get_ai_analysis, get_report_generator,
        ws_chain, snapshot, STAGES, REPORTS_DIR,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _DISC = get_data_discovery_phase()
    _CLS = get_data_classification_phase()
    _AST = get_data_asset_phase()
    _DLP = get_dlp_phase()
    _PRIV = get_privacy_compliance_phase()
    _ENC = get_encryption_key_phase()
    _ACC = get_access_audit_phase()
    _RISK = get_risk_rating_phase()
    _AI = get_ai_analysis()
    _RPT = get_report_generator()
    _MOD_AVAILABLE = True
    logger.info("data_security_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("data_security_pro_routes: load failed: %s", e)
    _ORCH = None  # type: ignore
    _DASH = None  # type: ignore


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
        return fail("数据安全 Pro 模块未加载", 503)
    return None


# =========================================================================== #
# WebSocket
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_data_security(websocket: WebSocket, task_id: str):
    """实时推送数据发现 / DLP 告警 / 合规检查进度。"""
    await ws_chain(websocket, task_id)


# =========================================================================== #
# 1. 任务管理（一键八阶段）
# =========================================================================== #
@router.post("/start")
def start_audit(target: str = Body(default="data-security-audit",
                                    embed=True)):
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


@router.get("/task/{task_id}/ws-snapshot")
def task_ws_snapshot(task_id: str):
    g = _guard()
    if g:
        return g
    return ok(snapshot(task_id))


# =========================================================================== #
# 2. 阶段1：数据发现
# =========================================================================== #
@router.get("/discovery/sources")
def disc_sources():
    g = _guard()
    if g:
        return g
    return ok({"sources": _DISC.list_sources(),
               "supported": _DISC.list_supported()})


@router.get("/discovery/drivers")
def disc_drivers():
    g = _guard()
    if g:
        return g
    return ok({"supported": _DISC.list_supported()})


@router.post("/discovery/register")
def disc_register(source_type: str = Body(...),
                  name: str = Body(default=""),
                  host: str = Body(default=""),
                  port: int = Body(default=0),
                  database: str = Body(default="")):
    g = _guard()
    if g:
        return g
    s = _DISC.register_source(source_type, name, host, port, database)
    return ok(s.to_dict())


@router.post("/discovery/scan")
def disc_scan(source_name: Optional[str] = Body(default=None)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_DISC.scan(source_name))
    except Exception as e:  # noqa: BLE001
        return fail(f"扫描失败: {e}")


@router.post("/discovery/analyze-text")
def disc_analyze_text(text: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_DISC.analyze_text(text))


# =========================================================================== #
# 3. 阶段2：数据分类分级
# =========================================================================== #
@router.get("/classification/rules")
def cls_rules():
    g = _guard()
    if g:
        return g
    return ok({"rules": _CLS.list_rules()})


@router.post("/classification/rules")
def cls_add_rule(name: str = Body(...),
                 level: str = Body(...),
                 field_pattern: str = Body(default=""),
                 data_type: str = Body(default=""),
                 content_keyword: str = Body(default=""),
                 weight: int = Body(default=5)):
    g = _guard()
    if g:
        return g
    return ok(_CLS.add_rule(name, level, field_pattern, data_type,
                            content_keyword, weight).to_dict())


@router.post("/classification/rules/{rule_id}/toggle")
def cls_toggle(rule_id: str):
    g = _guard()
    if g:
        return g
    return ok(_CLS.toggle_rule(rule_id))


@router.post("/classification/classify")
def cls_classify(data_type: str = Body(default=""),
                 field_name: str = Body(default=""),
                 content: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_CLS.classify_item(data_type, field_name, content))


@router.post("/classification/classify-batch")
def cls_batch(hits: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_CLS.classify_batch(hits))


@router.get("/classification/labels")
def cls_labels():
    g = _guard()
    if g:
        return g
    return ok({"labels": _CLS.get_labels()})


@router.get("/classification/history")
def cls_history():
    g = _guard()
    if g:
        return g
    return ok({"history": _CLS.history()})


# =========================================================================== #
# 4. 阶段3：数据资产盘点
# =========================================================================== #
@router.get("/asset/list")
def asset_list(kind: Optional[str] = Query(default=None)):
    g = _guard()
    if g:
        return g
    return ok({"assets": _AST.list_assets(kind)})


@router.get("/asset/{asset_id}")
def asset_detail(asset_id: str):
    g = _guard()
    if g:
        return g
    a = _AST.get_asset(asset_id)
    if not a:
        return fail("asset not found", 404)
    return ok(a)


@router.post("/asset/add")
def asset_add(name: str = Body(...), kind: str = Body(default="table"),
              location: str = Body(default=""),
              owner: str = Body(default="未分配"),
              admin: str = Body(default="未分配"),
              sensitivity: str = Body(default="internal"),
              value_score: int = Body(default=50)):
    g = _guard()
    if g:
        return g
    return ok(_AST.add_asset(name, kind, location, owner, admin,
                             sensitivity, value_score))


@router.get("/asset/summary")
def asset_summary():
    g = _guard()
    if g:
        return g
    return ok(_AST.summary())


@router.get("/asset/flows")
def asset_flows():
    g = _guard()
    if g:
        return g
    return ok({"flows": _AST.data_flows()})


@router.get("/asset/map")
def asset_map():
    g = _guard()
    if g:
        return g
    return ok(_AST.asset_map())


@router.get("/asset/changes")
def asset_changes(limit: int = Query(default=30)):
    g = _guard()
    if g:
        return g
    return ok({"changes": _AST.changes(limit)})


# =========================================================================== #
# 5. 阶段4：DLP 防泄漏
# =========================================================================== #
@router.get("/dlp/policies")
def dlp_policies(category: Optional[str] = Query(default=None),
                 enabled_only: bool = Query(default=False)):
    g = _guard()
    if g:
        return g
    return ok({"policies": _DLP.list_policies(category, enabled_only),
               "count": len(_DLP.list_policies(category, enabled_only))})


@router.get("/dlp/policies/{policy_id}")
def dlp_policy_detail(policy_id: str):
    g = _guard()
    if g:
        return g
    p = _DLP.policy_detail(policy_id)
    if not p:
        return fail("policy not found", 404)
    return ok(p)


@router.post("/dlp/policies/{policy_id}/toggle")
def dlp_toggle(policy_id: str, enabled: bool = Body(default=True)):
    g = _guard()
    if g:
        return g
    return ok(_DLP.enable_policy(policy_id, enabled))


@router.post("/dlp/policies/{policy_id}/threshold")
def dlp_threshold(policy_id: str, threshold: int = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_DLP.set_threshold(policy_id, threshold))


@router.post("/dlp/policies/{policy_id}/action")
def dlp_action(policy_id: str, action: str = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_DLP.set_action(policy_id, action))


@router.post("/dlp/policies/add")
def dlp_add(name: str = Body(...), category: str = Body(...),
            channel: str = Body(...), action: str = Body(default="alert"),
            level: str = Body(default="medium"),
            description: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_DLP.add_policy(name, category, channel, action, level,
                             description))


@router.post("/dlp/event")
def dlp_event(channel: str = Body(...), content: str = Body(default=""),
              user: str = Body(default="demo-user")):
    g = _guard()
    if g:
        return g
    return ok(_DLP.simulate_event(channel, content, user))


@router.get("/dlp/alerts")
def dlp_alerts(level: Optional[str] = Query(default=None),
               status: Optional[str] = Query(default=None),
               limit: int = Query(default=50)):
    g = _guard()
    if g:
        return g
    return ok({"alerts": _DLP.list_alerts(level, status, limit)})


@router.post("/dlp/alerts/{alert_id}/ack")
def dlp_ack(alert_id: str, status: str = Body(default="closed")):
    g = _guard()
    if g:
        return g
    return ok(_DLP.ack_alert(alert_id, status))


@router.get("/dlp/stats")
def dlp_stats():
    g = _guard()
    if g:
        return g
    return ok(_DLP.stats())


# =========================================================================== #
# 6. 阶段5：隐私合规
# =========================================================================== #
@router.get("/privacy/items")
def priv_items(framework: Optional[str] = Query(default=None),
               domain: Optional[str] = Query(default=None)):
    g = _guard()
    if g:
        return g
    return ok({"items": _PRIV.list_items(framework, domain)})


@router.get("/privacy/items/{item_id}")
def priv_item(item_id: str):
    g = _guard()
    if g:
        return g
    it = _PRIV.get_item(item_id)
    if not it:
        return fail("item not found", 404)
    return ok(it)


@router.post("/privacy/assess")
def priv_assess(item_id: str = Body(...), status: str = Body(...),
                score: int = Body(...), note: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_PRIV.assess(item_id, status, score, note))


@router.post("/privacy/auto-assess")
def priv_auto():
    g = _guard()
    if g:
        return g
    return ok(_PRIV.auto_assess())


@router.get("/privacy/summary")
def priv_summary():
    g = _guard()
    if g:
        return g
    return ok(_PRIV.summary())


@router.get("/privacy/report")
def priv_report():
    g = _guard()
    if g:
        return g
    return ok({"markdown": _PRIV.generate_report()})


# =========================================================================== #
# 7. 阶段6：加密与密钥
# =========================================================================== #
@router.get("/encryption/findings")
def enc_findings(scope: Optional[str] = Query(default=None),
                 min_risk: int = Query(default=0)):
    g = _guard()
    if g:
        return g
    return ok({"findings": _ENC.list_findings(scope, min_risk)})


@router.get("/encryption/keys")
def enc_keys():
    g = _guard()
    if g:
        return g
    return ok({"keys": _ENC.list_keys()})


@router.post("/encryption/check-algorithm")
def enc_check(algorithm: str = Body(...),
              key_length: int = Body(default=0),
              mode: str = Body(default="")):
    g = _guard()
    if g:
        return g
    return ok(_ENC.check_algorithm(algorithm, key_length, mode))


@router.get("/encryption/coverage")
def enc_coverage():
    g = _guard()
    if g:
        return g
    return ok(_ENC.coverage())


@router.get("/encryption/risk")
def enc_risk():
    g = _guard()
    if g:
        return g
    return ok(_ENC.risk_summary())


# =========================================================================== #
# 8. 阶段7：数据访问审计
# =========================================================================== #
@router.get("/access/logs")
def acc_logs(user: Optional[str] = Query(default=None),
             limit: int = Query(default=100)):
    g = _guard()
    if g:
        return g
    return ok({"logs": _ACC.list_logs(user, limit)})


@router.post("/access/logs")
def acc_ingest(user: str = Body(...), action: str = Body(...),
               resource: str = Body(...), ip: str = Body(...),
               location: str = Body(default="内网"),
               is_privileged: bool = Body(default=False),
               row_count: int = Body(default=0)):
    g = _guard()
    if g:
        return g
    return ok(_ACC.ingest_log(user, action, resource, ip, location,
                              is_privileged, row_count))


@router.get("/access/anomalies")
def acc_anomalies(atype: Optional[str] = Query(default=None),
                  min_risk: int = Query(default=0)):
    g = _guard()
    if g:
        return g
    return ok({"anomalies": _ACC.list_anomalies(atype, min_risk)})


@router.get("/access/permissions")
def acc_perms():
    g = _guard()
    if g:
        return g
    return ok({"permissions": _ACC.list_permissions()})


@router.get("/access/stats")
def acc_stats():
    g = _guard()
    if g:
        return g
    return ok(_ACC.stats())


# =========================================================================== #
# 9. 阶段8：风险评级
# =========================================================================== #
@router.post("/risk/compute")
def risk_compute(discovery: Optional[Dict[str, Any]] = Body(default=None),
                 classification: Optional[Dict[str, Any]] = Body(default=None),
                 dlp: Optional[Dict[str, Any]] = Body(default=None),
                 compliance: Optional[Dict[str, Any]] = Body(default=None),
                 encryption: Optional[Dict[str, Any]] = Body(default=None),
                 access: Optional[Dict[str, Any]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_RISK.compute(discovery, classification, dlp, compliance,
                            encryption, access))


@router.get("/risk/trend")
def risk_trend(limit: int = Query(default=10)):
    g = _guard()
    if g:
        return g
    return ok({"trend": _RISK.trend(limit)})


# =========================================================================== #
# 10. AI 分析
# =========================================================================== #
@router.post("/ai/analyze")
def ai_analyze(risk: Dict[str, Any] = Body(...),
               compliance: Optional[Dict[str, Any]] = Body(default=None),
               encryption: Optional[Dict[str, Any]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    return ok(_AI.analyze_overall(risk, compliance, encryption))


@router.post("/ai/sensitive-assist")
def ai_sensitive(hits: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_AI.assist_sensitive_recognition(hits))


@router.post("/ai/access-assist")
def ai_access(anomalies: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_AI.assist_access(anomalies))


# =========================================================================== #
# 11. 数据安全大屏
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    g = _guard()
    if g:
        return g
    return ok(_DASH.overview())


@router.get("/dashboard/alerts-stream")
def dash_alerts(limit: int = Query(default=20)):
    g = _guard()
    if g:
        return g
    return ok({"alerts": _DASH.dlp_alerts_stream(limit)})


@router.get("/dashboard/heatmap")
def dash_heatmap():
    g = _guard()
    if g:
        return g
    return ok({"cells": _DASH.risk_heatmap()})


@router.get("/dashboard/dlp-trend")
def dash_dlp_trend():
    g = _guard()
    if g:
        return g
    return ok(_DASH.dlp_trend())


@router.get("/dashboard/stages")
def dash_stages():
    g = _guard()
    if g:
        return g
    return ok({"stages": [
        {"key": k, "label": n, "progress": p} for k, n, p in STAGES]})


# =========================================================================== #
# 12. 报告生成
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
    ctx = {
        "discovery": t.discovery, "classification": t.classification,
        "asset_summary": t.asset, "dlp": t.dlp,
        "compliance": t.privacy, "encryption": t.encryption,
        "access": t.access, "risk": t.risk, "ai": t.ai,
    }
    t.report_markdown = _RPT.generate_markdown(ctx)
    t.report_html = _RPT.generate_html(ctx)
    return ok({"markdown": t.report_markdown, "html": t.report_html,
               "path": t.report_path})
