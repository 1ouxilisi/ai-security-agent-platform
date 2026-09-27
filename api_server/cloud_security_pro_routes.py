# -*- coding: utf-8 -*-
"""
cloud_security_pro_routes.py — 方向3 云安全 Pro REST API（40+ 端点，含 WebSocket）。

路由前缀: /api/v1/cloud-security-pro
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cloud-security-pro",
                   tags=["云安全Pro-方向3"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from cloud_security_pro import (
        get_orchestrator, get_dashboard, get_push_manager,
        get_asset_discovery_phase, get_config_check_phase,
        get_risk_rating_phase, get_vuln_detect_phase,
        get_compliance_audit_phase, get_ai_analysis, get_report_generator,
        detect_credential_status, STAGES,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _PUSH = get_push_manager()
    _RPT = get_report_generator()
    _MOD_AVAILABLE = True
    logger.info("cloud_security_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("cloud_security_pro_routes: load failed: %s", e)
    _ORCH = None  # type: ignore
    _DASH = None  # type: ignore
    _PUSH = None  # type: ignore
    _RPT = None  # type: ignore


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
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
        return fail("云安全 Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 凭证 / SDK 状态
# =========================================================================== #
@router.get("/credential/status")
def credential_status(provider: str = Query(default="aws")):
    g = _guard()
    if g:
        return g
    return ok(detect_credential_status(provider))


@router.get("/credential/guide")
def credential_guide(provider: str = Query(default="aws")):
    g = _guard()
    if g:
        return g
    if provider == "aws":
        return ok({"provider": "aws", "steps": [
            "1. pip install boto3",
            "2. aws configure 配置 AK/SK，或设置 AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_DEFAULT_REGION",
            "3. 使用只读审计权限(SecurityAudit)，勿用主账号 AK"]})
    return ok({"provider": "aliyun", "steps": [
        "1. pip install aliyun-python-sdk-core 等",
        "2. 设置 ALIBABA_CLOUD_ACCESS_KEY_ID/SECRET/REGION_ID",
        "3. 使用只读 RAM 子账号"]})


# =========================================================================== #
# 1. 任务管理（一键全流程）
# =========================================================================== #
@router.post("/start")
def start_assessment(provider: str = Body(default="aws"),
                     region: Optional[str] = Body(default=None)):
    g = _guard()
    if g:
        return g
    t = _ORCH.create_task(provider)
    threading.Thread(target=_ORCH.run_full,
                     args=(provider, region, t.task_id),
                     daemon=True).start()
    return ok({"task_id": t.task_id, "provider": provider,
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


@router.get("/task/{task_id}/logs")
def task_logs(task_id: str, limit: int = Query(default=100)):
    g = _guard()
    if g:
        return g
    return ok({"logs": _PUSH.get_logs(task_id, limit)})


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


# =========================================================================== #
# 2. 阶段1：资产发现
# =========================================================================== #
@router.post("/asset/discover")
def asset_discover(provider: str = Body(default="aws"),
                   region: Optional[str] = Body(default=None),
                   services: Optional[List[str]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    try:
        res = get_asset_discovery_phase().discover(
            provider=provider, region=region, services=services)
        return ok(res.to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"资产发现失败: {e}")


@router.get("/asset/services")
def asset_services():
    g = _guard()
    if g:
        return g
    return ok(get_asset_discovery_phase().list_available_services())


@router.get("/asset/tags")
def asset_tags():
    """从最近资产清单提取标签分布。"""
    g = _guard()
    if g:
        return g
    tags: Dict[str, int] = {}
    for t in _ORCH.list_tasks():
        for r in (t.get("inventory") or {}).get("resources", []):
            for k, v in (r.get("tags") or {}).items():
                key = f"{k}={v}"
                tags[key] = tags.get(key, 0) + 1
    return ok({"tags": tags, "count": len(tags)})


# =========================================================================== #
# 3. 阶段2：配置检查
# =========================================================================== #
@router.post("/config/check")
def config_check(inventory: Optional[Dict[str, Any]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_config_check_phase().run(inventory or {}).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"配置检查失败: {e}")


@router.get("/config/rules")
def config_rules():
    g = _guard()
    if g:
        return g
    rp = get_config_check_phase()
    return ok({"rules": rp.rules_meta(), "count": len(rp.rules_meta())})


@router.get("/config/rules/{rule_id}")
def config_rule_detail(rule_id: str):
    g = _guard()
    if g:
        return g
    for r in get_config_check_phase().rules_meta():
        if r["id"] == rule_id:
            return ok(r)
    return fail("rule not found", 404)


# =========================================================================== #
# 4. 阶段3：风险评级
# =========================================================================== #
@router.post("/risk/rate")
def risk_rate(findings: List[Dict[str, Any]] = Body(default_factory=list),
              resource_count: int = Body(default=0)):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_risk_rating_phase().rate(
            findings, resource_count).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"风险评级失败: {e}")


@router.get("/risk/trend")
def risk_trend():
    g = _guard()
    if g:
        return g
    return ok({"history": get_risk_rating_phase().history()})


# =========================================================================== #
# 5. 阶段4：漏洞检测
# =========================================================================== #
@router.post("/vuln/detect")
def vuln_detect(inventory: Optional[Dict[str, Any]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_vuln_detect_phase().detect(inventory or {}))
    except Exception as e:  # noqa: BLE001
        return fail(f"漏洞检测失败: {e}")


@router.get("/vuln/db")
def vuln_db():
    g = _guard()
    if g:
        return g
    return ok(get_vuln_detect_phase().db_overview())


@router.get("/vuln/cve/{cve_id}")
def vuln_cve_detail(cve_id: str):
    g = _guard()
    if g:
        return g
    for e in get_vuln_detect_phase().db:
        if e["cve_id"] == cve_id:
            return ok(e)
    return fail("CVE not found", 404)


@router.get("/vuln/search")
def vuln_search(keyword: str = Query(...),
                limit: int = Query(default=20)):
    g = _guard()
    if g:
        return g
    kw = keyword.lower()
    hits = [e for e in get_vuln_detect_phase().db
            if kw in e["product"].lower() or kw in e["title"].lower()
            or kw in e["cve_id"].lower()][:limit]
    return ok({"keyword": keyword, "count": len(hits), "items": hits})


# =========================================================================== #
# 6. 阶段5：合规审计
# =========================================================================== #
@router.post("/compliance/audit")
def compliance_audit(findings: List[Dict[str, Any]] = Body(default_factory=list)):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_compliance_audit_phase().audit(findings).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(f"合规审计失败: {e}")


@router.get("/compliance/frameworks")
def compliance_frameworks():
    g = _guard()
    if g:
        return g
    return ok({"frameworks": ["等保2.0", "ISO27001", "CIS"]})


# =========================================================================== #
# 7. AI 分析
# =========================================================================== #
@router.post("/ai/analyze")
def ai_analyze(payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ai_analysis().analyze(
            payload.get("inventory", {}), payload.get("config", {}),
            payload.get("risk", {}), payload.get("vuln", {}),
            payload.get("compliance", {})))
    except Exception as e:  # noqa: BLE001
        return fail(f"AI 分析失败: {e}")


@router.post("/ai/prioritize")
def ai_prioritize(findings: List[Dict[str, Any]] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok({"priorities": get_ai_analysis()._prioritize(findings)})
    except Exception as e:  # noqa: BLE001
        return fail(f"优先级排序失败: {e}")


@router.post("/ai/paths")
def ai_paths(payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        paths = get_ai_analysis()._attack_paths(
            payload.get("findings", []), payload.get("vuln", {}))
        return ok({"attack_paths": [p.to_dict() for p in paths]})
    except Exception as e:  # noqa: BLE001
        return fail(f"攻击路径分析失败: {e}")


@router.post("/ai/cost")
def ai_cost(inventory: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok({"cost_optimizations":
                   get_ai_analysis()._cost_tips(inventory)})
    except Exception as e:  # noqa: BLE001
        return fail(f"成本分析失败: {e}")


# =========================================================================== #
# 8. 报告
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
    from cloud_security_pro.report_generator import CloudReportData
    rd = CloudReportData(
        task_id=t.task_id, provider=t.provider,
        started_at=t.created_at,
        finished_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        inventory=t.inventory, config=t.config, risk=t.risk,
        vuln=t.vuln, compliance=t.compliance, ai=t.ai)
    path = _RPT.save(rd, "html")
    return ok({"path": path,
               "markdown": _RPT.generate_markdown(rd),
               "html": _RPT.generate_html(rd)})


# =========================================================================== #
# 9. 仪表盘
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
    return ok({"stages": [
        {"key": k, "label": n, "progress": p} for k, n, p in STAGES
    ]})


@router.get("/dashboard/ws-status")
def ws_status():
    g = _guard()
    if g:
        return g
    return ok({"connected_clients": _PUSH.connection_count()})


@router.get("/dashboard/heatmap")
def dash_heatmap():
    """资产风险热力图数据（按资源类型聚合）。"""
    g = _guard()
    if g:
        return g
    bt: Dict[str, int] = {}
    for t in _ORCH.list_tasks():
        for r in (t.get("inventory") or {}).get("resources", []):
            rt = r.get("resource_type", "other")
            bt[rt] = bt.get(rt, 0) + 1
    ft: Dict[str, int] = {}
    for t in _ORCH.list_tasks():
        for f in (t.get("config") or {}).get("findings", []):
            rt = f.get("resource_type", "other")
            ft[rt] = ft.get(rt, 0) + 1
    heat = [{"resource_type": rt, "count": bt.get(rt, 0),
             "risks": ft.get(rt, 0)} for rt in set(bt) | set(ft)]
    return ok({"heatmap": heat})


# =========================================================================== #
# 10. 单步快速触发
# =========================================================================== #
@router.post("/step/discover")
def step_discover(provider: str = Body(default="aws"),
                  region: Optional[str] = Body(default=None)):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_asset_discovery_phase().discover(
            provider=provider, region=region).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/step/config")
def step_config(inventory: Optional[Dict[str, Any]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_config_check_phase().run(inventory or {}).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/step/risk")
def step_risk(findings: List[Dict[str, Any]] = Body(default_factory=list)):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_risk_rating_phase().rate(findings).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/step/vuln")
def step_vuln(inventory: Optional[Dict[str, Any]] = Body(default=None)):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_vuln_detect_phase().detect(inventory or {}))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/step/compliance")
def step_compliance(findings: List[Dict[str, Any]] = Body(default_factory=list)):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_compliance_audit_phase().audit(findings).to_dict())
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


# =========================================================================== #
# 11. WebSocket 实时推送
# =========================================================================== #
@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await _PUSH.connect(ws)
    try:
        await ws.send_json({"type": "hello",
                            "msg": "已连接云安全 Pro 实时推送通道"})
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        await _PUSH.disconnect(ws)
    except Exception:  # noqa: BLE001
        await _PUSH.disconnect(ws)
