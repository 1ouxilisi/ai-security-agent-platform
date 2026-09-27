# -*- coding: utf-8 -*-
"""
iot_ot_pro_routes.py — 方向3 工控IoT Pro REST API（50+ 端点 + WebSocket）。

路由前缀: /api/v1/iot-ot-pro
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

router = APIRouter(prefix="/api/v1/iot-ot-pro",
                   tags=["IotOtPro-方向3"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from iot_ot_pro import (
        get_orchestrator, get_dashboard, get_realtime_push,
        get_device_discovery_phase, get_protocol_analysis_phase,
        get_firmware_analysis_phase, get_vuln_detection_phase,
        get_config_audit_phase, get_traffic_monitor_phase,
        get_risk_rating_phase, get_compliance_audit_phase,
        get_ai_analysis, get_report_generator, STAGES, REPORTS_DIR,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _RT = get_realtime_push()
    _DISC = get_device_discovery_phase()
    _PA = get_protocol_analysis_phase()
    _FW = get_firmware_analysis_phase()
    _VULN = get_vuln_detection_phase()
    _CFG = get_config_audit_phase()
    _TRAF = get_traffic_monitor_phase()
    _RISK = get_risk_rating_phase()
    _COMP = get_compliance_audit_phase()
    _AI = get_ai_analysis()
    _REP = get_report_generator()
    _MOD_AVAILABLE = True
    logger.info("iot_ot_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("iot_ot_pro_routes: load failed: %s", e)
    _ORCH = _DASH = _RT = None  # type: ignore
    _DISC = _PA = _FW = _VULN = _CFG = None  # type: ignore
    _TRAF = _RISK = _COMP = _AI = _REP = None  # type: ignore


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
        return fail("工控IoT Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 任务管理（八阶段一键全流程）
# =========================================================================== #
@router.post("/start")
def start_iotot(name: str = Body("工控IoT 全流程评估", embed=True)):
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
# 1. 阶段1 设备发现
# =========================================================================== #
@router.get("/discovery/devices")
def disc_devices(device_type: Optional[str] = Query(None),
                 vendor: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"devices": _DISC.list_devices(device_type, vendor)})


@router.get("/discovery/devices/{device_id}")
def disc_device(device_id: str):
    g = _guard()
    if g:
        return g
    d = _DISC.get_device(device_id)
    if d is None:
        return fail("device not found", 404)
    return ok(d)


@router.put("/discovery/devices/{device_id}")
def disc_update(device_id: str, payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    d = _DISC.update_device(device_id, **payload)
    if d is None:
        return fail("device not found", 404)
    return ok(d)


@router.post("/discovery/scan")
def disc_scan(cidr: str = Body("192.168.10.0/24", embed=True),
              real: bool = Body(False, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_DISC.start_discovery(cidr, real=real))


@router.post("/discovery/scan-host")
def disc_scan_host(ip: str = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_DISC.scan_host(ip))


@router.get("/discovery/tasks")
def disc_tasks():
    g = _guard()
    if g:
        return g
    return ok({"tasks": _DISC.list_tasks()})


@router.get("/discovery/stats")
def disc_stats():
    g = _guard()
    if g:
        return g
    return ok(_DISC.stats())


@router.get("/discovery/tools")
def disc_tools():
    g = _guard()
    if g:
        return g
    return ok(_DISC.tool_status())


@router.get("/discovery/protocols")
def disc_protocols():
    g = _guard()
    if g:
        return g
    return ok(_DISC.protocol_ports_reference())


# =========================================================================== #
# 2. 阶段2 协议分析
# =========================================================================== #
@router.post("/protocol/modbus")
def pa_modbus(ip: str = Body(...), port: int = Body(502)):
    g = _guard()
    if g:
        return g
    return ok(_PA.analyze_modbus(ip, port))


@router.post("/protocol/s7")
def pa_s7(ip: str = Body(...), port: int = Body(102)):
    g = _guard()
    if g:
        return g
    return ok(_PA.analyze_s7(ip, port))


@router.post("/protocol/mqtt")
def pa_mqtt(ip: str = Body(...), port: int = Body(1883)):
    g = _guard()
    if g:
        return g
    return ok(_PA.analyze_mqtt(ip, port))


@router.post("/protocol/coap")
def pa_coap(ip: str = Body(...), port: int = Body(5683)):
    g = _guard()
    if g:
        return g
    return ok(_PA.analyze_coap(ip, port))


@router.post("/protocol/ssdp-mdns")
def pa_ssdp(ip: str = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_PA.analyze_ssdp_mdns(ip))


@router.post("/protocol/dnp3")
def pa_dnp3(ip: str = Body(...), port: int = Body(20000)):
    g = _guard()
    if g:
        return g
    return ok(_PA.analyze_dnp3(ip, port))


@router.post("/protocol/bacnet")
def pa_bacnet(ip: str = Body(...), port: int = Body(47808)):
    g = _guard()
    if g:
        return g
    return ok(_PA.analyze_bacnet(ip, port))


@router.post("/protocol/opcua")
def pa_opcua(ip: str = Body(...), port: int = Body(4840)):
    g = _guard()
    if g:
        return g
    return ok(_PA.analyze_opcua(ip, port))


@router.post("/protocol/auto")
def pa_auto():
    g = _guard()
    if g:
        return g
    return ok(_PA.auto_analyze())


@router.get("/protocol/findings")
def pa_findings(protocol: Optional[str] = Query(None),
                severity: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"findings": _PA.list_findings(protocol, severity)})


@router.get("/protocol/stats")
def pa_stats():
    g = _guard()
    if g:
        return g
    return ok(_PA.stats())


@router.get("/protocol/reference")
def pa_ref():
    g = _guard()
    if g:
        return g
    return ok(_PA.protocol_reference())


# =========================================================================== #
# 3. 阶段3 固件分析
# =========================================================================== #
@router.post("/firmware/extract")
def fw_extract(path: str = Body("demo.bin", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_FW.extract_firmware(path))


@router.post("/firmware/creds")
def fw_creds(root: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    return ok({"findings": _FW.scan_hardcoded_creds(root)})


@router.post("/firmware/vuln-funcs")
def fw_vfuncs(root: str = Body("", embed=True)):
    g = _guard()
    if g:
        return g
    return ok({"findings": _FW.scan_vuln_functions(root)})


@router.get("/firmware/cve")
def fw_cve(product: str = Query(""), version: str = Query("")):
    g = _guard()
    if g:
        return g
    return ok({"cves": _FW.match_cve(product, version)})


@router.get("/firmware/default-creds")
def fw_default():
    g = _guard()
    if g:
        return g
    return ok({"creds": _FW.default_credential_check()})


@router.post("/firmware/analyze-all")
def fw_all(path: str = Body("demo.bin", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_FW.analyze_all(path))


@router.get("/firmware/findings")
def fw_findings():
    g = _guard()
    if g:
        return g
    return ok({"findings": _FW.list_findings()})


@router.get("/firmware/stats")
def fw_stats():
    g = _guard()
    if g:
        return g
    return ok(_FW.stats())


@router.get("/firmware/tools")
def fw_tools():
    g = _guard()
    if g:
        return g
    return ok(_FW.tool_status())


# =========================================================================== #
# 4. 阶段4 漏洞检测
# =========================================================================== #
@router.post("/vuln/detect")
def vuln_detect(targets: Optional[List[Dict[str, Any]]] = Body(None)):
    g = _guard()
    if g:
        return g
    return ok(_VULN.detect(targets))


@router.get("/vuln/list")
def vuln_list(scope: Optional[str] = Query(None),
              severity: Optional[str] = Query(None),
              status: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"vulns": _VULN.list_vulns(scope, severity, status)})


@router.get("/vuln/{vuln_id}")
def vuln_detail(vuln_id: str):
    g = _guard()
    if g:
        return g
    v = _VULN.get_vuln(vuln_id)
    if v is None:
        return fail("vuln not found", 404)
    return ok(v)


@router.post("/vuln/{vuln_id}/status")
def vuln_status(vuln_id: str, status: str = Body(...),
                note: str = Body("")):
    g = _guard()
    if g:
        return g
    r = _VULN.update_status(vuln_id, status, note)
    if r is None:
        return fail("invalid status or vuln not found")
    return ok(r)


@router.get("/vuln/stats")
def vuln_stats():
    g = _guard()
    if g:
        return g
    return ok(_VULN.stats())


@router.get("/vuln/trend")
def vuln_trend(days: int = Query(7)):
    g = _guard()
    if g:
        return g
    return ok({"trend": _VULN.trend(days)})


@router.get("/vuln/reference")
def vuln_ref():
    g = _guard()
    if g:
        return g
    return ok(_VULN.check_reference())


# =========================================================================== #
# 5. 阶段5 配置审计
# =========================================================================== #
@router.post("/config/audit")
def cfg_audit(devices: Optional[List[Dict[str, Any]]] = Body(None)):
    g = _guard()
    if g:
        return g
    return ok(_CFG.audit_all(devices))


@router.get("/config/findings")
def cfg_findings(device: Optional[str] = Query(None),
                 status: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"findings": _CFG.list_findings(device, status)})


@router.get("/config/stats")
def cfg_stats():
    g = _guard()
    if g:
        return g
    return ok(_CFG.stats())


@router.get("/config/tools")
def cfg_tools():
    g = _guard()
    if g:
        return g
    return ok(_CFG.tool_status())


@router.get("/config/domains")
def cfg_domains():
    g = _guard()
    if g:
        return g
    return ok(_CFG.domains_reference())


# =========================================================================== #
# 6. 阶段6 流量监控
# =========================================================================== #
@router.post("/traffic/start")
def traf_start(duration: int = Body(30, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_TRAF.start_live(duration))


@router.post("/traffic/stop")
def traf_stop():
    g = _guard()
    if g:
        return g
    return ok(_TRAF.stop())


@router.post("/traffic/baseline")
def traf_baseline(hours: int = Body(24, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_TRAF.build_baseline(hours))


@router.post("/traffic/detect")
def traf_detect(n: int = Body(20, embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_TRAF.quick_detect(n))


@router.get("/traffic/alerts")
def traf_alerts(scope: Optional[str] = Query(None),
                severity: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"alerts": _TRAF.list_alerts(scope, severity)})


@router.post("/traffic/alerts/{alert_id}/status")
def traf_alert_status(alert_id: str, status: str = Body(...)):
    g = _guard()
    if g:
        return g
    r = _TRAF.update_alert(alert_id, status)
    if r is None:
        return fail("alert not found", 404)
    return ok(r)


@router.get("/traffic/flow")
def traf_flow(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"flow": _TRAF.recent_flow(limit)})


@router.get("/traffic/stats")
def traf_stats():
    g = _guard()
    if g:
        return g
    return ok(_TRAF.stats())


@router.get("/traffic/tools")
def traf_tools():
    g = _guard()
    if g:
        return g
    return ok(_TRAF.tool_status())


# =========================================================================== #
# 7. 阶段7 风险评级
# =========================================================================== #
@router.post("/risk/score")
def risk_score(device: str = Body(...), device_type: str = Body("PLC"),
               vuln_severities: List[str] = Body(default=["high"]),
               network_location: str = Body("管理网"),
               business: str = Body("重要生产"),
               exploit_difficulty: str = Body("中"),
               exposure: str = Body("内网暴露"),
               open_vuln_count: int = Body(1)):
    g = _guard()
    if g:
        return g
    return ok(_RISK.score_device(
        device, device_type, vuln_severities, network_location,
        business, exploit_difficulty, exposure, open_vuln_count))


@router.post("/risk/auto")
def risk_auto():
    g = _guard()
    if g:
        return g
    return ok(_RISK.auto_score())


@router.get("/risk/top")
def risk_top(n: int = Query(10)):
    g = _guard()
    if g:
        return g
    return ok({"top": _RISK.top_risks(n)})


@router.get("/risk/matrix")
def risk_matrix():
    g = _guard()
    if g:
        return g
    return ok(_RISK.risk_matrix())


@router.get("/risk/maturity")
def risk_maturity():
    g = _guard()
    if g:
        return g
    return ok(_RISK.maturity())


@router.get("/risk/trend")
def risk_trend(days: int = Query(14)):
    g = _guard()
    if g:
        return g
    return ok({"trend": _RISK.trend(days)})


@router.get("/risk/stats")
def risk_stats():
    g = _guard()
    if g:
        return g
    return ok(_RISK.stats())


# =========================================================================== #
# 8. 阶段8 合规审计
# =========================================================================== #
@router.post("/compliance/run")
def comp_run():
    g = _guard()
    if g:
        return g
    return ok(_COMP.run_audit())


@router.get("/compliance/items")
def comp_items(standard: Optional[str] = Query(None),
               status: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"items": _COMP.list_items(standard, status)})


@router.post("/compliance/items/{item_id}/status")
def comp_item_status(item_id: str, status: str = Body(...),
                     note: str = Body("")):
    g = _guard()
    if g:
        return g
    r = _COMP.update_item(item_id, status, note)
    if r is None:
        return fail("invalid status or item not found")
    return ok(r)


@router.get("/compliance/summary")
def comp_summary():
    g = _guard()
    if g:
        return g
    return ok(_COMP.summary())


@router.get("/compliance/standards")
def comp_standards():
    g = _guard()
    if g:
        return g
    return ok(_COMP.standards_reference())


# =========================================================================== #
# 9. AI 分析
# =========================================================================== #
@router.post("/ai/device")
def ai_device(device: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    vulns = _VULN.list_vulns()
    return ok(_AI.analyze_device(
        device, [v for v in vulns
                 if device.get("ip", "") in v.get("target", "")]))


@router.post("/ai/traffic")
def ai_traffic():
    g = _guard()
    if g:
        return g
    return ok(_AI.analyze_traffic(_TRAF.list_alerts()))


@router.post("/ai/compliance")
def ai_compliance():
    g = _guard()
    if g:
        return g
    return ok(_AI.compliance_risk_alert(_COMP.summary()))


@router.post("/ai/overview")
def ai_overview():
    g = _guard()
    if g:
        return g
    return ok(_AI.batch_overview(
        _DISC.list_devices(), _VULN.list_vulns(),
        _TRAF.list_alerts(), _COMP.summary()))


@router.get("/ai/history")
def ai_history(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"history": _AI.history(limit)})


# =========================================================================== #
# 10. 工控 IoT 大屏仪表盘
# =========================================================================== #
@router.get("/dashboard/kpi")
def dash_kpi():
    g = _guard()
    if g:
        return g
    return ok(_DASH.kpi())


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


@router.get("/dashboard/devices")
def dash_devices():
    g = _guard()
    if g:
        return g
    return ok(_DASH.device_distribution())


@router.get("/dashboard/protocols")
def dash_protocols():
    g = _guard()
    if g:
        return g
    return ok(_DASH.protocol_distribution())


@router.get("/dashboard/vuln-trend")
def dash_trend(window: str = Query("7d")):
    g = _guard()
    if g:
        return g
    return ok({"series": _DASH.vuln_trend(window)})


@router.get("/dashboard/risk-heatmap")
def dash_heatmap():
    g = _guard()
    if g:
        return g
    return ok({"heatmap": _DASH.risk_heatmap()})


@router.get("/dashboard/top-risks")
def dash_top(n: int = Query(10)):
    g = _guard()
    if g:
        return g
    return ok({"top": _DASH.top_risks(n)})


@router.get("/dashboard/recent-alerts")
def dash_alerts(limit: int = Query(20)):
    g = _guard()
    if g:
        return g
    return ok({"alerts": _DASH.recent_alerts(limit)})


# =========================================================================== #
# 11. 报告生成
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
# 12. WebSocket 实时推送
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_endpoint(websocket: WebSocket, task_id: str):
    """实时推送进度/日志/思考/设备/漏洞/告警/结果。"""
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
