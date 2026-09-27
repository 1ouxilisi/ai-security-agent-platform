# -*- coding: utf-8 -*-
"""
emerging_comm_security_routes.py - 新兴通信安全 REST API（第29轮 方向4）。

路由前缀：/api/v1/emerging-comm-security
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典模拟异步任务（task_id -> status/results）。
"""

from __future__ import annotations

import importlib
import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 第三方/本项目模块统一 try-import；模块名以数字开头（5g_security）必须用 importlib
try:
    _pkg = importlib.import_module("emerging_comm_security")
    _m5g = importlib.import_module("emerging_comm_security.5g_security")
    _mv2x = importlib.import_module("emerging_comm_security.v2x_security")
    _mveh = importlib.import_module("emerging_comm_security.vehicle_security")
    _mota = importlib.import_module("emerging_comm_security.ota_security")
    _mnew = importlib.import_module("emerging_comm_security.emerging_comm")
    _mdash = importlib.import_module("emerging_comm_security.emerging_comm_dashboard")
    _C5G = _m5g.get_5g_controller()
    _CV2X = _mv2x.get_v2x_controller()
    _CVEH = _mveh.get_vehicle_controller()
    _COTA = _mota.get_ota_controller()
    _CNEW = _mnew.get_emerging_comm_controller()
    _DASH = _mdash.get_dashboard()
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    import logging as _log
    _log.warning("emerging_comm_security_routes: 模块导入失败: %s", _e)
    _MODULES_OK = False
    _C5G = _CV2X = _CVEH = _COTA = _CNEW = _DASH = None  # type: ignore


router = APIRouter(prefix="/api/v1/emerging-comm-security",
                   tags=["新兴通信安全"])


# ==================== 响应工具 ====================

def _clean(obj: Any) -> Any:
    """递归清理控制字符，避免 JSON 序列化异常。"""
    if isinstance(obj, str):
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": str(err)})


# ==================== 内存任务存储 ====================
TASKS: Dict[str, Dict[str, Any]] = {}
HISTORY: List[Dict[str, Any]] = []


def _new_task(task_type: str) -> str:
    tid = f"ecs-{task_type}-{uuid.uuid4().hex[:10]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(),
    }
    return tid


def _run_and_store(task_id: str, func) -> None:
    try:
        TASKS[task_id]["status"] = "running"
        result = func()
        TASKS[task_id]["status"] = "success"
        TASKS[task_id]["result"] = result
    except Exception as e:  # pragma: no cover
        TASKS[task_id]["status"] = "failed"
        TASKS[task_id]["error"] = str(e)
    finally:
        TASKS[task_id]["finished_at"] = datetime.now().isoformat()
        HISTORY.insert(0, {"ts": datetime.now().isoformat(),
                            "task_id": task_id,
                            "status": TASKS[task_id]["status"]})
        if len(HISTORY) > 500:
            HISTORY.pop()


# ==================== 通用任务端点 ====================

@router.get("/tasks")
def list_tasks():
    try:
        return _ok({"tasks": list(TASKS.values())[-50:], "total": len(TASKS)})
    except Exception as e:
        return _fail(str(e))


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t)
    except Exception as e:
        return _fail(str(e))


@router.get("/history")
def history():
    try:
        return _ok({"history": HISTORY, "total": len(HISTORY)})
    except Exception as e:
        return _fail(str(e))


# ==================== 5G 核心网安全 ====================

@router.get("/5g/overview")
def five_g_overview():
    try:
        return _ok(_C5G.overview())
    except Exception as e:
        return _fail(str(e))


@router.get("/5g/nfs")
def five_g_list_nfs(nf_type: Optional[str] = None):
    try:
        return _ok({"nfs": _C5G.list_nfs(nf_type)})
    except Exception as e:
        return _fail(str(e))


@router.post("/5g/nfs/register")
def five_g_register_nf(payload: Dict[str, Any]):
    try:
        node = _C5G.register_nf(
            nf_type=payload.get("nf_type", "AMF"),
            name=payload.get("name", ""),
            address=payload.get("address", ""),
            port=int(payload.get("port", 8000)),
            slices=payload.get("slices"),
        )
        return _ok({"nf_id": node.nf_id, "status": node.status})
    except Exception as e:
        return _fail(str(e))


@router.delete("/5g/nfs/{nf_id}")
def five_g_deregister_nf(nf_id: str):
    try:
        ok = _C5G.deregister_nf(nf_id)
        return _ok({"nf_id": nf_id, "deregistered": ok})
    except Exception as e:
        return _fail(str(e))


@router.get("/5g/nf-discovery")
def five_g_nf_discovery(service: str, requester: str):
    try:
        return _ok({"hits": _C5G.nf_discovery(service, requester)})
    except Exception as e:
        return _fail(str(e))


@router.post("/5g/nf-subscribe")
def five_g_nf_subscribe(payload: Dict[str, Any]):
    try:
        return _ok(_C5G.nf_subscribe(
            payload["subscriber_nf"], payload["event"], payload["target_nf"]))
    except Exception as e:
        return _fail(str(e))


@router.post("/5g/nf-authorize")
def five_g_nf_authorize(payload: Dict[str, Any]):
    try:
        return _ok(_C5G.nf_authorize(payload["requester"], payload["target_service"]))
    except Exception as e:
        return _fail(str(e))


@router.post("/5g/subscriber/provision")
def five_g_provision(payload: Dict[str, Any]):
    try:
        sub = _C5G.provision_subscriber(payload["supi"], payload.get("slices"))
        return _ok({"supi": sub.supi, "suci": sub.suci,
                     "guti": sub.guti, "state": sub.state})
    except Exception as e:
        return _fail(str(e))


@router.get("/5g/subscribers")
def five_g_subscribers():
    try:
        return _ok({"subscribers": [
            {"supi": s.supi, "suci": s.suci, "guti": s.guti,
             "state": s.state, "auth_count": s.auth_count}
            for s in _C5G.subscribers.values()]})
    except Exception as e:
        return _fail(str(e))


@router.post("/5g/auth/aka")
def five_g_aka(payload: Dict[str, Any]):
    try:
        ev = _C5G.run_5g_aka(payload["supi"],
                              payload.get("serving_network_name", "5G:mcc001.mnc001"))
        return _ok(ev)
    except Exception as e:
        return _fail(str(e))


@router.post("/5g/auth/negotiate")
def five_g_negotiate(payload: Dict[str, Any]):
    try:
        return _ok(_C5G.negotiate_security_algorithms(
            payload.get("ue_pref_int", []), payload.get("ue_pref_enc", [])))
    except Exception as e:
        return _fail(str(e))


@router.get("/5g/slices")
def five_g_slices():
    try:
        return _ok({"slices": _C5G.list_slices()})
    except Exception as e:
        return _fail(str(e))


@router.post("/5g/slices/authorize")
def five_g_authorize_slice(payload: Dict[str, Any]):
    try:
        return _ok(_C5G.authorize_slice(payload["supi"], payload["s_nssai"]))
    except Exception as e:
        return _fail(str(e))


@router.post("/5g/slices/detect-cross")
def five_g_detect_cross(payload: Dict[str, Any]):
    try:
        return _ok(_C5G.detect_cross_slice_attack(payload))
    except Exception as e:
        return _fail(str(e))


@router.post("/5g/mec/apps")
def five_g_register_mec(payload: Dict[str, Any]):
    try:
        return _ok(_C5G.register_mec_app(
            payload["app_id"], payload["edge_site"], payload["owner"],
            payload["required_slice"]))
    except Exception as e:
        return _fail(str(e))


@router.get("/5g/mec/apps")
def five_g_list_mec():
    try:
        return _ok({"apps": _C5G.list_mec_apps()})
    except Exception as e:
        return _fail(str(e))


@router.get("/5g/auth-events")
def five_g_auth_events(limit: int = 20):
    try:
        return _ok({"events": _C5G.recent_auth_events(limit)})
    except Exception as e:
        return _fail(str(e))


# ==================== V2X 车联网安全 ====================

@router.get("/v2x/overview")
def v2x_overview():
    try:
        return _ok(_CV2X.overview())
    except Exception as e:
        return _fail(str(e))


@router.get("/v2x/nodes")
def v2x_list_nodes(node_type: Optional[str] = None):
    try:
        return _ok({"nodes": _CV2X.list_nodes(node_type)})
    except Exception as e:
        return _fail(str(e))


@router.post("/v2x/nodes/register")
def v2x_register_node(payload: Dict[str, Any]):
    try:
        n = _CV2X.register_node(payload.get("node_type", "OBU"),
                                  payload.get("region", ""))
        return _ok({"node_id": n.node_id, "pseudonym": n.pseudonym,
                     "cert_id": n.cert_id})
    except Exception as e:
        return _fail(str(e))


@router.post("/v2x/certs/issue")
def v2x_issue_cert(payload: Dict[str, Any]):
    try:
        return _ok(_CV2X.issue_pseudonym_cert(payload["real_id"]))
    except Exception as e:
        return _fail(str(e))


@router.post("/v2x/certs/revoke")
def v2x_revoke_cert(payload: Dict[str, Any]):
    try:
        ok = _CV2X.revoke_cert(payload["cert_id"], payload.get("reason", "compromised"))
        return _ok({"cert_id": payload["cert_id"], "revoked": ok})
    except Exception as e:
        return _fail(str(e))


@router.get("/v2x/certs/revoked")
def v2x_list_revoked():
    try:
        return _ok({"revoked": _CV2X.list_revoked()})
    except Exception as e:
        return _fail(str(e))


@router.post("/v2x/nodes/{node_id}/rotate")
def v2x_rotate(node_id: str):
    try:
        return _ok(_CV2X.rotate_pseudonym(node_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/v2x/messages/ingest")
def v2x_ingest(payload: Dict[str, Any]):
    try:
        return _ok(_CV2X.ingest_message(
            payload["msg_type"], payload["sender_pseudonym"],
            payload.get("payload", {}),
            signature=payload.get("signature", ""),
            signed_at=payload.get("signed_at")))
    except Exception as e:
        return _fail(str(e))


@router.get("/v2x/messages")
def v2x_messages(msg_type: Optional[str] = None, limit: int = 50):
    try:
        return _ok({"messages": _CV2X.list_messages(msg_type, limit)})
    except Exception as e:
        return _fail(str(e))


@router.get("/v2x/detect/flood")
def v2x_detect_flood(window_s: int = 10, threshold: int = 50):
    try:
        return _ok(_CV2X.detect_flood(window_s, threshold))
    except Exception as e:
        return _fail(str(e))


@router.post("/v2x/detect/position")
def v2x_detect_position(payload: Dict[str, Any]):
    try:
        return _ok(_CV2X.detect_spoofed_position(
            payload["node_id"], float(payload["lat"]), float(payload["lon"])))
    except Exception as e:
        return _fail(str(e))


@router.get("/v2x/privacy")
def v2x_privacy():
    try:
        return _ok(_CV2X.privacy_stats())
    except Exception as e:
        return _fail(str(e))


@router.get("/v2x/anomalies")
def v2x_anomalies(limit: int = 20):
    try:
        return _ok({"anomalies": _CV2X.recent_anomalies(limit)})
    except Exception as e:
        return _fail(str(e))


# ==================== 车载安全 ====================

@router.get("/vehicle/overview")
def vehicle_overview():
    try:
        return _ok(_CVEH.overview())
    except Exception as e:
        return _fail(str(e))


@router.get("/vehicle/vehicles")
def vehicle_list():
    try:
        return _ok({"vehicles": _CVEH.list_vehicles()})
    except Exception as e:
        return _fail(str(e))


@router.post("/vehicle/vehicles/register")
def vehicle_register(payload: Dict[str, Any]):
    try:
        v = _CVEH.register_vehicle(payload["vin"], payload.get("make", ""),
                                    payload.get("model", ""),
                                    int(payload.get("year", 2024)),
                                    payload.get("ecus"))
        return _ok({"vin": v.vin, "ecus": v.ecus})
    except Exception as e:
        return _fail(str(e))


@router.post("/vehicle/can/ingest")
def vehicle_can_ingest(payload: Dict[str, Any]):
    try:
        data_hex = payload.get("data_hex", "00")
        data = bytes.fromhex(data_hex) if isinstance(data_hex, str) else bytes(data_hex)
        return _ok(_CVEH.ingest_can_frame(int(payload["can_id"], 0), data,
                                            payload.get("src_ecu", "")))
    except Exception as e:
        return _fail(str(e))


@router.get("/vehicle/can/ids")
def vehicle_can_ids():
    try:
        return _ok({"ids": _CVEH.can_ids_seen()})
    except Exception as e:
        return _fail(str(e))


@router.post("/vehicle/can/replay")
def vehicle_can_replay(payload: Dict[str, Any]):
    try:
        data = bytes.fromhex(payload.get("data_hex", "00"))
        return _ok({"replay": _CVEH.detect_replay(int(payload["can_id"], 0), data)})
    except Exception as e:
        return _fail(str(e))


@router.post("/vehicle/cloud/session")
def vehicle_cloud_session(payload: Dict[str, Any]):
    try:
        return _ok(_CVEH.open_cloud_session(payload["vin"], payload["user"]))
    except Exception as e:
        return _fail(str(e))


@router.post("/vehicle/cloud/scan-command")
def vehicle_cloud_scan(payload: Dict[str, Any]):
    try:
        return _ok(_CVEH.scan_remote_command(payload["sid"], payload["command"]))
    except Exception as e:
        return _fail(str(e))


@router.post("/vehicle/apps/{app_id}/escalation")
def vehicle_escalation(app_id: str, payload: Dict[str, Any]):
    try:
        return _ok(_CVEH.detect_privilege_escalation(app_id, payload["requested"]))
    except Exception as e:
        return _fail(str(e))


@router.get("/vehicle/apps")
def vehicle_apps():
    try:
        return _ok({"apps": _CVEH.list_apps()})
    except Exception as e:
        return _fail(str(e))


@router.post("/vehicle/apps/register")
def vehicle_register_app(payload: Dict[str, Any]):
    try:
        a = _CVEH.register_app(payload["name"], payload.get("permissions", []),
                                payload.get("data_collection"))
        return _ok({"app_id": a.app_id, "name": a.name})
    except Exception as e:
        return _fail(str(e))


@router.get("/vehicle/data-inventory")
def vehicle_data_inventory():
    try:
        return _ok(_CVEH.data_inventory())
    except Exception as e:
        return _fail(str(e))


@router.get("/vehicle/threats")
def vehicle_threats(limit: int = 20):
    try:
        return _ok({"threats": _CVEH.recent_threats(limit)})
    except Exception as e:
        return _fail(str(e))


# ==================== OTA 安全 ====================

@router.get("/ota/stats")
def ota_stats():
    try:
        return _ok(_COTA.stats())
    except Exception as e:
        return _fail(str(e))


@router.get("/ota/firmware")
def ota_list_firmware(component: Optional[str] = None):
    try:
        return _ok({"firmware": _COTA.list_firmware(component)})
    except Exception as e:
        return _fail(str(e))


@router.post("/ota/firmware/publish")
def ota_publish(payload: Dict[str, Any]):
    try:
        fw = _COTA.publish_firmware(payload["version"], payload["component"],
                                     payload.get("differential_from", ""),
                                     payload.get("release_notes", ""))
        return _ok({"fw_id": fw.fw_id, "version": fw.version,
                     "component": fw.component, "signature": fw.signature})
    except Exception as e:
        return _fail(str(e))


@router.post("/ota/firmware/{fw_id}/verify")
def ota_verify(fw_id: str):
    try:
        return _ok(_COTA.verify_firmware(fw_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/ota/install")
def ota_install(payload: Dict[str, Any]):
    try:
        t = _COTA.start_install(payload["vin"], payload["fw_id"],
                                  bool(payload.get("user_consent", True)))
        return _ok({"task_id": t.task_id, "status": t.status})
    except Exception as e:
        return _fail(str(e))


@router.post("/ota/install/{task_id}/step")
def ota_step(task_id: str, payload: Dict[str, Any]):
    try:
        t = _COTA.advance_install(task_id, payload["step"])
        return _ok({"task_id": t.task_id, "status": t.status,
                     "progress": t.progress})
    except Exception as e:
        return _fail(str(e))


@router.post("/ota/install/{task_id}/finish")
def ota_finish(task_id: str, payload: Dict[str, Any]):
    try:
        t = _COTA.finish_install(task_id, bool(payload.get("success", True)),
                                   payload.get("error", ""))
        return _ok({"task_id": t.task_id, "status": t.status,
                     "progress": t.progress})
    except Exception as e:
        return _fail(str(e))


@router.post("/ota/install/{task_id}/rollback")
def ota_rollback(task_id: str):
    try:
        t = _COTA.rollback(task_id)
        return _ok({"task_id": t.task_id, "status": t.status})
    except Exception as e:
        return _fail(str(e))


@router.post("/ota/detect/replay")
def ota_detect_replay(payload: Dict[str, Any]):
    try:
        return _ok({"replay": _COTA.detect_replay(payload["fw_id"],
                                                    float(payload["prev_seen_at"]))})
    except Exception as e:
        return _fail(str(e))


@router.post("/ota/tamper-scan")
def ota_tamper(payload: Dict[str, Any]):
    try:
        return _ok(_COTA.tamper_scan(payload["fw_id"],
                                       bool(payload.get("tampered", False))))
    except Exception as e:
        return _fail(str(e))


@router.get("/ota/tasks")
def ota_tasks(limit: int = 50):
    try:
        return _ok({"tasks": _COTA.list_tasks(limit)})
    except Exception as e:
        return _fail(str(e))


@router.get("/ota/violations")
def ota_violations(limit: int = 20):
    try:
        return _ok({"violations": _COTA.recent_violations(limit)})
    except Exception as e:
        return _fail(str(e))


# ==================== 新兴通信（卫星 / 低空 / 工业 / IoT / 边缘 / 量子） ====================

@router.get("/emerging/overview")
def emerging_overview():
    try:
        return _ok(_CNEW.overview())
    except Exception as e:
        return _fail(str(e))


@router.get("/emerging/satellites")
def emerging_satellites():
    try:
        return _ok({"satellites": _CNEW.list_satellites()})
    except Exception as e:
        return _fail(str(e))


@router.post("/emerging/satellites/handover")
def emerging_handover(payload: Dict[str, Any]):
    try:
        return _ok(_CNEW.handover(payload["sat_id"], payload["target_sat"]))
    except Exception as e:
        return _fail(str(e))


@router.get("/emerging/anti-jam")
def emerging_anti_jam():
    try:
        return _ok(_CNEW.anti_jam_report())
    except Exception as e:
        return _fail(str(e))


@router.post("/emerging/drones/register")
def emerging_register_drone(payload: Dict[str, Any]):
    try:
        d = _CNEW.register_drone(payload["operator"],
                                  float(payload["lat"]),
                                  float(payload["lon"]),
                                  float(payload.get("alt_m", 120)))
        return _ok({"drone_id": d.drone_id, "no_fly": d.no_fly_zone})
    except Exception as e:
        return _fail(str(e))


@router.get("/emerging/drones")
def emerging_list_drones():
    try:
        return _ok({"drones": _CNEW.list_drones()})
    except Exception as e:
        return _fail(str(e))


@router.post("/emerging/drones/{drone_id}/detect")
def emerging_detect_drone(drone_id: str):
    try:
        return _ok(_CNEW.detect_rogue_drone(drone_id))
    except Exception as e:
        return _fail(str(e))


@router.get("/emerging/industrial")
def emerging_industrial():
    try:
        return _ok({"assets": _CNEW.list_industrial()})
    except Exception as e:
        return _fail(str(e))


@router.get("/emerging/industrial/audit")
def emerging_industrial_audit():
    try:
        return _ok(_CNEW.segment_audit())
    except Exception as e:
        return _fail(str(e))


@router.post("/emerging/iot/provision")
def emerging_provision_iot(payload: Dict[str, Any]):
    try:
        n = _CNEW.provision_iot(payload["proto"], payload["tenant"])
        return _ok({"dev_eui": n.dev_eui, "proto": n.proto})
    except Exception as e:
        return _fail(str(e))


@router.get("/emerging/iot")
def emerging_list_iot(proto: Optional[str] = None):
    try:
        return _ok({"nodes": _CNEW.list_iot(proto)})
    except Exception as e:
        return _fail(str(e))


@router.post("/emerging/iot/{dev_eui}/auth")
def emerging_iot_auth(dev_eui: str, payload: Dict[str, Any]):
    try:
        return _ok(_CNEW.lightweight_auth(dev_eui, payload["nonce"]))
    except Exception as e:
        return _fail(str(e))


@router.post("/emerging/edge/{edge_id}/apps")
def emerging_edge_app(edge_id: str, payload: Dict[str, Any]):
    try:
        e = _CNEW.register_edge_app(edge_id, payload["app"])
        return _ok({"edge_id": e.edge_id, "apps": e.apps})
    except Exception as e:
        return _fail(str(e))


@router.get("/emerging/edge")
def emerging_edge_list():
    try:
        return _ok({"edges": _CNEW.list_edge()})
    except Exception as e:
        return _fail(str(e))


@router.post("/emerging/quantum/{link_id}/distribute")
def emerging_quantum_distribute(link_id: str, payload: Dict[str, Any]):
    try:
        return _ok(_CNEW.distribute_qkey(link_id, int(payload.get("bits", 256))))
    except Exception as e:
        return _fail(str(e))


@router.get("/emerging/quantum")
def emerging_quantum_list():
    try:
        return _ok({"links": _CNEW.list_quantum()})
    except Exception as e:
        return _fail(str(e))


@router.get("/emerging/pqc-readiness")
def emerging_pqc():
    try:
        return _ok(_CNEW.pqc_readiness())
    except Exception as e:
        return _fail(str(e))


@router.get("/emerging/alerts")
def emerging_alerts(limit: int = 20):
    try:
        return _ok({"alerts": _CNEW.recent_alerts(limit)})
    except Exception as e:
        return _fail(str(e))


# ==================== 控制台聚合 ====================

@router.get("/dashboard/overview")
def dashboard_overview():
    try:
        return _ok(_DASH.overview())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/health")
def dashboard_health():
    try:
        return _ok(_DASH.health_score())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/risk")
def dashboard_risk():
    try:
        return _ok(_DASH.risk_score())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/events")
def dashboard_events(limit: int = 50):
    try:
        return _ok({"events": _DASH.unified_events(limit)})
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/settings")
def dashboard_settings():
    try:
        return _ok(_DASH.settings())
    except Exception as e:
        return _fail(str(e))
