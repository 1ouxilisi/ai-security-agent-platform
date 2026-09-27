# -*- coding: utf-8 -*-
"""
wireless_security_routes.py - 无线网络安全 REST API（第12轮深化模块）。

路由前缀：/api/v1/wireless-security
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典模拟异步任务（task_id -> status/results）。

合法边界：仅对授权网络进行安全评估，提供检测报告与加固建议，
不实际破解密码、不注入流量、不进行中间人攻击。
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from wireless_security.wifi_scanner import WiFiScanner
    from wireless_security.wifi_security import WiFiSecurityAssessor, WEAK_PASSWORD_DICTIONARY
    from wireless_security.evil_twin_detector import EvilTwinDetector
    from wireless_security.bluetooth_security import BluetoothSecurityAnalyzer
    from wireless_security.zigbee_security import ZigbeeSecurityAnalyzer
    from wireless_security.spectrum_analyzer import SpectrumAnalyzer
    from wireless_security.wireless_assessment_workflow import WirelessAssessmentWorkflow
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    import logging as _log
    _log.warning("wireless_security_routes: 模块导入失败: %s", _e)
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/wireless-security", tags=["无线网络安全"])


# ==================== 响应工具 ====================

def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": data, "error": err})


# ==================== 内存任务存储 ====================
TASKS: Dict[str, Dict[str, Any]] = {}
HISTORY: List[Dict[str, Any]] = []


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(),
    }
    return tid


def _run_and_store(task_id: str, func) -> None:
    """同步执行并写回任务结果（同步路径即可，避免依赖异步事件循环）。"""
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


# ==================== 共享数据（进程内） ====================
_SHARED: Dict[str, Any] = {}


def _get_scanner() -> WiFiScanner:
    if "scanner" not in _SHARED:
        _SHARED["scanner"] = WiFiScanner()
    return _SHARED["scanner"]


# ==================== WiFi 扫描 ====================

@router.post("/wifi/scan")
def wifi_scan(duration: int = 10, interface: str = "wlan0"):
    """启动 WiFi 扫描任务。"""
    try:
        tid = _new_task("wifi-scan")
        scanner = _get_scanner()
        aps = scanner.scan(duration=duration) if hasattr(scanner, "scan") else []
        _run_and_store(tid, lambda: {"aps": aps, "report": scanner.scan_report()})
        return _ok({"task_id": tid, "aps_count": len(aps)})
    except Exception as e:
        return _fail(str(e))


@router.get("/wifi/{task_id}/status")
def wifi_scan_status(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(str(e))


@router.get("/wifi/{task_id}/results")
def wifi_scan_results(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/wifi/aps")
def wifi_list_aps():
    try:
        return _ok({"aps": list(_get_scanner().aps.values())})
    except Exception as e:
        return _fail(str(e))


@router.get("/wifi/aps/{bssid}/detail")
def wifi_ap_detail(bssid: str):
    try:
        scanner = _get_scanner()
        ap = scanner.aps.get(bssid)
        if not ap:
            return _fail("AP not found")
        detail = {
            "ap": ap,
            "wps": scanner.detect_wps(bssid),
            "fingerprint": scanner.fingerprint(bssid),
        }
        return _ok(detail)
    except Exception as e:
        return _fail(str(e))


@router.get("/wifi/clients")
def wifi_clients():
    try:
        return _ok({"clients": _get_scanner().list_clients()})
    except Exception as e:
        return _fail(str(e))


# ==================== WiFi 安全评估 ====================

@router.post("/wifi/security/assess")
def wifi_security_assess():
    try:
        tid = _new_task("wifi-security")
        assessor = WiFiSecurityAssessor(_get_scanner())
        _run_and_store(tid, lambda: assessor.report())
        return _ok({"task_id": tid})
    except Exception as e:
        return _fail(str(e))


@router.get("/wifi/security/{task_id}/status")
def wifi_security_status(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(str(e))


@router.get("/wifi/security/{task_id}/results")
def wifi_security_results(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/wifi/security/{task_id}/report")
def wifi_security_report(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/wifi/security/dictionary")
def wifi_security_dictionary():
    try:
        return _ok({
            "size": len(WEAK_PASSWORD_DICTIONARY),
            "sample": WEAK_PASSWORD_DICTIONARY[:50],
            "note": "仅用于离线风险评估，不进行实际破解",
        })
    except Exception as e:
        return _fail(str(e))


# ==================== 邪恶孪生检测 ====================

@router.post("/evil-twin/detect")
def evil_twin_detect():
    try:
        tid = _new_task("evil-twin")
        detector = EvilTwinDetector(_get_scanner())
        _run_and_store(tid, detector.detect)
        return _ok({"task_id": tid})
    except Exception as e:
        return _fail(str(e))


@router.get("/evil-twin/{task_id}/status")
def evil_twin_status(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(str(e))


@router.get("/evil-twin/{task_id}/results")
def evil_twin_results(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/evil-twin/{task_id}/report")
def evil_twin_report(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


# ==================== 蓝牙安全 ====================

@router.post("/bluetooth/scan")
def bluetooth_scan(duration: int = 8):
    try:
        tid = _new_task("bluetooth")
        analyzer = BluetoothSecurityAnalyzer()
        devices = analyzer.discover(duration=duration)
        _run_and_store(tid, analyzer.report)
        return _ok({"task_id": tid, "devices": len(devices)})
    except Exception as e:
        return _fail(str(e))


@router.get("/bluetooth/{task_id}/status")
def bluetooth_status(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(str(e))


@router.get("/bluetooth/{task_id}/results")
def bluetooth_results(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/bluetooth/{task_id}/report")
def bluetooth_report(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/bluetooth/devices")
def bluetooth_devices():
    try:
        # 重新跑一次发现（轻量）
        analyzer = BluetoothSecurityAnalyzer()
        devs = analyzer.discover()
        return _ok({"devices": devs})
    except Exception as e:
        return _fail(str(e))


# ==================== Zigbee 安全 ====================

@router.post("/zigbee/scan")
def zigbee_scan():
    try:
        tid = _new_task("zigbee")
        analyzer = ZigbeeSecurityAnalyzer()
        _run_and_store(tid, analyzer.analyze)
        return _ok({"task_id": tid})
    except Exception as e:
        return _fail(str(e))


@router.get("/zigbee/{task_id}/status")
def zigbee_status(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(str(e))


@router.get("/zigbee/{task_id}/results")
def zigbee_results(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/zigbee/{task_id}/report")
def zigbee_report(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


# ==================== 频谱分析 ====================

@router.post("/spectrum/analyze")
def spectrum_analyze():
    try:
        tid = _new_task("spectrum")
        analyzer = SpectrumAnalyzer()
        _run_and_store(tid, analyzer.analyze)
        return _ok({"task_id": tid})
    except Exception as e:
        return _fail(str(e))


@router.get("/spectrum/{task_id}/status")
def spectrum_status(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(str(e))


@router.get("/spectrum/{task_id}/results")
def spectrum_results(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/spectrum/{task_id}/report")
def spectrum_report(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


# ==================== 综合评估 ====================

@router.post("/assessment/run")
def assessment_run():
    try:
        tid = _new_task("assessment")
        workflow = WirelessAssessmentWorkflow()
        _run_and_store(tid, workflow.run)
        HISTORY.insert(0, {
            "task_id": tid, "type": "assessment",
            "created_at": datetime.now().isoformat(),
        })
        return _ok({"task_id": tid})
    except Exception as e:
        return _fail(str(e))


@router.get("/assessment/{task_id}/status")
def assessment_status(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok({"task_id": task_id, "status": t["status"], "error": t.get("error")})
    except Exception as e:
        return _fail(str(e))


@router.get("/assessment/{task_id}/results")
def assessment_results(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/assessment/{task_id}/report")
def assessment_report(task_id: str):
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("task not found")
        return _ok(t.get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/assessment/history")
def assessment_history():
    try:
        return _ok({"history": HISTORY, "total": len(HISTORY)})
    except Exception as e:
        return _fail(str(e))


# ==================== 健康检查 ====================

@router.get("/health")
def health():
    return _ok({
        "status": "ok",
        "modules_loaded": _MODULES_OK,
        "active_tasks": len(TASKS),
        "timestamp": datetime.now().isoformat(),
        "legal_boundary": "仅对授权网络做评估，不实际破解/注入/中间人",
    })


__all__ = ["router"]
