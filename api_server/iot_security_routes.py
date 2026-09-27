# -*- coding: utf-8 -*-
"""
iot_security_routes.py — IoT安全 REST API（第12轮深化模块）。

路由前缀：/api/v1/iot-security
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典模拟异步任务（task_id -> status/results）。
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

try:
    from iot_security.device_discovery import get_device_discovery
    from iot_security.firmware_analyzer import get_firmware_analyzer
    from iot_security.protocol_security import get_protocol_analyzer
    from iot_security.default_credentials import get_credential_detector
    from iot_security.communication_security import get_communication_analyzer
    from iot_security.vulnerability_detector import get_vulnerability_detector
    from iot_security.iot_assessment_workflow import get_assessment_workflow
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("iot_security_routes: 模块导入失败: %s", _e)
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/iot-security", tags=["IoT安全"])


# ==================== 响应工具 ====================

def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": data, "error": err})


# ==================== 内存任务存储 ====================

TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(),
    }
    return tid


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return TASKS.get(task_id)


def _run_task(task_type: str, func, *args, **kwargs) -> str:
    """同步执行任务（演示用，实际可改为异步）"""
    tid = _new_task(task_type)
    TASKS[tid]["status"] = "running"
    try:
        result = func(*args, **kwargs)
        TASKS[tid]["status"] = "success"
        TASKS[tid]["result"] = result
    except Exception as e:
        TASKS[tid]["status"] = "failed"
        TASKS[tid]["error"] = str(e)
    return tid


# ==================== 请求模型 ====================

class DiscoveryScanReq(BaseModel):
    target: str = "192.168.1.0/24"
    ports: Optional[List[int]] = None
    passive: bool = False
    interface: str = "eth0"
    duration: int = 10


class FirmwareAnalyzeReq(BaseModel):
    firmware_path: str = ""
    vendor_hint: str = ""


class ProtocolAnalyzeReq(BaseModel):
    target: str = "192.168.1.1"
    protocols: Optional[List[str]] = None


class CredentialCheckReq(BaseModel):
    target: str = "192.168.1.1"
    vendor: str = ""
    device_type: str = "未知"
    ports: Optional[List[int]] = None


class CommunicationAnalyzeReq(BaseModel):
    target: str = "192.168.1.1"
    ports: Optional[List[int]] = None


class VulnerabilityScanReq(BaseModel):
    target: str = "192.168.1.1"
    vendor: str = ""
    device_type: str = "未知"
    ports: Optional[List[int]] = None
    firmware_version: str = ""


class AssessmentRunReq(BaseModel):
    target: str = "192.168.1.0/24"
    skip_discovery: bool = False
    skip_protocol: bool = False
    skip_credentials: bool = False
    skip_communication: bool = False
    skip_firmware: bool = False
    skip_vulnerability: bool = False
    firmware_path: str = ""


# ==================== 设备发现 API ====================

@router.post("/discovery/scan")
def discovery_scan(req: DiscoveryScanReq):
    """启动IoT设备发现扫描任务"""
    try:
        if not _MODULES_OK:
            return _fail("IoT安全模块未正确加载", {"task_id": None})
        disc = get_device_discovery()
        if req.passive:
            result = disc.passive_listen(req.interface, req.duration)
        else:
            result = disc.active_scan(req.target, req.ports)
        tid = _run_task("discovery", lambda: result)
        return _ok({"task_id": tid, "message": "扫描任务已启动"})
    except Exception as e:
        return _fail(f"扫描启动失败: {e}")


@router.get("/discovery/{task_id}/status")
def discovery_status(task_id: str):
    """查询设备发现任务状态"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/discovery/{task_id}/results")
def discovery_results(task_id: str):
    """获取设备发现任务结果"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成，当前状态: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/devices/list")
def devices_list():
    """获取已发现设备列表"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        disc = get_device_discovery()
        return _ok({"devices": disc.list_devices(), "statistics": disc.statistics()})
    except Exception as e:
        return _fail(f"获取设备列表失败: {e}")


@router.get("/devices/{device_ip}/detail")
def device_detail(device_ip: str):
    """获取设备详细信息"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        disc = get_device_discovery()
        d = disc.get_device(device_ip)
        if not d:
            return _fail("设备不存在")
        return _ok(d)
    except Exception as e:
        return _fail(f"获取设备详情失败: {e}")


@router.get("/devices/export")
def devices_export():
    """导出设备列表"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        disc = get_device_discovery()
        return _ok({
            "export_time": datetime.now().isoformat(),
            "total": len(disc.list_devices()),
            "devices": disc.list_devices(),
        })
    except Exception as e:
        return _fail(f"导出失败: {e}")


# ==================== 固件分析 API ====================

@router.post("/firmware/analyze")
def firmware_analyze(req: FirmwareAnalyzeReq):
    """启动固件分析任务"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        analyzer = get_firmware_analyzer()
        tid = _run_task("firmware", lambda: analyzer.analyze(req.firmware_path, req.vendor_hint).to_dict())
        return _ok({"task_id": tid, "message": "固件分析任务已启动"})
    except Exception as e:
        return _fail(f"固件分析启动失败: {e}")


@router.get("/firmware/{task_id}/status")
def firmware_status(task_id: str):
    """查询固件分析任务状态"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/firmware/{task_id}/results")
def firmware_results(task_id: str):
    """获取固件分析结果"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/firmware/{task_id}/report")
def firmware_report(task_id: str):
    """获取固件分析报告"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        result = t["result"]
        return _ok({
            "report_title": "IoT固件安全分析报告",
            "file_name": result.get("file_name", ""),
            "filesystem_type": result.get("filesystem_type", ""),
            "hardcoded_credentials": result.get("hardcoded_credentials", []),
            "component_vulnerabilities": result.get("component_vulnerabilities", []),
            "risk_level": result.get("risk_level", "medium"),
            "risk_score": result.get("risk_score", 0),
            "recommendations": result.get("recommendations", []),
            "findings": result.get("findings", []),
            "analysis_time": result.get("analysis_time", ""),
        })
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


# ==================== 协议安全 API ====================

@router.post("/protocol/analyze")
def protocol_analyze(req: ProtocolAnalyzeReq):
    """启动协议安全分析任务"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        analyzer = get_protocol_analyzer()
        tid = _run_task("protocol", lambda: analyzer.analyze(req.target, req.protocols).to_dict())
        return _ok({"task_id": tid, "message": "协议分析任务已启动"})
    except Exception as e:
        return _fail(f"协议分析启动失败: {e}")


@router.get("/protocol/{task_id}/status")
def protocol_status(task_id: str):
    """查询协议分析任务状态"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/protocol/{task_id}/results")
def protocol_results(task_id: str):
    """获取协议分析结果"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/protocol/{task_id}/report")
def protocol_report(task_id: str):
    """获取协议安全分析报告"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        result = t["result"]
        return _ok({
            "report_title": "IoT协议安全分析报告",
            "target": result.get("target", ""),
            "protocols_analyzed": result.get("protocols_analyzed", []),
            "findings_by_severity": result.get("findings_by_severity", {}),
            "overall_risk": result.get("overall_risk", "medium"),
            "risk_score": result.get("risk_score", 0),
            "recommendations": result.get("recommendations", []),
            "protocols_status": result.get("protocols_status", {}),
        })
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/protocol/supported")
def protocol_supported():
    """获取支持的协议列表"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        analyzer = get_protocol_analyzer()
        return _ok({"protocols": analyzer.get_supported_protocols()})
    except Exception as e:
        return _fail(f"获取协议列表失败: {e}")


# ==================== 默认凭据 API ====================

@router.post("/credentials/check")
def credentials_check(req: CredentialCheckReq):
    """启动默认凭据检测任务"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        detector = get_credential_detector()
        tid = _run_task("credentials", lambda: detector.check(
            req.target, req.vendor, req.device_type, req.ports).to_dict())
        return _ok({"task_id": tid, "message": "凭据检测任务已启动"})
    except Exception as e:
        return _fail(f"凭据检测启动失败: {e}")


@router.get("/credentials/{task_id}/status")
def credentials_status(task_id: str):
    """查询凭据检测任务状态"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/credentials/{task_id}/results")
def credentials_results(task_id: str):
    """获取凭据检测结果"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/credentials/database")
def credentials_database():
    """获取默认凭据数据库"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        detector = get_credential_detector()
        return _ok(detector.get_credentials_database())
    except Exception as e:
        return _fail(f"获取凭据库失败: {e}")


# ==================== 通信安全 API ====================

@router.post("/communication/analyze")
def communication_analyze(req: CommunicationAnalyzeReq):
    """启动通信安全分析任务"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        analyzer = get_communication_analyzer()
        tid = _run_task("communication", lambda: analyzer.analyze(req.target, req.ports).to_dict())
        return _ok({"task_id": tid, "message": "通信安全分析任务已启动"})
    except Exception as e:
        return _fail(f"通信分析启动失败: {e}")


@router.get("/communication/{task_id}/status")
def communication_status(task_id: str):
    """查询通信安全分析任务状态"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/communication/{task_id}/results")
def communication_results(task_id: str):
    """获取通信安全分析结果"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/communication/{task_id}/report")
def communication_report(task_id: str):
    """获取通信安全分析报告"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        result = t["result"]
        return _ok({
            "report_title": "IoT通信安全分析报告",
            "target": result.get("target", ""),
            "risk_level": result.get("risk_level", "medium"),
            "risk_score": result.get("risk_score", 0),
            "plaintext_findings": result.get("plaintext_findings", []),
            "tls_findings": result.get("tls_findings", []),
            "certificate_findings": result.get("certificate_findings", []),
            "mitm_risk_findings": result.get("mitm_risk_findings", []),
            "recommendations": result.get("recommendations", []),
            "findings_by_severity": result.get("findings_by_severity", {}),
        })
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


# ==================== 漏洞检测 API ====================

@router.post("/vulnerability/scan")
def vulnerability_scan(req: VulnerabilityScanReq):
    """启动漏洞检测任务"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        detector = get_vulnerability_detector()
        tid = _run_task("vulnerability", lambda: detector.scan(
            req.target, req.vendor, req.device_type, req.ports, req.firmware_version).to_dict())
        return _ok({"task_id": tid, "message": "漏洞检测任务已启动"})
    except Exception as e:
        return _fail(f"漏洞检测启动失败: {e}")


@router.get("/vulnerability/{task_id}/status")
def vulnerability_status(task_id: str):
    """查询漏洞检测任务状态"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/vulnerability/{task_id}/results")
def vulnerability_results(task_id: str):
    """获取漏洞检测结果"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/vulnerability/{task_id}/report")
def vulnerability_report(task_id: str):
    """获取漏洞检测报告"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        result = t["result"]
        return _ok({
            "report_title": "IoT漏洞检测报告",
            "target": result.get("target", ""),
            "total_vulns": result.get("total_vulns", 0),
            "by_severity": result.get("vuln_count_by_severity", {}),
            "by_type": result.get("vuln_count_by_type", {}),
            "risk_level": result.get("risk_level", "medium"),
            "risk_score": result.get("risk_score", 0),
            "vulnerabilities": result.get("vulnerabilities", []),
            "top_fixes": result.get("top_fixes", []),
        })
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/vulnerability/database")
def vulnerability_database():
    """获取漏洞数据库"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        detector = get_vulnerability_detector()
        return _ok(detector.get_vulnerability_database())
    except Exception as e:
        return _fail(f"获取漏洞库失败: {e}")


# ==================== 综合评估 API ====================

@router.post("/assessment/run")
def assessment_run(req: AssessmentRunReq):
    """启动综合安全评估"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        workflow = get_assessment_workflow()
        options = {
            "skip_discovery": req.skip_discovery,
            "skip_protocol": req.skip_protocol,
            "skip_credentials": req.skip_credentials,
            "skip_communication": req.skip_communication,
            "skip_firmware": req.skip_firmware,
            "skip_vulnerability": req.skip_vulnerability,
            "firmware_path": req.firmware_path,
        }
        tid = _run_task("assessment", lambda: workflow.run(req.target, options).to_dict())
        return _ok({"task_id": tid, "message": "综合评估任务已启动"})
    except Exception as e:
        return _fail(f"综合评估启动失败: {e}")


@router.get("/assessment/{task_id}/status")
def assessment_status(task_id: str):
    """查询综合评估任务状态"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({"task_id": task_id, "status": t["status"], "error": t["error"]})
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/assessment/{task_id}/results")
def assessment_results(task_id: str):
    """获取综合评估结果"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        return _ok(t["result"])
    except Exception as e:
        return _fail(f"获取结果失败: {e}")


@router.get("/assessment/{task_id}/report")
def assessment_report(task_id: str):
    """获取综合评估报告"""
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}")
        result = t["result"]
        return _ok({
            "report_title": "IoT安全综合评估报告",
            "assessment_id": result.get("assessment_id", ""),
            "target": result.get("target", ""),
            "assessment_time": result.get("assessment_time", ""),
            "duration_seconds": result.get("duration_seconds", 0),
            "executive_summary": result.get("executive_summary", ""),
            "overall_risk": result.get("overall_risk", "medium"),
            "risk_score": result.get("risk_score", 0),
            "total_devices": result.get("total_devices", 0),
            "total_vulnerabilities": result.get("total_vulnerabilities", 0),
            "total_findings": result.get("total_findings", 0),
            "devices_by_risk": result.get("devices_by_risk", {}),
            "vulnerabilities_by_severity": result.get("vulnerabilities_by_severity", {}),
            "findings_by_category": result.get("findings_by_category", {}),
            "critical_fixes": result.get("critical_fixes", []),
            "high_fixes": result.get("high_fixes", []),
            "medium_fixes": result.get("medium_fixes", []),
            "assessment_conclusion": result.get("assessment_conclusion", ""),
        })
    except Exception as e:
        return _fail(f"生成报告失败: {e}")


@router.get("/assessment/history")
def assessment_history():
    """获取评估历史记录"""
    try:
        if not _MODULES_OK:
            return _fail("模块未加载")
        workflow = get_assessment_workflow()
        return _ok({
            "history": workflow.list_assessments(),
            "statistics": workflow.get_statistics(),
        })
    except Exception as e:
        return _fail(f"获取历史失败: {e}")
