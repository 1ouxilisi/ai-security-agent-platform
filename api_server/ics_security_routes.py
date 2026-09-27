# -*- coding: utf-8 -*-
"""
ics_security_routes.py - 工控安全(ICS/SCADA) REST API（第12轮深化模块）。

路由前缀：/api/v1/ics-security
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典模拟异步任务（task_id -> status/result）。

合法边界：所有端点仅做只读/评估/检测，不向 PLC 下发任何写指令或控制命令。
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

try:
    from ics_security.asset_discovery import create_asset_discovery
    from ics_security.protocol_analyzer import create_protocol_analyzer
    from ics_security.vulnerability_detector import create_vulnerability_detector
    from ics_security.baseline_checker import create_baseline_checker
    from ics_security.anomaly_detector import create_anomaly_detector
    from ics_security.threat_intel import create_threat_intel
    from ics_security.ics_assessment_workflow import create_assessment_workflow
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("ics_security_routes: 模块导入失败: %s", _e)
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/ics-security", tags=["工控安全"])


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


async def _run_task(task_id: str, fn) -> None:
    task = TASKS.get(task_id)
    if not task:
        return
    task["status"] = "running"
    try:
        await asyncio.sleep(0)
        result = await asyncio.to_thread(fn) if not asyncio.iscoroutinefunction(fn) else fn()
        task["status"] = "success"
        task["result"] = result
    except Exception as e:  # pragma: no cover
        task["status"] = "failed"
        task["error"] = str(e)
    finally:
        task["finished_at"] = datetime.now().isoformat()


# ==================== 请求模型 ====================

class DiscoveryReq(BaseModel):
    targets: List[str] = ["192.168.0.10", "192.168.0.11", "192.168.0.20"]
    ports: Optional[List[int]] = None
    timeout: float = 1.0


class ProtocolAnalyzeReq(BaseModel):
    frames: List[Dict[str, str]] = []
    protocol: str = "modbus"


class VulnScanReq(BaseModel):
    assets: Optional[List[Dict[str, Any]]] = None
    # 也可直接按厂商/型号做离线匹配
    vendor: Optional[str] = None
    model: Optional[str] = None


class BaselineReq(BaseModel):
    evidence: Dict[str, bool] = {}


class AnomalyReq(BaseModel):
    function_code_events: List[Dict[str, Any]] = []
    write_events: List[Dict[str, Any]] = []
    comm_flows: List[Dict[str, Any]] = []
    time_events: List[Dict[str, Any]] = []
    traffic: Optional[Dict[str, Any]] = None
    traffic_baseline: Optional[Dict[str, Any]] = None
    critical_events: List[Dict[str, Any]] = []


class ThreatMatchReq(BaseModel):
    observables: List[Dict[str, str]] = []


class AssessmentReq(BaseModel):
    targets: List[str] = ["192.168.0.10"]
    protocol_frames: List[Dict[str, str]] = []
    baseline_evidence: Dict[str, bool] = {}
    anomaly_payload: Dict[str, Any] = {}
    threat_observables: List[Dict[str, str]] = []


# ==================== 1. 资产发现 ====================

@router.post("/discovery/scan", summary="启动工控资产发现")
async def discovery_scan(req: DiscoveryReq):
    try:
        tid = _new_task("disc")

        def _job():
            if not _MODULES_OK:
                return {"assets": [], "asset_count": 0, "summary": {},
                        "note": "模块未加载，返回空结果"}
            ad = create_asset_discovery(timeout=req.timeout)
            return ad.discover(req.targets, req.ports)

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(f"启动失败: {e}")


@router.get("/discovery/{task_id}/status", summary="资产发现任务状态")
async def discovery_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({k: t[k] for k in ("task_id", "type", "status", "error", "created_at", "finished_at") if k in t})
    except Exception as e:
        return _fail(str(e))


@router.get("/discovery/{task_id}/results", summary="资产发现任务结果")
async def discovery_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"])
    except Exception as e:
        return _fail(str(e))


@router.get("/assets/list", summary="资产列表（从最近一次发现任务聚合）")
async def assets_list(
    type: Optional[str] = Query(None, description="按设备类型过滤"),
    risk: Optional[str] = Query(None, description="按风险等级过滤"),
):
    try:
        all_assets: List[Dict[str, Any]] = []
        for t in TASKS.values():
            if t["type"] == "disc" and t["result"]:
                all_assets.extend(t["result"].get("assets", []))
        if type:
            all_assets = [a for a in all_assets if type in a.get("device_types", [])]
        if risk:
            all_assets = [a for a in all_assets if a.get("risk", {}).get("level") == risk]
        return _ok({"total": len(all_assets), "assets": all_assets})
    except Exception as e:
        return _fail(str(e))


@router.get("/assets/{asset_id}/detail", summary="资产详情")
async def asset_detail(asset_id: str):
    try:
        for t in TASKS.values():
            if t["type"] == "disc" and t["result"]:
                for a in t["result"].get("assets", []):
                    if a.get("asset_id") == asset_id:
                        return _ok(a)
        return _fail("资产不存在")
    except Exception as e:
        return _fail(str(e))


@router.get("/assets/export", summary="导出资产列表(JSON)")
async def assets_export():
    try:
        all_assets: List[Dict[str, Any]] = []
        for t in TASKS.values():
            if t["type"] == "disc" and t["result"]:
                all_assets.extend(t["result"].get("assets", []))
        body = json.dumps({"exported_at": datetime.now().isoformat(),
                            "assets": all_assets}, ensure_ascii=False, indent=2)
        return PlainTextResponse(body, media_type="application/json; charset=utf-8")
    except Exception as e:
        return _fail(str(e))


# ==================== 2. 协议分析 ====================

@router.post("/protocol/analyze", summary="启动协议深度分析")
async def protocol_analyze(req: ProtocolAnalyzeReq):
    try:
        tid = _new_task("proto")

        def _job():
            pa = create_protocol_analyzer() if _MODULES_OK else None
            if pa is None:
                return {"analysis": {}, "report": {}}
            analysis = pa.analyze_batch(req.frames)
            report = pa.generate_report(analysis)
            return {"analysis": analysis, "report": report}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(str(e))


@router.get("/protocol/supported", summary="支持的工控协议清单")
async def protocol_supported():
    try:
        if not _MODULES_OK:
            return _ok({"protocols": []})
        return _ok(create_protocol_analyzer().supported_protocols())
    except Exception as e:
        return _fail(str(e))


@router.get("/protocol/{task_id}/status", summary="协议分析任务状态")
async def protocol_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({k: t[k] for k in ("task_id", "type", "status", "error") if k in t})
    except Exception as e:
        return _fail(str(e))


@router.get("/protocol/{task_id}/results", summary="协议分析任务结果")
async def protocol_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"].get("analysis"))
    except Exception as e:
        return _fail(str(e))


@router.get("/protocol/{task_id}/report", summary="协议分析报告")
async def protocol_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"].get("report"))
    except Exception as e:
        return _fail(str(e))


# ==================== 3. 漏洞检测 ====================

@router.post("/vulnerability/scan", summary="启动漏洞检测")
async def vuln_scan(req: VulnScanReq):
    try:
        tid = _new_task("vuln")

        def _job():
            vd = create_vulnerability_detector() if _MODULES_OK else None
            if vd is None:
                return {"scan": {}, "report": {}}
            assets = req.assets or []
            if not assets and (req.vendor or req.model):
                assets = [{"asset_id": "A-00000000", "ip": "manual",
                           "fingerprint": {"vendor": req.vendor or "", "model": req.model or ""},
                           "protocols": []}]
            scan = vd.scan(assets)
            report = vd.generate_report(scan)
            return {"scan": scan, "report": report}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(str(e))


@router.get("/vulnerability/database", summary="漏洞库查询")
async def vuln_database(
    severity: Optional[str] = Query(None),
    vendor: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
):
    try:
        if not _MODULES_OK:
            return _ok({"total": 0, "items": []})
        items = create_vulnerability_detector().list_vulns(severity=severity, vendor=vendor, category=category)
        return _ok({"total": len(items), "items": items})
    except Exception as e:
        return _fail(str(e))


@router.get("/vulnerability/{task_id}/status", summary="漏洞检测任务状态")
async def vuln_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({k: t[k] for k in ("task_id", "type", "status", "error") if k in t})
    except Exception as e:
        return _fail(str(e))


@router.get("/vulnerability/{task_id}/results", summary="漏洞检测结果")
async def vuln_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"].get("scan"))
    except Exception as e:
        return _fail(str(e))


@router.get("/vulnerability/{task_id}/report", summary="漏洞检测报告")
async def vuln_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"].get("report"))
    except Exception as e:
        return _fail(str(e))


# ==================== 4. 基线检查 ====================

@router.post("/baseline/check", summary="启动基线检查")
async def baseline_check(req: BaselineReq):
    try:
        tid = _new_task("baseline")

        def _job():
            bc = create_baseline_checker() if _MODULES_OK else None
            if bc is None:
                return {"result": {}, "report": {}}
            result = bc.check(req.evidence)
            report = bc.generate_report(result)
            return {"result": result, "report": report}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(str(e))


@router.get("/baseline/rules", summary="基线规则库")
async def baseline_rules(category: Optional[str] = Query(None)):
    try:
        if not _MODULES_OK:
            return _ok({"total": 0, "items": []})
        items = create_baseline_checker().list_rules(category)
        return _ok({"total": len(items), "items": items})
    except Exception as e:
        return _fail(str(e))


@router.get("/baseline/{task_id}/status", summary="基线检查任务状态")
async def baseline_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({k: t[k] for k in ("task_id", "type", "status", "error") if k in t})
    except Exception as e:
        return _fail(str(e))


@router.get("/baseline/{task_id}/results", summary="基线检查结果")
async def baseline_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"].get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/baseline/{task_id}/report", summary="基线检查报告")
async def baseline_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"].get("report"))
    except Exception as e:
        return _fail(str(e))


# ==================== 5. 异常检测 ====================

@router.post("/anomaly/detect", summary="启动异常行为检测")
async def anomaly_detect(req: AnomalyReq):
    try:
        tid = _new_task("anomaly")

        def _job():
            ad = create_anomaly_detector() if _MODULES_OK else None
            if ad is None:
                return {"result": {}, "report": {}}
            result = ad.detect(
                function_code_events=req.function_code_events,
                write_events=req.write_events,
                comm_flows=req.comm_flows,
                time_events=req.time_events,
                traffic=req.traffic,
                traffic_baseline=req.traffic_baseline,
                critical_events=req.critical_events,
            )
            report = ad.generate_report(result)
            return {"result": result, "report": report}

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(str(e))


@router.get("/anomaly/alerts", summary="历史异常告警聚合")
async def anomaly_alerts(severity: Optional[str] = Query(None)):
    try:
        merged: List[Dict[str, Any]] = []
        for t in TASKS.values():
            if t["type"] == "anomaly" and t["result"]:
                merged.extend(t["result"].get("result", {}).get("alarms", []))
        if severity:
            merged = [a for a in merged if a.get("severity") == severity]
        return _ok({"total": len(merged), "alarms": merged})
    except Exception as e:
        return _fail(str(e))


@router.get("/anomaly/{task_id}/status", summary="异常检测任务状态")
async def anomaly_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({k: t[k] for k in ("task_id", "type", "status", "error") if k in t})
    except Exception as e:
        return _fail(str(e))


@router.get("/anomaly/{task_id}/results", summary="异常检测结果")
async def anomaly_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"].get("result"))
    except Exception as e:
        return _fail(str(e))


@router.get("/anomaly/{task_id}/report", summary="异常检测报告")
async def anomaly_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"].get("report"))
    except Exception as e:
        return _fail(str(e))


# ==================== 6. 威胁情报 ====================

@router.get("/threat/iocs", summary="IOC 库")
async def threat_iocs(
    type: Optional[str] = Query(None, description="IOC 类型"),
    severity: Optional[str] = Query(None),
):
    try:
        if not _MODULES_OK:
            return _ok({"total": 0, "items": []})
        items = create_threat_intel().list_iocs(ioc_type=type, severity=severity)
        return _ok({"total": len(items), "items": items})
    except Exception as e:
        return _fail(str(e))


@router.get("/threat/campaigns", summary="已知工控攻击活动")
async def threat_campaigns():
    try:
        if not _MODULES_OK:
            return _ok({"items": []})
        return _ok({"items": create_threat_intel().list_campaigns()})
    except Exception as e:
        return _fail(str(e))


@router.post("/threat/match", summary="威胁情报匹配")
async def threat_match(req: ThreatMatchReq):
    try:
        if not _MODULES_OK:
            return _ok({"hit_count": 0, "hits": [], "threat_level": "none"})
        m = create_threat_intel().match(req.observables)
        return _ok(m)
    except Exception as e:
        return _fail(str(e))


@router.get("/threat/report", summary="威胁情报概览报告")
async def threat_report():
    try:
        if not _MODULES_OK:
            return _ok({"items": []})
        ti = create_threat_intel()
        return _ok({
            "ioc_total": len(ti.iocs),
            "campaign_total": len(ti.campaigns),
            "campaigns": ti.list_campaigns(),
            "ioc_types": sorted({i["type"] for i in ti.iocs}),
        })
    except Exception as e:
        return _fail(str(e))


# ==================== 7. 综合评估 ====================

@router.post("/assessment/run", summary="启动综合评估")
async def assessment_run(req: AssessmentReq):
    try:
        tid = _new_task("assess")

        def _job():
            wf = create_assessment_workflow() if _MODULES_OK else None
            if wf is None:
                return {"status": "degraded", "note": "模块未加载"}
            return wf.run(
                targets=req.targets,
                protocol_frames=req.protocol_frames,
                baseline_evidence=req.baseline_evidence,
                anomaly_payload=req.anomaly_payload,
                threat_observables=req.threat_observables,
            )

        asyncio.create_task(_run_task(tid, _job))
        return _ok({"task_id": tid, "status": "pending"})
    except Exception as e:
        return _fail(str(e))


@router.get("/assessment/history", summary="综合评估历史")
async def assessment_history(limit: int = Query(20, ge=1, le=100)):
    try:
        items = []
        for t in sorted(TASKS.values(), key=lambda x: x.get("created_at", ""), reverse=True):
            if t["type"] == "assess":
                items.append({
                    "task_id": t["task_id"], "status": t["status"],
                    "created_at": t.get("created_at"), "finished_at": t.get("finished_at"),
                })
        return _ok({"total": len(items), "items": items[:limit]})
    except Exception as e:
        return _fail(str(e))


@router.get("/assessment/{task_id}/status", summary="综合评估任务状态")
async def assessment_status(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok({k: t[k] for k in ("task_id", "type", "status", "error") if k in t})
    except Exception as e:
        return _fail(str(e))


@router.get("/assessment/{task_id}/results", summary="综合评估结果")
async def assessment_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"])
    except Exception as e:
        return _fail(str(e))


@router.get("/assessment/{task_id}/report", summary="综合评估报告")
async def assessment_report(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return _fail("任务不存在")
        if t["status"] != "success":
            return _fail(f"任务未完成: {t['status']}", t)
        return _ok(t["result"].get("report"))
    except Exception as e:
        return _fail(str(e))
