# -*- coding: utf-8 -*-
"""
防御中心 API 路由

提供 IDS / 日志分析 / 基线检查 / 修复验证 / 威胁狩猎 的 HTTP 接口。
所有防御引擎采用延迟导入（try/except），单个模块失败不影响整体路由注册。

注意：本路由只导出 `router`，由上层 app.py 统一 include；不自行挂载。
"""
import os
import traceback
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/defense", tags=["防御中心"])


# ---------------------------------------------------------------------- #
# 请求模型
# ---------------------------------------------------------------------- #
class AnalyzeRequest(BaseModel):
    """单条请求/日志分析"""
    packet: Optional[Dict[str, Any]] = Field(None, description="网络请求字典")
    log_line: Optional[str] = Field(None, description="单行日志文本")


class AnalyzeFileRequest(BaseModel):
    """指定文件路径批量分析"""
    filepath: str = Field(..., description="日志/流量文本文件路径")
    log_type: str = Field("auto", description="auto/access/auth/windows")


class LogAnalyzeRequest(BaseModel):
    filepath: str = Field(..., description="日志文件路径")
    log_type: str = Field("auto", description="日志类型")


class BaselineCheckRequest(BaseModel):
    category: Optional[str] = Field(None, description="web/os/database/container，缺省全部")
    configs: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, description="各类别配置字典，key 为类别名")


class VulnItem(BaseModel):
    vuln_info: Dict[str, Any]
    remediation_plan: Dict[str, Any] = Field(default_factory=dict)


class RemediationVerifyRequest(BaseModel):
    vulns: List[VulnItem] = Field(..., description="待验证漏洞列表")


class ThreatHuntRequest(BaseModel):
    scenario: Optional[str] = Field(None, description="指定场景，缺省全部")
    events: List[Dict[str, Any]] = Field(default_factory=list, description="事件列表")
    iocs: Optional[List[Dict[str, str]]] = Field(None, description="IOC 列表")


# 进程内缓存：保存最近一次分析结果，供 GET 查询
_STATE: Dict[str, Any] = {
    "ids_alerts": [],
    "log_statistics": {},
    "log_report": {},
    "baseline_report": {},
    "verification_report": {},
    "hunt_report": {},
}


def _safe_import(mod_path: str, attr: Optional[str] = None):
    """延迟导入防御模块，失败返回 None。"""
    try:
        import importlib
        mod = importlib.import_module(mod_path)
        if attr:
            return getattr(mod, attr)
        return mod
    except Exception as e:  # pragma: no cover
        traceback.print_exc()
        print(f"[defense_routes] 导入 {mod_path} 失败: {e}")
        return None


# ---------------------------------------------------------------------- #
# IDS 端点
# ---------------------------------------------------------------------- #
@router.post("/ids/analyze", summary="分析单条请求/日志")
async def ids_analyze(req: AnalyzeRequest):
    IDSEngine = _safe_import("defense.ids_engine", "IDSEngine")
    if IDSEngine is None:
        raise HTTPException(status_code=500, detail="IDS 引擎不可用")
    eng = IDSEngine()
    alerts = []
    if req.packet:
        alerts.extend(eng.analyze_packet(req.packet))
    if req.log_line:
        alerts.extend(eng.analyze_log_line(req.log_line))
    _STATE["ids_alerts"] = eng.alerts
    return {"status": "success", "count": len(alerts), "alerts": alerts}


@router.post("/ids/analyze-file", summary="批量分析日志/流量文件")
async def ids_analyze_file(req: AnalyzeFileRequest):
    IDSEngine = _safe_import("defense.ids_engine", "IDSEngine")
    if IDSEngine is None:
        raise HTTPException(status_code=500, detail="IDS 引擎不可用")
    if not os.path.exists(req.filepath):
        raise HTTPException(status_code=404, detail=f"文件不存在: {req.filepath}")
    eng = IDSEngine()
    result = eng.analyze_pcap_file(req.filepath)
    _STATE["ids_alerts"] = eng.alerts
    return {"status": "success", **result}


@router.get("/ids/alerts", summary="获取告警列表")
async def ids_alerts(severity: Optional[str] = Query(None, description="info/warning/critical")):
    alerts = _STATE["ids_alerts"]
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    return {"status": "success", "total": len(alerts), "alerts": alerts}


# ---------------------------------------------------------------------- #
# 日志分析端点
# ---------------------------------------------------------------------- #
@router.post("/log/analyze", summary="分析日志文件")
async def log_analyze(req: LogAnalyzeRequest):
    LogAnalyzer = _safe_import("defense.log_analyzer", "LogAnalyzer")
    if LogAnalyzer is None:
        raise HTTPException(status_code=500, detail="日志分析器不可用")
    if not os.path.exists(req.filepath):
        raise HTTPException(status_code=404, detail=f"文件不存在: {req.filepath}")
    la = LogAnalyzer()
    result = la.analyze_file(req.filepath, req.log_type)
    _STATE["log_statistics"] = la.get_statistics()
    _STATE["log_report"] = la.export_report()
    return {"status": "success", **result}


@router.get("/log/statistics", summary="获取日志统计")
async def log_statistics():
    return {"status": "success",
            "statistics": _STATE["log_statistics"],
            "anomalies": _STATE["log_report"].get("anomalies", [])}


# ---------------------------------------------------------------------- #
# 基线检查端点
# ---------------------------------------------------------------------- #
@router.post("/baseline/check", summary="执行基线检查")
async def baseline_check(req: BaselineCheckRequest):
    BaselineChecker = _safe_import("defense.baseline_checker", "BaselineChecker")
    if BaselineChecker is None:
        raise HTTPException(status_code=500, detail="基线检查器不可用")
    bc = BaselineChecker()
    report = bc.run_check(category=req.category, configs=req.configs or {})
    _STATE["baseline_report"] = report
    return {"status": "success", "report": report}


@router.get("/baseline/report", summary="获取基线检查报告")
async def baseline_report():
    return {"status": "success", "report": _STATE["baseline_report"]}


# ---------------------------------------------------------------------- #
# 修复验证端点
# ---------------------------------------------------------------------- #
@router.post("/remediation/verify", summary="验证漏洞修复")
async def remediation_verify(req: RemediationVerifyRequest):
    RemediationVerifier = _safe_import("defense.remediation_verifier", "RemediationVerifier")
    if RemediationVerifier is None:
        raise HTTPException(status_code=500, detail="修复验证器不可用")
    vf = RemediationVerifier()
    items = [v.model_dump() for v in req.vulns]
    vf.batch_verify(items)
    report = vf.get_verification_report()
    _STATE["verification_report"] = report
    return {"status": "success", "report": report}


# ---------------------------------------------------------------------- #
# 威胁狩猎端点
# ---------------------------------------------------------------------- #
@router.post("/threat-hunt/run", summary="执行威胁狩猎")
async def threat_hunt_run(req: ThreatHuntRequest):
    ThreatHunter = _safe_import("defense.threat_hunting", "ThreatHunter")
    if ThreatHunter is None:
        raise HTTPException(status_code=500, detail="威胁狩猎引擎不可用")
    th = ThreatHunter()
    if req.iocs:
        th.load_iocs(req.iocs)
    if req.scenario:
        th.hunt(req.scenario, req.events)
    else:
        th.hunt_all(req.events)
    report = th.export_hunt_report()
    _STATE["hunt_report"] = report
    return {"status": "success", "report": report}


@router.get("/threat-hunt/findings", summary="获取狩猎发现")
async def threat_hunt_findings():
    return {"status": "success", "report": _STATE["hunt_report"]}
