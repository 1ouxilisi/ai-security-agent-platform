# -*- coding: utf-8 -*-
"""
endpoint_security_routes.py — 终端安全EDR REST API（36 个端点）。

路由前缀: /api/v1/endpoint-security
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

设计定位：仅用于经过授权的终端安全运营，输出检测/监控/分析/管理视角的报告与建议。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/endpoint-security", tags=["终端安全EDR"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from endpoint_security.endpoint_asset import EndpointAssetManager, get_asset_manager
    from endpoint_security.process_behavior import ProcessBehaviorMonitor, get_process_monitor
    from endpoint_security.malware_detection import MalwareDetectionEngine, get_malware_engine
    from endpoint_security.threat_response import ThreatResponseManager, get_threat_manager
    from endpoint_security.vulnerability_patch import VulnerabilityPatchManager, get_vuln_manager
    from endpoint_security.edr_dashboard import EDRDashboard, get_dashboard
    _MOD_AVAILABLE = True
    logger.info("endpoint_security_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("endpoint_security_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    _TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in _TASKS:
        t = _TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return _TASKS.get(task_id)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理数据中的控制字符和无效Unicode，防止编码失败。"""
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(item) for item in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("终端安全EDR模块不可用，请检查加载日志", 503)
    return None


def _task_view(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"task_id": t["task_id"], "status": t["status"], "kind": t["kind"],
            "created_at": t["created_at"], "finished_at": t["finished_at"]}


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class DiscoverRequest(BaseModel):
    network_range: str = "10.10.0.0/16"
    method: str = "Agent上报"


class GroupCreateRequest(BaseModel):
    name: str
    gtype: str = "department"
    rule: str = ""


class LifecycleRegisterRequest(BaseModel):
    hostname: str
    ip: str
    department: str = "未分配"
    owner: str = "unknown"


class LifecycleTransitionRequest(BaseModel):
    action: str
    operator: str = "admin"


class ResponseActionRequest(BaseModel):
    action: str
    asset_id: str
    params: Dict[str, Any] = Field(default_factory=dict)


class AlertUpdateRequest(BaseModel):
    status: str
    assignee: Optional[str] = None
    note: Optional[str] = None


class HuntRequest(BaseModel):
    query: str
    hunt_type: str = "process"


class IncidentCreateRequest(BaseModel):
    title: str
    severity: str = "high"
    asset_ids: List[str] = Field(default_factory=list)


class IncidentPhaseRequest(BaseModel):
    phase: str
    note: str = ""


class SandboxSubmitRequest(BaseModel):
    file_name: str
    sha256: str
    asset_id: str = "EP-0001"


class PatchDeployRequest(BaseModel):
    patch_id: str
    asset_ids: List[str] = Field(default_factory=list)


class FixTaskUpdateRequest(BaseModel):
    status: str


# =========================================================================== #
# 1. 终端资产管理（8 个端点）
# =========================================================================== #
@router.post("/asset/discover")
def asset_discover(req: DiscoverRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_asset_manager()
        result = mgr.discover_endpoints(req.network_range, req.method)
        return ok(result)
    except Exception as e:
        logger.exception("asset_discover error")
        return fail(f"终端发现失败: {e}", 500)


@router.get("/asset/list")
def asset_list(department: Optional[str] = Query(default=None),
               os_name: Optional[str] = Query(default=None),
               risk_level: Optional[str] = Query(default=None),
               location: Optional[str] = Query(default=None),
               online: Optional[bool] = Query(default=None),
               search: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_asset_manager()
        result = mgr.list_assets(department, os_name, risk_level, location, online, search)
        return ok(result)
    except Exception as e:
        return fail(f"查询终端清单失败: {e}", 500)


@router.get("/asset/{asset_id}/detail")
def asset_detail(asset_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_asset_manager()
        detail = mgr.get_asset_detail(asset_id)
        if not detail:
            return fail("终端不存在", 404)
        return ok(detail)
    except Exception as e:
        return fail(f"查询终端详情失败: {e}", 500)


@router.get("/asset/groups")
def asset_groups():
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_asset_manager()
        return ok(mgr.list_groups())
    except Exception as e:
        return fail(f"查询分组失败: {e}", 500)


@router.post("/asset/groups")
def asset_group_create(req: GroupCreateRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_asset_manager()
        return ok(mgr.create_group(req.name, req.gtype, req.rule))
    except Exception as e:
        return fail(f"创建分组失败: {e}", 500)


@router.get("/asset/groups/{group_id}/stats")
def asset_group_stats(group_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_asset_manager()
        stats = mgr.get_group_stats(group_id)
        if not stats:
            return fail("分组不存在", 404)
        return ok(stats)
    except Exception as e:
        return fail(f"查询分组统计失败: {e}", 500)


@router.get("/asset/monitor/status")
def asset_monitor_status():
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_asset_manager()
        return ok(mgr.monitor_status())
    except Exception as e:
        return fail(f"查询监控状态失败: {e}", 500)


@router.post("/asset/lifecycle/register")
def asset_lifecycle_register(req: LifecycleRegisterRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_asset_manager()
        return ok(mgr.lifecycle_register(req.hostname, req.ip, req.department, req.owner))
    except Exception as e:
        return fail(f"终端注册失败: {e}", 500)


@router.post("/asset/lifecycle/{asset_id}/transition")
def asset_lifecycle_transition(asset_id: str, req: LifecycleTransitionRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_asset_manager()
        result = mgr.lifecycle_transition(asset_id, req.action, req.operator)
        if "error" in result:
            return fail(result["error"], 400)
        return ok(result)
    except Exception as e:
        return fail(f"状态流转失败: {e}", 500)


@router.get("/asset/lifecycle/events")
def asset_lifecycle_events(asset_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        mgr = get_asset_manager()
        return ok({"events": mgr.lifecycle_events(asset_id)})
    except Exception as e:
        return fail(f"查询生命周期事件失败: {e}", 500)


# =========================================================================== #
# 2. 进程与行为监控（6 个端点）
# =========================================================================== #
@router.get("/process/{asset_id}/tree")
def process_tree(asset_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        mon = get_process_monitor()
        return ok(mon.get_process_tree(asset_id))
    except Exception as e:
        return fail(f"查询进程树失败: {e}", 500)


@router.get("/process/{asset_id}/list")
def process_list(asset_id: str, search: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        mon = get_process_monitor()
        return ok(mon.list_processes(asset_id, search))
    except Exception as e:
        return fail(f"查询进程列表失败: {e}", 500)


@router.get("/process/{asset_id}/behavior")
def process_behavior(asset_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        mon = get_process_monitor()
        return ok(mon.analyze_behavior(asset_id))
    except Exception as e:
        return fail(f"行为分析失败: {e}", 500)


@router.get("/process/anomalies")
def process_anomalies(severity: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        mon = get_process_monitor()
        return ok(mon.list_anomalies(severity))
    except Exception as e:
        return fail(f"查询异常进程失败: {e}", 500)


@router.get("/process/cmdline/audit")
def process_cmdline_audit(asset_id: Optional[str] = Query(default=None),
                          severity: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        mon = get_process_monitor()
        return ok(mon.audit_commandlines(asset_id, severity))
    except Exception as e:
        return fail(f"查询命令行审计失败: {e}", 500)


@router.get("/process/injection/detections")
def process_injection(asset_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        mon = get_process_monitor()
        return ok(mon.detect_injections(asset_id))
    except Exception as e:
        return fail(f"查询注入检测失败: {e}", 500)


@router.get("/process/persistence")
def process_persistence(asset_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        mon = get_process_monitor()
        return ok(mon.detect_persistence(asset_id))
    except Exception as e:
        return fail(f"查询持久化检测失败: {e}", 500)


# =========================================================================== #
# 3. 恶意软件检测（6 个端点）
# =========================================================================== #
@router.get("/malware/signature/scan")
def malware_signature_scan(asset_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_malware_engine()
        return ok(eng.signature_scan(asset_id))
    except Exception as e:
        return fail(f"签名扫描失败: {e}", 500)


@router.get("/malware/families")
def malware_families():
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_malware_engine()
        return ok(eng.list_families())
    except Exception as e:
        return fail(f"查询恶意软件家族失败: {e}", 500)


@router.get("/malware/behavior/detections")
def malware_behavior(asset_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_malware_engine()
        return ok(eng.behavior_detection(asset_id))
    except Exception as e:
        return fail(f"查询行为检测失败: {e}", 500)


@router.get("/malware/yara/scan")
def malware_yara_scan(asset_id: Optional[str] = Query(default=None),
                      scan_type: str = "file"):
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_malware_engine()
        return ok(eng.yara_scan(asset_id, scan_type))
    except Exception as e:
        return fail(f"YARA扫描失败: {e}", 500)


@router.get("/malware/yara/rules")
def malware_yara_rules(category: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_malware_engine()
        return ok(eng.list_yara_rules(category))
    except Exception as e:
        return fail(f"查询YARA规则失败: {e}", 500)


@router.get("/malware/heuristic/scan")
def malware_heuristic_scan(asset_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_malware_engine()
        return ok(eng.heuristic_scan(asset_id))
    except Exception as e:
        return fail(f"启发式扫描失败: {e}", 500)


@router.post("/malware/sandbox/submit")
def malware_sandbox_submit(req: SandboxSubmitRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_malware_engine()
        return ok(eng.submit_sandbox(req.file_name, req.sha256, req.asset_id))
    except Exception as e:
        return fail(f"提交沙箱失败: {e}", 500)


@router.get("/malware/sandbox/{sandbox_id}/report")
def malware_sandbox_report(sandbox_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_malware_engine()
        report = eng.get_sandbox_report(sandbox_id)
        if not report:
            return fail("沙箱报告不存在", 404)
        return ok(report)
    except Exception as e:
        return fail(f"查询沙箱报告失败: {e}", 500)


# =========================================================================== #
# 4. 威胁检测与响应（8 个端点）
# =========================================================================== #
@router.get("/threat/rules")
def threat_rules(tactic: Optional[str] = Query(default=None),
                 severity: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        return ok(trm.list_rules(tactic, severity))
    except Exception as e:
        return fail(f"查询检测规则失败: {e}", 500)


@router.get("/threat/alerts")
def threat_alerts(severity: Optional[str] = Query(default=None),
                  status: Optional[str] = Query(default=None),
                  asset_id: Optional[str] = Query(default=None),
                  tactic: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        return ok(trm.list_alerts(severity, status, asset_id, tactic))
    except Exception as e:
        return fail(f"查询告警失败: {e}", 500)


@router.put("/threat/alerts/{alert_id}")
def threat_alert_update(alert_id: str, req: AlertUpdateRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        result = trm.update_alert_status(alert_id, req.status, req.assignee, req.note)
        if "error" in result:
            return fail(result["error"], 404)
        return ok(result)
    except Exception as e:
        return fail(f"更新告警失败: {e}", 500)


@router.get("/threat/alerts/trends")
def threat_alert_trends(days: int = Query(default=7)):
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        return ok({"trends": trm.alert_trends(days)})
    except Exception as e:
        return fail(f"查询告警趋势失败: {e}", 500)


@router.get("/threat/actions")
def threat_actions():
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        return ok({"actions": trm.list_response_actions()})
    except Exception as e:
        return fail(f"查询响应动作失败: {e}", 500)


@router.post("/threat/actions/execute")
def threat_action_execute(req: ResponseActionRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        return ok(trm.execute_action(req.action, req.asset_id, req.params))
    except Exception as e:
        return fail(f"执行响应动作失败: {e}", 500)


@router.post("/threat/hunt")
def threat_hunt(req: HuntRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        return ok(trm.hunt_search(req.query, req.hunt_type))
    except Exception as e:
        return fail(f"威胁狩猎失败: {e}", 500)


@router.get("/threat/incidents")
def threat_incidents(status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        return ok(trm.list_incidents(status))
    except Exception as e:
        return fail(f"查询事件失败: {e}", 500)


@router.post("/threat/incidents")
def threat_incident_create(req: IncidentCreateRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        return ok(trm.create_incident(req.title, req.severity, req.asset_ids))
    except Exception as e:
        return fail(f"创建事件失败: {e}", 500)


@router.get("/threat/incidents/{incident_id}")
def threat_incident_detail(incident_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        inc = trm.get_incident(incident_id)
        if not inc:
            return fail("事件不存在", 404)
        return ok(inc)
    except Exception as e:
        return fail(f"查询事件详情失败: {e}", 500)


@router.put("/threat/incidents/{incident_id}/phase")
def threat_incident_phase(incident_id: str, req: IncidentPhaseRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        trm = get_threat_manager()
        result = trm.update_incident_phase(incident_id, req.phase, req.note)
        if "error" in result:
            return fail(result["error"], 404)
        return ok(result)
    except Exception as e:
        return fail(f"更新事件阶段失败: {e}", 500)


# =========================================================================== #
# 5. 漏洞与补丁管理（6 个端点）
# =========================================================================== #
@router.post("/vuln/scan")
def vuln_scan(asset_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        vpm = get_vuln_manager()
        return ok(vpm.scan_vulnerabilities(asset_id))
    except Exception as e:
        return fail(f"漏洞扫描失败: {e}", 500)


@router.get("/vuln/list")
def vuln_list(severity: Optional[str] = Query(default=None),
              asset_id: Optional[str] = Query(default=None),
              cve_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        vpm = get_vuln_manager()
        return ok(vpm.list_vulnerabilities(severity, asset_id, cve_id))
    except Exception as e:
        return fail(f"查询漏洞列表失败: {e}", 500)


@router.get("/vuln/patches")
def vuln_patches(status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        vpm = get_vuln_manager()
        return ok(vpm.list_patches(status))
    except Exception as e:
        return fail(f"查询补丁失败: {e}", 500)


@router.post("/vuln/patches/deploy")
def vuln_patch_deploy(req: PatchDeployRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        vpm = get_vuln_manager()
        return ok(vpm.deploy_patch(req.patch_id, req.asset_ids))
    except Exception as e:
        return fail(f"部署补丁失败: {e}", 500)


@router.get("/vuln/risk-assessment")
def vuln_risk_assessment():
    try:
        g = _guard()
        if g is not None:
            return g
        vpm = get_vuln_manager()
        return ok(vpm.risk_assessment())
    except Exception as e:
        return fail(f"风险评估失败: {e}", 500)


@router.get("/vuln/baseline")
def vuln_baseline(asset_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        vpm = get_vuln_manager()
        return ok(vpm.baseline_check(asset_id))
    except Exception as e:
        return fail(f"基线检查失败: {e}", 500)


@router.get("/vuln/fix-tasks")
def vuln_fix_tasks(status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        vpm = get_vuln_manager()
        return ok(vpm.list_fix_tasks(status))
    except Exception as e:
        return fail(f"查询修复任务失败: {e}", 500)


@router.get("/vuln/fix-report")
def vuln_fix_report():
    try:
        g = _guard()
        if g is not None:
            return g
        vpm = get_vuln_manager()
        return ok(vpm.fix_report())
    except Exception as e:
        return fail(f"修复报告生成失败: {e}", 500)


# =========================================================================== #
# 6. EDR 仪表盘（5 个端点）
# =========================================================================== #
@router.get("/dashboard/posture")
def dashboard_posture():
    try:
        g = _guard()
        if g is not None:
            return g
        d = get_dashboard()
        return ok(d.security_posture())
    except Exception as e:
        return fail(f"查询安全态势失败: {e}", 500)


@router.get("/dashboard/realtime-alerts")
def dashboard_realtime_alerts(limit: int = Query(default=20)):
    try:
        g = _guard()
        if g is not None:
            return g
        d = get_dashboard()
        return ok(d.realtime_alerts(limit))
    except Exception as e:
        return fail(f"查询实时告警流失败: {e}", 500)


@router.get("/dashboard/threat-map")
def dashboard_threat_map():
    try:
        g = _guard()
        if g is not None:
            return g
        d = get_dashboard()
        return ok(d.threat_map())
    except Exception as e:
        return fail(f"查询威胁地图失败: {e}", 500)


@router.get("/dashboard/health")
def dashboard_health():
    try:
        g = _guard()
        if g is not None:
            return g
        d = get_dashboard()
        return ok(d.endpoint_health())
    except Exception as e:
        return fail(f"查询终端健康失败: {e}", 500)


@router.get("/dashboard/metrics")
def dashboard_metrics():
    try:
        g = _guard()
        if g is not None:
            return g
        d = get_dashboard()
        return ok(d.edr_metrics())
    except Exception as e:
        return fail(f"查询EDR度量失败: {e}", 500)
