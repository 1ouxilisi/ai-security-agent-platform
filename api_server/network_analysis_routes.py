# -*- coding: utf-8 -*-
"""
network_analysis_routes.py — 网络流量分析 NTA/NDR REST API（36 个端点）。

路由前缀: /api/v1/network-analysis
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

设计定位：仅用于授权的网络流量安全分析与监控，输出检测报告与告警。
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

router = APIRouter(prefix="/api/v1/network-analysis", tags=["网络流量分析NTA/NDR"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from network_analysis.traffic_capture import TrafficCaptureEngine, PCAP_PROTOCOLS, BPF_FILTER_PRESETS
    from network_analysis.anomaly_detection import AnomalyDetectionEngine, TUNNEL_SIGNATURES, DGA_FEATURES
    from network_analysis.network_behavior import NetworkBehaviorAnalyzer, LATERAL_MOVEMENT_INDICATORS
    from network_analysis.threat_rules import ThreatRuleEngine, SNORT_RULE_LIBRARY, YARA_RULE_LIBRARY
    from network_analysis.traffic_forensics import TrafficForensicsManager, EVIDENCE_PACK_TEMPLATES
    from network_analysis.ndr_dashboard import NDRDashboard, NDR_METRICS_DEFINITIONS
    _MOD_AVAILABLE = True
    logger.info("network_analysis_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("network_analysis_routes: load failed: %s", e)


# 单例引擎
_capture_engine: Optional[TrafficCaptureEngine] = None
_anomaly_engine: Optional[AnomalyDetectionEngine] = None
_behavior_analyzer: Optional[NetworkBehaviorAnalyzer] = None
_rule_engine: Optional[ThreatRuleEngine] = None
_forensics_mgr: Optional[TrafficForensicsManager] = None
_dashboard: Optional[NDRDashboard] = None


def _get_capture() -> TrafficCaptureEngine:
    global _capture_engine
    if _capture_engine is None:
        _capture_engine = TrafficCaptureEngine()
    return _capture_engine


def _get_anomaly() -> AnomalyDetectionEngine:
    global _anomaly_engine
    if _anomaly_engine is None:
        _anomaly_engine = AnomalyDetectionEngine()
    return _anomaly_engine


def _get_behavior() -> NetworkBehaviorAnalyzer:
    global _behavior_analyzer
    if _behavior_analyzer is None:
        _behavior_analyzer = NetworkBehaviorAnalyzer()
    return _behavior_analyzer


def _get_rules() -> ThreatRuleEngine:
    global _rule_engine
    if _rule_engine is None:
        _rule_engine = ThreatRuleEngine()
    return _rule_engine


def _get_forensics() -> TrafficForensicsManager:
    global _forensics_mgr
    if _forensics_mgr is None:
        _forensics_mgr = TrafficForensicsManager()
    return _forensics_mgr


def _get_dashboard() -> NDRDashboard:
    global _dashboard
    if _dashboard is None:
        _dashboard = NDRDashboard()
    return _dashboard


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


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理数据中的控制字符与无效Unicode。"""
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
        return fail("网络流量分析模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class CaptureStartRequest(BaseModel):
    interface: str = "eth0"
    bpf_filter: str = ""
    max_packets: int = 1000


class BaselineLearnRequest(BaseModel):
    duration_minutes: int = 30


class DgaDetectRequest(BaseModel):
    domains: List[str] = Field(default_factory=list)


class CustomRuleRequest(BaseModel):
    name: str = ""
    conditions: Dict[str, Any] = Field(default_factory=dict)
    threshold: int = 1
    severity: str = "medium"


class EvidencePackRequest(BaseModel):
    pack_name: str = ""
    template: str = "incident_response"
    pcap_ids: List[str] = Field(default_factory=list)
    analyst: str = "security_analyst"
    notes: str = ""


class AlertTriageRequest(BaseModel):
    action: str = "confirm"
    analyst: str = "auto"
    notes: str = ""


# =========================================================================== #
# 1. 流量捕获模块（8 个端点）
# =========================================================================== #
@router.get("/capture/interfaces")
def list_interfaces():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_capture().list_interfaces())
    except Exception as e:
        logger.exception("list_interfaces error")
        return fail(f"获取接口列表失败: {e}", 500)


@router.post("/capture/start")
def start_capture(req: CaptureStartRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        result = _get_capture().start_capture(req.interface, req.bpf_filter, req.max_packets)
        task_id = _new_task("capture")
        _finish_task(task_id, result)
        return ok({"task_id": task_id, **result})
    except Exception as e:
        logger.exception("start_capture error")
        return fail(f"启动抓包失败: {e}", 500)


@router.post("/capture/stop")
def stop_capture():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_capture().stop_capture())
    except Exception as e:
        logger.exception("stop_capture error")
        return fail(f"停止抓包失败: {e}", 500)


@router.get("/capture/live-stats")
def live_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_capture().get_live_stats())
    except Exception as e:
        return fail(f"获取实时统计失败: {e}", 500)


@router.get("/capture/statistics")
def capture_statistics():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_capture().get_statistics())
    except Exception as e:
        return fail(f"获取流量统计失败: {e}", 500)


@router.get("/capture/protocols")
def protocol_parsing():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_capture().parse_protocols())
    except Exception as e:
        return fail(f"协议解析失败: {e}", 500)


@router.get("/capture/tcp-flows")
def tcp_flows(limit: int = 10):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_capture().reconstruct_tcp_flows(limit))
    except Exception as e:
        return fail(f"TCP流重组失败: {e}", 500)


@router.get("/capture/http-sessions")
def http_sessions(limit: int = 10):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_capture().reconstruct_http_sessions(limit))
    except Exception as e:
        return fail(f"HTTP会话重建失败: {e}", 500)


# =========================================================================== #
# 2. 异常检测模块（6 个端点）
# =========================================================================== #
@router.post("/anomaly/baseline/learn")
def learn_baseline(req: BaselineLearnRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("baseline_learn")
        result = _get_anomaly().learn_baseline(req.duration_minutes)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        logger.exception("learn_baseline error")
        return fail(f"基线学习失败: {e}", 500)


@router.get("/anomaly/baselines")
def list_baselines():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_anomaly().list_baselines())
    except Exception as e:
        return fail(f"列出基线失败: {e}", 500)


@router.get("/anomaly/detect")
def detect_anomalies(baseline_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_anomaly().detect_anomalies(baseline_id))
    except Exception as e:
        return fail(f"异常检测失败: {e}", 500)


@router.get("/anomaly/tunnels")
def detect_tunnels():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_anomaly().detect_tunnels())
    except Exception as e:
        return fail(f"隧道检测失败: {e}", 500)


@router.post("/anomaly/dga")
def detect_dga(req: DgaDetectRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_anomaly().detect_dga(req.domains if req.domains else None))
    except Exception as e:
        logger.exception("detect_dga error")
        return fail(f"DGA检测失败: {e}", 500)


@router.get("/anomaly/port-scans")
def detect_port_scans():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_anomaly().detect_port_scans())
    except Exception as e:
        return fail(f"端口扫描检测失败: {e}", 500)


# =========================================================================== #
# 3. 行为分析模块（6 个端点）
# =========================================================================== #
@router.get("/behavior/profiles")
def entity_profiles():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_behavior().build_entity_profiles())
    except Exception as e:
        return fail(f"实体画像构建失败: {e}", 500)


@router.get("/behavior/profile/{ip}")
def get_entity_profile(ip: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_behavior().get_entity_profile(ip))
    except Exception as e:
        return fail(f"获取实体画像失败: {e}", 500)


@router.get("/behavior/graph")
def communication_graph(limit_nodes: int = 30):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_behavior().build_communication_graph(limit_nodes))
    except Exception as e:
        return fail(f"通信图谱构建失败: {e}", 500)


@router.get("/behavior/topology")
def discover_topology():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_behavior().discover_topology())
    except Exception as e:
        return fail(f"拓扑发现失败: {e}", 500)


@router.get("/behavior/lateral-movement")
def detect_lateral():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_behavior().detect_lateral_movement())
    except Exception as e:
        return fail(f"横向移动检测失败: {e}", 500)


@router.get("/behavior/exfiltration")
def detect_exfiltration():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_behavior().detect_data_exfiltration())
    except Exception as e:
        return fail(f"数据渗出检测失败: {e}", 500)


# =========================================================================== #
# 4. 威胁规则模块（6 个端点）
# =========================================================================== #
@router.get("/rules/signatures")
def list_signature_rules(category: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_rules().list_signature_rules(category))
    except Exception as e:
        return fail(f"列出签名规则失败: {e}", 500)


@router.get("/rules/signatures/run")
def run_signature_detection():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_rules().run_signature_detection())
    except Exception as e:
        return fail(f"签名检测运行失败: {e}", 500)


@router.get("/rules/behavioral/run")
def run_behavioral_detection():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_rules().run_behavioral_detection())
    except Exception as e:
        return fail(f"行为检测运行失败: {e}", 500)


@router.get("/rules/yara")
def list_yara_rules():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_rules().list_yara_rules())
    except Exception as e:
        return fail(f"列出YARA规则失败: {e}", 500)


@router.get("/rules/yara/run")
def run_yara_scan(target: str = "extracted_files"):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_rules().run_yara_scan(target))
    except Exception as e:
        return fail(f"YARA扫描失败: {e}", 500)


@router.get("/rules/ioc/match")
def match_ioc():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_rules().match_ioc())
    except Exception as e:
        return fail(f"IOC匹配失败: {e}", 500)


@router.post("/rules/custom")
def create_custom_rule(req: CustomRuleRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_rules().create_custom_rule(req.name, req.conditions,
                                                    req.threshold, req.severity))
    except Exception as e:
        logger.exception("create_custom_rule error")
        return fail(f"创建自定义规则失败: {e}", 500)


@router.get("/rules/custom")
def list_custom_rules():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_rules().list_custom_rules())
    except Exception as e:
        return fail(f"列出自定义规则失败: {e}", 500)


@router.get("/rules/stats")
def rule_statistics():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_rules().get_rule_hit_statistics())
    except Exception as e:
        return fail(f"规则统计失败: {e}", 500)


# =========================================================================== #
# 5. 流量取证模块（6 个端点）
# =========================================================================== #
@router.get("/forensics/pcaps")
def list_pcaps():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_forensics().list_pcaps())
    except Exception as e:
        return fail(f"列出PCAP失败: {e}", 500)


@router.post("/forensics/pcaps/upload")
def upload_pcap(filename: str = Query(...), file_size: int = 0,
                interface: str = "eth0", notes: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_forensics().upload_pcap(filename, file_size, interface, notes))
    except Exception as e:
        logger.exception("upload_pcap error")
        return fail(f"上传PCAP失败: {e}", 500)


@router.get("/forensics/search")
def search_traffic(pcap_id: str = "all", search_type: str = "all",
                   query: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_forensics().search_traffic(pcap_id, search_type, query))
    except Exception as e:
        return fail(f"流量搜索失败: {e}", 500)


@router.get("/forensics/sessions")
def list_sessions(pcap_id: str = "all", limit: int = 20):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_forensics().list_sessions(pcap_id, limit))
    except Exception as e:
        return fail(f"列出会话失败: {e}", 500)


@router.get("/forensics/replay/{session_id}")
def replay_session(session_id: str, protocol: str = "tcp"):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_forensics().replay_session(session_id, protocol))
    except Exception as e:
        return fail(f"会话回放失败: {e}", 500)


@router.get("/forensics/extract-files")
def extract_files(pcap_id: str = "all"):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_forensics().extract_files(pcap_id))
    except Exception as e:
        return fail(f"文件提取失败: {e}", 500)


@router.post("/forensics/evidence-pack")
def create_evidence_pack(req: EvidencePackRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_forensics().generate_evidence_pack(
            req.pack_name, req.template, req.pcap_ids, req.analyst, req.notes))
    except Exception as e:
        logger.exception("create_evidence_pack error")
        return fail(f"生成证据包失败: {e}", 500)


@router.get("/forensics/evidence-packs")
def list_evidence_packs():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_forensics().list_evidence_packs())
    except Exception as e:
        return fail(f"列出证据包失败: {e}", 500)


# =========================================================================== #
# 6. NDR 仪表盘模块（6 个端点）
# =========================================================================== #
@router.get("/dashboard/realtime")
def realtime_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_dashboard().get_realtime_overview())
    except Exception as e:
        return fail(f"实时大屏数据获取失败: {e}", 500)


@router.get("/dashboard/alerts")
def list_dashboard_alerts(status: Optional[str] = Query(default=None),
                          severity: Optional[str] = Query(default=None),
                          limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_dashboard().list_alerts(status, severity, limit))
    except Exception as e:
        return fail(f"告警列表获取失败: {e}", 500)


@router.post("/dashboard/alerts/{alert_id}/triage")
def triage_dashboard_alert(alert_id: str, req: AlertTriageRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_dashboard().triage_alert(alert_id, req.action, req.analyst, req.notes))
    except Exception as e:
        logger.exception("triage_alert error")
        return fail(f"告警分诊失败: {e}", 500)


@router.get("/dashboard/alert-stats")
def alert_statistics():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_dashboard().get_alert_statistics())
    except Exception as e:
        return fail(f"告警统计失败: {e}", 500)


@router.get("/dashboard/threat-map")
def threat_map():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_dashboard().get_threat_map())
    except Exception as e:
        return fail(f"威胁地图获取失败: {e}", 500)


@router.get("/dashboard/health")
def health_status():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_dashboard().get_health_status())
    except Exception as e:
        return fail(f"健康状态获取失败: {e}", 500)


@router.get("/dashboard/metrics")
def ndr_metrics():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_dashboard().get_metrics())
    except Exception as e:
        return fail(f"NDR度量获取失败: {e}", 500)


@router.get("/dashboard/overview")
def dashboard_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_get_dashboard().get_dashboard_overview())
    except Exception as e:
        return fail(f"仪表盘总览获取失败: {e}", 500)


# =========================================================================== #
# 7. 系统/元信息端点（2 个端点）
# =========================================================================== #
@router.get("/info")
def module_info():
    """模块元信息。"""
    try:
        return ok({
            "module": "network_analysis",
            "version": "17.2.0",
            "round": 17,
            "direction": 2,
            "modules": [
                "traffic_capture", "anomaly_detection", "network_behavior",
                "threat_rules", "traffic_forensics", "ndr_dashboard",
            ],
            "protocols_supported": list(PCAP_PROTOCOLS.keys()) if _MOD_AVAILABLE else [],
            "tunnel_signatures": len(TUNNEL_SIGNATURES) if _MOD_AVAILABLE else 0,
            "snort_rules": len(SNORT_RULE_LIBRARY) if _MOD_AVAILABLE else 0,
            "yara_rules": len(YARA_RULE_LIBRARY) if _MOD_AVAILABLE else 0,
            "ndr_metrics": list(NDR_METRICS_DEFINITIONS.keys()) if _MOD_AVAILABLE else [],
            "status": "operational" if _MOD_AVAILABLE else "degraded",
        })
    except Exception as e:
        return fail(f"获取模块信息失败: {e}", 500)


@router.get("/tasks/{task_id}")
def get_task_status(task_id: str):
    try:
        t = _TASKS.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok({
            "task_id": t["task_id"], "status": t["status"], "kind": t["kind"],
            "created_at": t["created_at"], "finished_at": t["finished_at"],
        })
    except Exception as e:
        return fail(f"查询失败: {e}", 500)
