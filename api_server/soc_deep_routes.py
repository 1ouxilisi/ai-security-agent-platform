# -*- coding: utf-8 -*-
"""
soc_deep_routes.py — 第26轮升级方向3：SOC 深度平台 REST API（50+ 端点）。

路由前缀: /api/v1/soc-deep
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。
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

router = APIRouter(prefix="/api/v1/soc-deep", tags=["SOC Deep 深度平台"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from soc_deep.siem_logging import (
        get_siem, LOG_SOURCES, parse_syslog, parse_json_line, parse_csv_blob,
    )
    from soc_deep.correlation_engine import (
        get_correlation_engine, OPERATORS, RULE_SEVERITIES, RULE_STATUSES,
    )
    from soc_deep.alert_triage_deep import (
        get_alert_triage_deep, ALERT_SOURCES, TRIAGE_STATUSES,
    )
    from soc_deep.incident_response_deep import (
        get_incident_response, IR_PHASES, INCIDENT_SEVERITIES, INCIDENT_STATUSES,
        CONTAINMENT_ACTIONS, ERADICATION_ACTIONS,
    )
    from soc_deep.threat_intel_soc import (
        get_threat_intel_soc, INTEL_SOURCES, IOC_TYPES,
    )
    from soc_deep.soc_metrics import (
        get_soc_metrics, MATURITY_LEVELS, SHIFT_SCHEDULES, REPORT_TEMPLATES,
    )
    from soc_deep.soc_dashboard import get_soc_dashboard, SYSTEM_SETTINGS
    _MOD_AVAILABLE = True
    logger.info("soc_deep_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("soc_deep_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from soc_deep.siem_logging import (  # noqa
            get_siem, LOG_SOURCES, parse_syslog, parse_json_line, parse_csv_blob,
        )
        from soc_deep.correlation_engine import (  # noqa
            get_correlation_engine, OPERATORS, RULE_SEVERITIES, RULE_STATUSES,
        )
        from soc_deep.alert_triage_deep import (  # noqa
            get_alert_triage_deep, ALERT_SOURCES, TRIAGE_STATUSES,
        )
        from soc_deep.incident_response_deep import (  # noqa
            get_incident_response, IR_PHASES, INCIDENT_SEVERITIES,  # noqa
            INCIDENT_STATUSES, CONTAINMENT_ACTIONS, ERADICATION_ACTIONS,
        )
        from soc_deep.threat_intel_soc import (  # noqa
            get_threat_intel_soc, INTEL_SOURCES, IOC_TYPES,
        )
        from soc_deep.soc_metrics import (  # noqa
            get_soc_metrics, MATURITY_LEVELS, SHIFT_SCHEDULES, REPORT_TEMPLATES,
        )
        from soc_deep.soc_dashboard import get_soc_dashboard, SYSTEM_SETTINGS  # noqa
        _MOD_AVAILABLE = True
        logger.info("soc_deep_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("soc_deep_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = uuid.uuid4().hex[:16]
    TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish_task(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in TASKS:
        t = TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        chars = [c for c in obj if ord(c) >= 32 or c in ("\t", "\n", "\r")]
        s = "".join(chars)
        return s.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("SOC Deep 模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class LogIngestReq(BaseModel):
    line: str
    source: str = "syslog"
    fmt: str = "auto"


class LogBatchReq(BaseModel):
    lines: List[str] = Field(default_factory=list)
    source: str = "syslog"


class LogCsvReq(BaseModel):
    blob: str
    source: str = "csv_file"


class RuleCreateReq(BaseModel):
    name: str
    description: str = ""
    conditions: List[Dict[str, Any]] = Field(default_factory=list)
    logic: str = "and"
    severity: str = "medium"
    threshold: Optional[Dict[str, Any]] = None
    group: str = "default"
    tags: List[str] = Field(default_factory=list)


class RuleUpdateReq(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[List[Dict[str, Any]]] = None
    logic: Optional[str] = None
    severity: Optional[str] = None
    threshold: Optional[Dict[str, Any]] = None
    status: Optional[str] = None
    group: Optional[str] = None
    tags: Optional[List[str]] = None


class RuleTestReq(BaseModel):
    rule_id: str
    events: List[Dict[str, Any]] = Field(default_factory=list)


class EventProcessReq(BaseModel):
    events: List[Dict[str, Any]] = Field(default_factory=list)


class AlertIngestReq(BaseModel):
    title: str = ""
    severity: str = "medium"
    category: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    user: str = ""
    asset: str = "unknown"
    description: str = ""
    tags: List[str] = Field(default_factory=list)


class AlertStatusReq(BaseModel):
    status: str
    assignee: Optional[str] = None
    note: str = ""


class IncidentCreateReq(BaseModel):
    title: str
    severity: str = "medium"
    category: str = "unknown"
    description: str = ""
    assignee: str = ""


class IncidentPhaseReq(BaseModel):
    note: str = ""


class IncidentAssignReq(BaseModel):
    assignee: str


class IOCAddReq(BaseModel):
    value: str
    ioc_type: str = "auto"
    source: str = "internal"
    threat: str = "unknown"
    confidence: int = 50
    tags: List[str] = Field(default_factory=list)


class IOCBatchReq(BaseModel):
    items: List[Dict[str, Any]] = Field(default_factory=list)


class IOCLookupReq(BaseModel):
    value: str
    ioc_type: str = "auto"


class ActionReq(BaseModel):
    action: str
    target: str
    operator: str = "soc-analyst"
    dry_run: bool = True


class LessonReq(BaseModel):
    lesson: str


class RootCauseReq(BaseModel):
    cause: str


class CloseReq(BaseModel):
    postmortem: str = ""


# =========================================================================== #
# 1. SIEM 日志管理（8 个端点）
# =========================================================================== #
@router.get("/siem/sources")
def siem_sources():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(LOG_SOURCES)
    except Exception as e:
        return fail(f"查询日志源失败: {e}", 500)


@router.post("/siem/ingest")
def siem_ingest(req: LogIngestReq):
    try:
        g = _guard()
        if g is not None:
            return g
        log = get_siem().ingest(req.line, req.source, req.fmt)
        return ok(log.to_dict())
    except Exception as e:
        return fail(f"日志接入失败: {e}", 500)


@router.post("/siem/ingest-batch")
def siem_ingest_batch(req: LogBatchReq):
    try:
        g = _guard()
        if g is not None:
            return g
        logs = get_siem().ingest_batch(req.lines, req.source)
        tid = _new_task("siem_ingest_batch")
        _finish_task(tid, {"count": len(logs)})
        return ok({"task_id": tid, "count": len(logs)})
    except Exception as e:
        return fail(f"批量接入失败: {e}", 500)


@router.post("/siem/ingest-csv")
def siem_ingest_csv(req: LogCsvReq):
    try:
        g = _guard()
        if g is not None:
            return g
        logs = get_siem().ingest_csv(req.blob, req.source)
        return ok({"count": len(logs), "rows": [l.to_dict() for l in logs]})
    except Exception as e:
        return fail(f"CSV 接入失败: {e}", 500)


@router.get("/siem/search")
def siem_search(q: str = "", host: str = "", app: str = "",
               src_ip: str = "", user: str = "", severity: str = "",
               limit: int = 100):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_siem().search(q, host, app, src_ip, user, severity, limit))
    except Exception as e:
        return fail(f"日志检索失败: {e}", 500)


@router.get("/siem/stats")
def siem_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_siem().stats())
    except Exception as e:
        return fail(f"日志统计失败: {e}", 500)


@router.get("/siem/topn")
def siem_topn(field: str = "src_ip", n: int = 10):
    try:
        g = _guard()
        if g is not None:
            return g
        rows = get_siem().top_n(field, n)
        return ok({"field": field, "topn": [{"value": v, "count": c} for v, c in rows]})
    except Exception as e:
        return fail(f"TopN 失败: {e}", 500)


@router.get("/siem/anomalies")
def siem_anomalies(src_ip: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_siem().anomalies(src_ip))
    except Exception as e:
        return fail(f"异常检测失败: {e}", 500)


# =========================================================================== #
# 2. 关联规则引擎（10 个端点）
# =========================================================================== #
@router.get("/rules/operators")
def rule_operators():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"operators": OPERATORS, "severities": RULE_SEVERITIES,
                   "statuses": RULE_STATUSES})
    except Exception as e:
        return fail(f"查询操作符失败: {e}", 500)


@router.get("/rules")
def list_rules(status: str = "", group: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_correlation_engine().list_rules(status, group))
    except Exception as e:
        return fail(f"查询规则失败: {e}", 500)


@router.post("/rules")
def create_rule(req: RuleCreateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        r = get_correlation_engine().create_rule(
            name=req.name, conditions=req.conditions, logic=req.logic,
            severity=req.severity, threshold=req.threshold,
            description=req.description, group=req.group, tags=req.tags)
        return ok(r.to_dict())
    except Exception as e:
        return fail(f"创建规则失败: {e}", 500)


@router.get("/rules/{rule_id}")
def get_rule(rule_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        r = get_correlation_engine().get_rule(rule_id)
        if not r:
            return fail("规则不存在", 404)
        return ok(r.to_dict())
    except Exception as e:
        return fail(f"查询规则失败: {e}", 500)


@router.put("/rules/{rule_id}")
def update_rule(rule_id: str, req: RuleUpdateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        payload = {k: v for k, v in req.dict().items() if v is not None}
        r = get_correlation_engine().update_rule(rule_id, **payload)
        if not r:
            return fail("规则不存在", 404)
        return ok(r.to_dict())
    except Exception as e:
        return fail(f"更新规则失败: {e}", 500)


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_ = get_correlation_engine().delete_rule(rule_id)
        if not ok_:
            return fail("规则不存在", 404)
        return ok({"deleted": True})
    except Exception as e:
        return fail(f"删除规则失败: {e}", 500)


@router.post("/rules/test")
def test_rule(req: RuleTestReq):
    try:
        g = _guard()
        if g is not None:
            return g
        r = get_correlation_engine().get_rule(req.rule_id)
        if not r:
            return fail("规则不存在", 404)
        return ok(get_correlation_engine().test_rule(r, req.events))
    except Exception as e:
        return fail(f"规则测试失败: {e}", 500)


@router.post("/rules/process")
def process_events(req: EventProcessReq):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_correlation_engine().batch_process(req.events)
        return ok(result)
    except Exception as e:
        return fail(f"事件流处理失败: {e}", 500)


@router.get("/rules/alerts")
def rule_alerts():
    try:
        g = _guard()
        if g is not None:
            return ok(get_correlation_engine().alerts)
    except Exception as e:
        return fail(f"查询规则告警失败: {e}", 500)


@router.get("/rules/metrics")
def rule_metrics():
    try:
        g = _guard()
        if g is not None:
            return ok(get_correlation_engine().metrics())
    except Exception as e:
        return fail(f"规则度量失败: {e}", 500)


# =========================================================================== #
# 3. 告警分诊与聚合（10 个端点）
# =========================================================================== #
@router.get("/alerts/sources")
def alert_sources():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"sources": ALERT_SOURCES, "statuses": TRIAGE_STATUSES})
    except Exception as e:
        return fail(f"查询告警源失败: {e}", 500)


@router.post("/alerts/ingest")
def alert_ingest(req: AlertIngestReq):
    try:
        g = _guard()
        if g is not None:
            return g
        a = get_alert_triage_deep().ingest(req.dict(), "siem")
        return ok(a.to_dict())
    except Exception as e:
        return fail(f"告警接入失败: {e}", 500)


@router.get("/alerts")
def list_alerts(status: str = "", severity: str = "", category: str = "",
               source: str = "", keyword: str = "", limit: int = 200):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_alert_triage_deep().list_alerts(
            status, severity, category, source, keyword, limit))
    except Exception as e:
        return fail(f"查询告警失败: {e}", 500)


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        a = get_alert_triage_deep().alerts.get(alert_id)
        if not a:
            return fail("告警不存在", 404)
        return ok(a.to_dict())
    except Exception as e:
        return fail(f"查询告警失败: {e}", 500)


@router.post("/alerts/{alert_id}/status")
def update_alert(alert_id: str, req: AlertStatusReq):
    try:
        g = _guard()
        if g is not None:
            return g
        a = get_alert_triage_deep().update_status(alert_id, req.status,
                                                  req.assignee, req.note)
        if not a:
            return fail("告警不存在", 404)
        return ok(a.to_dict())
    except Exception as e:
        return fail(f"更新告警失败: {e}", 500)


@router.get("/alerts/aggregates/list")
def list_aggregates():
    try:
        g = _guard()
        if g is not None:
            return ok(get_alert_triage_deep().aggregates())
    except Exception as e:
        return fail(f"查询聚合失败: {e}", 500)


@router.get("/alerts/summary")
def alert_summary():
    try:
        g = _guard()
        if g is not None:
            return ok(get_alert_triage_deep().summary())
    except Exception as e:
        return fail(f"告警汇总失败: {e}", 500)


@router.post("/alerts/batch-ingest")
def alert_batch_ingest(req: List[Dict[str, Any]] = ...):
    try:
        g = _guard()
        if g is not None:
            return g
        items = req or []
        alerts = get_alert_triage_deep().ingest_batch(items, "siem")
        tid = _new_task("alert_batch")
        _finish_task(tid, {"count": len(alerts)})
        return ok({"task_id": tid, "count": len(alerts)})
    except Exception as e:
        return fail(f"批量接入失败: {e}", 500)


# =========================================================================== #
# 4. 事件响应（12 个端点）
# =========================================================================== #
@router.get("/incidents/meta")
def incident_meta():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"phases": IR_PHASES, "severities": INCIDENT_SEVERITIES,
                   "statuses": INCIDENT_STATUSES,
                   "containment_actions": CONTAINMENT_ACTIONS,
                   "eradication_actions": ERADICATION_ACTIONS})
    except Exception as e:
        return fail(f"查询事件元数据失败: {e}", 500)


@router.post("/incidents")
def create_incident(req: IncidentCreateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        i = get_incident_response().create(
            req.title, req.severity, req.category, req.description, req.assignee)
        get_soc_metrics().record_event(i.id, "detect")
        return ok(i.to_dict())
    except Exception as e:
        return fail(f"创建事件失败: {e}", 500)


@router.get("/incidents")
def list_incidents(status: str = "", severity: str = "", keyword: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_incident_response().list(status, severity, keyword))
    except Exception as e:
        return fail(f"查询事件失败: {e}", 500)


@router.get("/incidents/{inc_id}")
def get_incident(inc_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        i = get_incident_response().get(inc_id)
        if not i:
            return fail("事件不存在", 404)
        return ok(i.to_dict())
    except Exception as e:
        return fail(f"查询事件失败: {e}", 500)


@router.post("/incidents/{inc_id}/assign")
def assign_incident(inc_id: str, req: IncidentAssignReq):
    try:
        g = _guard()
        if g is not None:
            return g
        i = get_incident_response().assign(inc_id, req.assignee)
        if not i:
            return fail("事件不存在", 404)
        return ok(i.to_dict())
    except Exception as e:
        return fail(f"指派事件失败: {e}", 500)


@router.post("/incidents/{inc_id}/advance")
def advance_incident(inc_id: str, req: IncidentPhaseReq):
    try:
        g = _guard()
        if g is not None:
            return g
        i = get_incident_response().advance_phase(inc_id, req.note)
        if not i:
            return fail("事件不存在", 404)
        return ok(i.to_dict())
    except Exception as e:
        return fail(f"阶段流转失败: {e}", 500)


@router.post("/incidents/{inc_id}/iocs")
def add_ioc(inc_id: str, req: Dict[str, str]):
    try:
        g = _guard()
        if g is not None:
            return g
        i = get_incident_response().add_ioc(inc_id, req.get("kind", "ip"),
                                            req.get("value", ""))
        if not i:
            return fail("事件不存在", 404)
        return ok(i.to_dict())
    except Exception as e:
        return fail(f"添加IOC失败: {e}", 500)


@router.post("/incidents/{inc_id}/root-cause")
def set_root(inc_id: str, req: RootCauseReq):
    try:
        g = _guard()
        if g is not None:
            return g
        i = get_incident_response().set_root_cause(inc_id, req.cause)
        if not i:
            return fail("事件不存在", 404)
        return ok(i.to_dict())
    except Exception as e:
        return fail(f"根因定位失败: {e}", 500)


@router.post("/incidents/{inc_id}/contain")
def contain_incident(inc_id: str, req: ActionReq):
    try:
        g = _guard()
        if g is not None:
            return g
        r = get_incident_response().containment_action(
            inc_id, req.action, req.target, req.operator, req.dry_run)
        if not r:
            return fail("事件不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(f"遏制动作失败: {e}", 500)


@router.post("/incidents/{inc_id}/eradicate")
def eradicate_incident(inc_id: str, req: ActionReq):
    try:
        g = _guard()
        if g is not None:
            return g
        r = get_incident_response().eradication_action(
            inc_id, req.action, req.target, req.operator, req.dry_run)
        if not r:
            return fail("事件不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(f"根除动作失败: {e}", 500)


@router.post("/incidents/{inc_id}/lessons")
def add_lesson(inc_id: str, req: LessonReq):
    try:
        g = _guard()
        if g is not None:
            return g
        i = get_incident_response().add_lesson(inc_id, req.lesson)
        if not i:
            return fail("事件不存在", 404)
        return ok(i.to_dict())
    except Exception as e:
        return fail(f"添加经验失败: {e}", 500)


@router.post("/incidents/{inc_id}/close")
def close_incident(inc_id: str, req: CloseReq):
    try:
        g = _guard()
        if g is not None:
            return g
        i = get_incident_response().close(inc_id, req.postmortem)
        if not i:
            return fail("事件不存在", 404)
        get_soc_metrics().record_event(inc_id, "close")
        return ok(i.to_dict())
    except Exception as e:
        return fail(f"关闭事件失败: {e}", 500)


# =========================================================================== #
# 5. 威胁情报（8 个端点）
# =========================================================================== #
@router.get("/intel/sources")
def intel_sources():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"sources": INTEL_SOURCES, "ioc_types": IOC_TYPES})
    except Exception as e:
        return fail(f"查询情报源失败: {e}", 500)


@router.post("/intel/iocs")
def add_ioc_item(req: IOCAddReq):
    try:
        g = _guard()
        if g is not None:
            return g
        ioc = get_threat_intel_soc().ingest(
            req.value, req.ioc_type, req.source, req.threat,
            req.confidence, req.tags)
        return ok(ioc.to_dict())
    except Exception as e:
        return fail(f"添加IOC失败: {e}", 500)


@router.post("/intel/iocs/batch")
def add_ioc_batch(req: IOCBatchReq):
    try:
        g = _guard()
        if g is not None:
            return g
        iocs = get_threat_intel_soc().ingest_batch(req.items)
        tid = _new_task("intel_batch")
        _finish_task(tid, {"count": len(iocs)})
        return ok({"task_id": tid, "count": len(iocs)})
    except Exception as e:
        return fail(f"批量接入失败: {e}", 500)


@router.get("/intel/iocs")
def list_iocs(ioc_type: str = "", threat: str = "", source: str = "",
              keyword: str = "", limit: int = 200):
    try:
        g = _guard()
        if g is not None:
            return ok(get_threat_intel_soc().list_iocs(
                ioc_type, threat, source, keyword, limit))
    except Exception as e:
        return fail(f"查询IOC失败: {e}", 500)


@router.delete("/intel/iocs/{ioc_id}")
def delete_ioc(ioc_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_ = get_threat_intel_soc().delete(ioc_id)
        if not ok_:
            return fail("IOC不存在", 404)
        return ok({"deleted": True})
    except Exception as e:
        return fail(f"删除IOC失败: {e}", 500)


@router.post("/intel/lookup")
def intel_lookup(req: IOCLookupReq):
    try:
        g = _guard()
        if g is not None:
            return g
        hit = get_threat_intel_soc().lookup(req.value, req.ioc_type)
        return ok({"hit": hit is not None, "ioc": hit})
    except Exception as e:
        return fail(f"情报查询失败: {e}", 500)


@router.post("/intel/match-event")
def intel_match_event(req: Dict[str, Any]):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"hits": get_threat_intel_soc().match_event(req)})
    except Exception as e:
        return fail(f"事件情报匹配失败: {e}", 500)


@router.get("/intel/quality")
def intel_quality():
    try:
        g = _guard()
        if g is not None:
            return ok(get_threat_intel_soc().quality_report())
    except Exception as e:
        return fail(f"情报质量失败: {e}", 500)


# =========================================================================== #
# 6. SOC 度量与报告（6 个端点）
# =========================================================================== #
@router.get("/metrics/dashboard")
def metrics_dashboard():
    try:
        g = _guard()
        if g is not None:
            return ok(get_soc_metrics().dashboard())
    except Exception as e:
        return fail(f"度量仪表盘失败: {e}", 500)


@router.get("/metrics/report")
def metrics_report(kind: str = "daily"):
    try:
        g = _guard()
        if g is not None:
            return ok(get_soc_metrics().generate_report(kind))
    except Exception as e:
        return fail(f"生成报告失败: {e}", 500)


@router.get("/metrics/maturity")
def metrics_maturity():
    try:
        g = _guard()
        if g is not None:
            return ok(get_soc_metrics().maturity_assess())
    except Exception as e:
        return fail(f"成熟度评估失败: {e}", 500)


@router.get("/metrics/staff")
def metrics_staff():
    try:
        g = _guard()
        if g is not None:
            return ok(get_soc_metrics().staff())
    except Exception as e:
        return fail(f"人员查询失败: {e}", 500)


@router.get("/metrics/process")
def metrics_process():
    try:
        g = _guard()
        if g is not None:
            return ok(get_soc_metrics().process())
    except Exception as e:
        return fail(f"流程健康失败: {e}", 500)


@router.post("/metrics/record")
def metrics_record(req: Dict[str, str]):
    try:
        g = _guard()
        if g is not None:
            return g
        get_soc_metrics().record_event(req.get("incident_id", ""),
                                       req.get("stage", "detect"))
        return ok({"recorded": True})
    except Exception as e:
        return fail(f"度量记录失败: {e}", 500)


# =========================================================================== #
# 7. 仪表盘聚合 & 系统设置 & 任务（6 个端点）
# =========================================================================== #
@router.get("/overview")
def overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soc_dashboard().overview())
    except Exception as e:
        return fail(f"总览失败: {e}", 500)


@router.get("/threat-wall")
def threat_wall():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soc_dashboard().threat_wall())
    except Exception as e:
        return fail(f"威胁墙失败: {e}", 500)


@router.get("/kill-chain")
def kill_chain():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soc_dashboard().kill_chain())
    except Exception as e:
        return fail(f"攻击链失败: {e}", 500)


@router.get("/settings")
def get_settings():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(SYSTEM_SETTINGS)
    except Exception as e:
        return fail(f"查询设置失败: {e}", 500)


@router.get("/health")
def health():
    try:
        return ok(get_soc_dashboard().health())
    except Exception as e:
        return fail(f"健康检查失败: {e}", 500)


@router.get("/tasks")
def list_tasks():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"tasks": list(TASKS.values())})
    except Exception as e:
        return fail(f"查询任务失败: {e}", 500)


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        t = TASKS.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(f"查询任务失败: {e}", 500)
