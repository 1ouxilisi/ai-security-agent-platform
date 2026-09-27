# -*- coding: utf-8 -*-
"""
soar_deep_routes.py — 第24轮升级方向2：SOAR 深度平台 REST API（60+ 端点）。

路由前缀: /api/v1/soar-deep
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

设计定位：SOAR 深度编排/自动化/响应视角，全部 dry-run 模拟。
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

router = APIRouter(prefix="/api/v1/soar-deep", tags=["SOAR Deep 深度平台"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from soar_deep.playbook_engine import (
        get_playbook_engine, NODE_TYPE_REGISTRY, TRIGGER_TYPES, DATA_FUNCTIONS,
    )
    from soar_deep.response_actions import (
        get_action_executor, ACTION_REGISTRY, ACTION_CATEGORIES,
    )
    from soar_deep.alert_triage import get_alert_triage, ALERT_SOURCES
    from soar_deep.case_management import (
        get_case_manager, STATUSES, CATEGORIES, PRIORITIES, ROLES, CASE_TEMPLATES,
    )
    from soar_deep.threat_intel_integration import (
        get_threat_intel, INTEL_SOURCES, IOC_TYPES,
    )
    from soar_deep.soar_dashboard import get_soar_dashboard, SYSTEM_SETTINGS
    _MOD_AVAILABLE = True
    logger.info("soar_deep_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("soar_deep_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from soar_deep.playbook_engine import (  # noqa
            get_playbook_engine, NODE_TYPE_REGISTRY, TRIGGER_TYPES, DATA_FUNCTIONS,
        )
        from soar_deep.response_actions import (  # noqa
            get_action_executor, ACTION_REGISTRY, ACTION_CATEGORIES,
        )
        from soar_deep.alert_triage import get_alert_triage, ALERT_SOURCES  # noqa
        from soar_deep.case_management import (  # noqa
            get_case_manager, STATUSES, CATEGORIES, PRIORITIES, ROLES, CASE_TEMPLATES,
        )
        from soar_deep.threat_intel_integration import (  # noqa
            get_threat_intel, INTEL_SOURCES, IOC_TYPES,
        )
        from soar_deep.soar_dashboard import get_soar_dashboard, SYSTEM_SETTINGS  # noqa
        _MOD_AVAILABLE = True
        logger.info("soar_deep_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("soar_deep_routes: fallback load failed: %s", e2)


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
        return fail("SOAR Deep 模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class PlaybookCreateReq(BaseModel):
    name: str
    category: str = "general"
    description: str = ""


class PlaybookNodeReq(BaseModel):
    node_type: str
    config: Dict[str, Any] = Field(default_factory=dict)
    position: Dict[str, float] = Field(default_factory=dict)


class PlaybookEdgeReq(BaseModel):
    source: str
    target: str
    condition: Optional[Dict[str, Any]] = None


class PlaybookExecuteReq(BaseModel):
    input_vars: Dict[str, Any] = Field(default_factory=dict)
    triggered_by: str = "manual"
    dry_run: bool = False


class VersionSaveReq(BaseModel):
    note: str = ""
    author: str = ""


class ActionExecuteReq(BaseModel):
    action_id: str
    params: Dict[str, Any] = Field(default_factory=dict)
    operator: str = "soar-bot"
    dry_run: bool = True


class ActionBatchReq(BaseModel):
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    operator: str = "soar-bot"
    dry_run: bool = True


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
    raw: Dict[str, Any] = Field(default_factory=dict)


class AlertBatchIngestReq(BaseModel):
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    source: str = "webhook"


class CaseCreateReq(BaseModel):
    title: str
    severity: str = "medium"
    category: str = "其他"
    owner: str = ""
    description: str = ""
    related_alerts: List[str] = Field(default_factory=list)


class CaseCommentReq(BaseModel):
    author: str
    body: str
    mentions: List[str] = Field(default_factory=list)


class CaseTaskReq(BaseModel):
    title: str
    assignee: str = ""
    due: str = ""


class CaseStatusReq(BaseModel):
    status: str
    operator: str = "system"
    note: str = ""


class CasePriorityReq(BaseModel):
    priority: str


class CaseMemberReq(BaseModel):
    user: str
    role: str = "analyst"


class CaseIOCReq(BaseModel):
    ioc_type: str
    value: str
    source: str = "manual"


class IntelQueryReq(BaseModel):
    value: str


class IntelExportReq(BaseModel):
    ioc_ids: List[str] = Field(default_factory=list)
    format: str = "stix"


class IntelShareReq(BaseModel):
    feed_name: str
    ioc_ids: List[str] = Field(default_factory=list)


class VariableSetReq(BaseModel):
    key: str
    value: Any


# =========================================================================== #
# 1. SOAR 总览 & 仪表盘（6 个端点）
# =========================================================================== #
@router.get("/overview")
def dashboard_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soar_dashboard().overview())
    except Exception as e:
        logger.exception("overview error")
        return fail(f"总览查询失败: {e}", 500)


@router.get("/view/playbooks")
def view_playbooks():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soar_dashboard().playbook_view())
    except Exception as e:
        return fail(f"剧本视图失败: {e}", 500)


@router.get("/view/actions")
def view_actions():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soar_dashboard().action_view())
    except Exception as e:
        return fail(f"动作视图失败: {e}", 500)


@router.get("/view/alerts")
def view_alerts():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soar_dashboard().alert_view())
    except Exception as e:
        return fail(f"告警视图失败: {e}", 500)


@router.get("/view/cases")
def view_cases():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soar_dashboard().case_view())
    except Exception as e:
        return fail(f"案例视图失败: {e}", 500)


@router.get("/view/settings")
def view_settings():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soar_dashboard().settings_view())
    except Exception as e:
        return fail(f"设置视图失败: {e}", 500)


@router.get("/view/intel")
def view_intel():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soar_dashboard().intel_view())
    except Exception as e:
        return fail(f"情报视图失败: {e}", 500)


# =========================================================================== #
# 2. 剧本编排引擎（16 个端点）
# =========================================================================== #
@router.get("/playbooks")
def playbook_list(status: Optional[str] = Query(default=None),
                  category: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"playbooks": get_playbook_engine().list_playbooks(status, category)})
    except Exception as e:
        return fail(f"查询剧本失败: {e}", 500)


@router.post("/playbooks")
def playbook_create(req: PlaybookCreateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().create(req.name, req.category, req.description)
        return ok(pb.to_dict())
    except Exception as e:
        logger.exception("playbook_create error")
        return fail(f"创建剧本失败: {e}", 500)


@router.get("/playbooks/{pb_id}")
def playbook_detail(pb_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().get(pb_id)
        if not pb:
            return fail("剧本不存在", 404)
        return ok(pb.to_dict())
    except Exception as e:
        return fail(f"查询剧本失败: {e}", 500)


@router.delete("/playbooks/{pb_id}")
def playbook_delete(pb_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_del = get_playbook_engine().delete(pb_id)
        if not ok_del:
            return fail("剧本不存在", 404)
        return ok({"deleted": True, "id": pb_id})
    except Exception as e:
        return fail(f"删除剧本失败: {e}", 500)


@router.post("/playbooks/{pb_id}/nodes")
def playbook_add_node(pb_id: str, req: PlaybookNodeReq):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().get(pb_id)
        if not pb:
            return fail("剧本不存在", 404)
        node = pb.add_node(req.node_type, config=req.config, position=req.position)
        return ok(node)
    except Exception as e:
        return fail(f"添加节点失败: {e}", 500)


@router.delete("/playbooks/{pb_id}/nodes/{node_id}")
def playbook_remove_node(pb_id: str, node_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().get(pb_id)
        if not pb:
            return fail("剧本不存在", 404)
        removed = pb.remove_node(node_id)
        return ok({"removed": removed, "node_id": node_id})
    except Exception as e:
        return fail(f"删除节点失败: {e}", 500)


@router.post("/playbooks/{pb_id}/edges")
def playbook_add_edge(pb_id: str, req: PlaybookEdgeReq):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().get(pb_id)
        if not pb:
            return fail("剧本不存在", 404)
        edge = pb.add_edge(req.source, req.target, req.condition)
        return ok(edge)
    except Exception as e:
        return fail(f"添加连线失败: {e}", 500)


@router.post("/playbooks/{pb_id}/execute")
def playbook_execute(pb_id: str, req: PlaybookExecuteReq):
    try:
        g = _guard()
        if g is not None:
            return g
        inst = get_playbook_engine().execute(
            pb_id, input_vars=req.input_vars,
            triggered_by=req.triggered_by, dry_run=req.dry_run)
        if not inst:
            return fail("剧本不存在", 404)
        return ok(inst.to_dict())
    except Exception as e:
        logger.exception("playbook_execute error")
        return fail(f"执行剧本失败: {e}", 500)


@router.get("/playbooks/{pb_id}/versions")
def playbook_versions(pb_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"versions": get_playbook_engine().list_versions(pb_id)})
    except Exception as e:
        return fail(f"查询版本失败: {e}", 500)


@router.post("/playbooks/{pb_id}/versions/save")
def playbook_save_version(pb_id: str, req: VersionSaveReq):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().get(pb_id)
        if not pb:
            return fail("剧本不存在", 404)
        snap = pb.save_version(note=req.note, author=req.author)
        return ok(snap)
    except Exception as e:
        return fail(f"保存版本失败: {e}", 500)


@router.get("/playbooks/{pb_id}/versions/diff")
def playbook_diff(pb_id: str, v1: int, v2: int):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_playbook_engine().diff_versions(pb_id, v1, v2))
    except Exception as e:
        return fail(f"版本对比失败: {e}", 500)


@router.post("/playbooks/{pb_id}/rollback")
def playbook_rollback(pb_id: str, version: int = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().get(pb_id)
        if not pb:
            return fail("剧本不存在", 404)
        ok_rb = pb.rollback(version)
        return ok({"rolled_back": ok_rb, "to_version": version})
    except Exception as e:
        return fail(f"回滚失败: {e}", 500)


@router.post("/playbooks/{pb_id}/publish")
def playbook_publish(pb_id: str, req: VersionSaveReq):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().get(pb_id)
        if not pb:
            return fail("剧本不存在", 404)
        entry = pb.publish(note=req.note, approver=req.author)
        return ok(entry)
    except Exception as e:
        return fail(f"发布失败: {e}", 500)


@router.post("/playbooks/{pb_id}/dry-run")
def playbook_dry_run(pb_id: str, req: PlaybookExecuteReq):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_playbook_engine().debug_dry_run(pb_id, req.input_vars)
        return ok(result)
    except Exception as e:
        return fail(f"Dry run失败: {e}", 500)


@router.get("/instances")
def instance_list(status: Optional[str] = Query(default=None),
                  pb_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"instances": get_playbook_engine().list_instances(status, pb_id)})
    except Exception as e:
        return fail(f"查询实例失败: {e}", 500)


@router.post("/instances/{inst_id}/approve")
def instance_approve(inst_id: str, decision: str = Query("approve"),
                     approver: str = Query("")):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_app = get_playbook_engine().approve(inst_id, decision, approver)
        return ok({"approved": ok_app, "decision": decision})
    except Exception as e:
        return fail(f"审批失败: {e}", 500)


@router.post("/instances/{inst_id}/cancel")
def instance_cancel(inst_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_c = get_playbook_engine().cancel(inst_id)
        return ok({"cancelled": ok_c})
    except Exception as e:
        return fail(f"取消失败: {e}", 500)


@router.get("/meta/node-types")
def meta_node_types():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(NODE_TYPE_REGISTRY)
    except Exception as e:
        return fail(f"查询节点类型失败: {e}", 500)


@router.get("/meta/trigger-types")
def meta_trigger_types():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(TRIGGER_TYPES)
    except Exception as e:
        return fail(f"查询触发器类型失败: {e}", 500)


@router.get("/meta/data-functions")
def meta_data_functions():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DATA_FUNCTIONS)
    except Exception as e:
        return fail(f"查询数据函数失败: {e}", 500)


# =========================================================================== #
# 3. 响应动作库（8 个端点）
# =========================================================================== #
@router.get("/actions")
def action_list(category: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"actions": get_action_executor().list_actions(category)})
    except Exception as e:
        return fail(f"查询动作失败: {e}", 500)


@router.get("/actions/categories")
def action_categories():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ACTION_CATEGORIES)
    except Exception as e:
        return fail(f"查询分类失败: {e}", 500)


@router.get("/actions/{action_id}")
def action_detail(action_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        a = get_action_executor().get_action(action_id)
        if not a:
            return fail("动作不存在", 404)
        return ok(a)
    except Exception as e:
        return fail(f"查询动作失败: {e}", 500)


@router.post("/actions/execute")
def action_execute(req: ActionExecuteReq):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_action_executor().execute(
            req.action_id, req.params, req.operator, req.dry_run)
        return ok(result)
    except Exception as e:
        logger.exception("action_execute error")
        return fail(f"执行动作失败: {e}", 500)


@router.post("/actions/batch")
def action_batch(req: ActionBatchReq):
    try:
        g = _guard()
        if g is not None:
            return g
        results = get_action_executor().batch_execute(
            req.actions, req.operator, req.dry_run)
        return ok({"results": results, "total": len(results)})
    except Exception as e:
        return fail(f"批量执行失败: {e}", 500)


@router.get("/actions/history")
def action_history(limit: int = Query(50),
                   status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"history": get_action_executor().get_history(limit, status)})
    except Exception as e:
        return fail(f"查询历史失败: {e}", 500)


@router.get("/actions/stats")
def action_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_action_executor().stats())
    except Exception as e:
        return fail(f"查询统计失败: {e}", 500)


# =========================================================================== #
# 4. 告警分诊与聚合（10 个端点）
# =========================================================================== #
@router.post("/alerts/ingest")
def alert_ingest(req: AlertIngestReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = dict(req.raw)
        raw.update({"title": req.title, "severity": req.severity,
                    "category": req.category, "src_ip": req.src_ip,
                    "dst_ip": req.dst_ip, "user": req.user,
                    "asset": req.asset, "description": req.description,
                    "tags": req.tags})
        a = get_alert_triage().ingest(raw, source="api")
        return ok(a.to_dict())
    except Exception as e:
        logger.exception("alert_ingest error")
        return fail(f"接入告警失败: {e}", 500)


@router.post("/alerts/ingest-batch")
def alert_ingest_batch(req: AlertBatchIngestReq):
    try:
        g = _guard()
        if g is not None:
            return g
        alerts = get_alert_triage().ingest_batch(req.alerts, req.source)
        return ok({"count": len(alerts),
                   "alerts": [a.to_dict() for a in alerts]})
    except Exception as e:
        return fail(f"批量接入失败: {e}", 500)


@router.get("/alerts")
def alert_list(status: Optional[str] = Query(default=None),
               severity: Optional[str] = Query(default=None),
               category: Optional[str] = Query(default=None),
               priority: Optional[str] = Query(default=None),
               limit: int = Query(100)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"alerts": get_alert_triage().list_alerts(
            status, severity, category, priority, limit)})
    except Exception as e:
        return fail(f"查询告警失败: {e}", 500)


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        a = get_alert_triage().get_alert(alert_id)
        if not a:
            return fail("告警不存在", 404)
        return ok(a)
    except Exception as e:
        return fail(f"查询告警失败: {e}", 500)


@router.post("/alerts/{alert_id}/deduplicate")
def alert_deduplicate(alert_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        is_new = get_alert_triage().deduplicate(alert_id)
        return ok({"is_new": is_new, "alert_id": alert_id})
    except Exception as e:
        return fail(f"去重失败: {e}", 500)


@router.post("/alerts/aggregate/asset")
def alert_aggregate_asset():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"groups": get_alert_triage().aggregate_by_asset()})
    except Exception as e:
        return fail(f"按资产聚合失败: {e}", 500)


@router.post("/alerts/aggregate/chain")
def alert_aggregate_chain():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"groups": get_alert_triage().aggregate_by_attack_chain()})
    except Exception as e:
        return fail(f"按攻击链聚合失败: {e}", 500)


@router.post("/alerts/{alert_id}/triage")
def alert_triage_one(alert_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_alert_triage().triage(alert_id)
        if not result:
            return fail("告警不存在", 404)
        return ok(result)
    except Exception as e:
        return fail(f"分诊失败: {e}", 500)


@router.post("/alerts/triage-all")
def alert_triage_all():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_alert_triage().triage_all())
    except Exception as e:
        return fail(f"批量分诊失败: {e}", 500)


@router.post("/alerts/{alert_id}/enrich")
def alert_enrich(alert_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_alert_triage().enrich(alert_id)
        if not result:
            return fail("告警不存在", 404)
        return ok(result)
    except Exception as e:
        return fail(f"丰富化失败: {e}", 500)


@router.get("/alerts/sources")
def alert_sources():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ALERT_SOURCES)
    except Exception as e:
        return fail(f"查询告警源失败: {e}", 500)


@router.get("/alerts/stats")
def alert_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_alert_triage().stats())
    except Exception as e:
        return fail(f"查询告警统计失败: {e}", 500)


# =========================================================================== #
# 5. 案例管理与协作（14 个端点）
# =========================================================================== #
@router.get("/cases")
def case_list(status: Optional[str] = Query(default=None),
              category: Optional[str] = Query(default=None),
              priority: Optional[str] = Query(default=None),
              severity: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"cases": get_case_manager().list_cases(status, category, priority, severity)})
    except Exception as e:
        return fail(f"查询案例失败: {e}", 500)


@router.post("/cases")
def case_create(req: CaseCreateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().create(
            req.title, req.severity, req.category, req.owner,
            req.description, req.related_alerts)
        return ok(c.to_dict())
    except Exception as e:
        logger.exception("case_create error")
        return fail(f"创建案例失败: {e}", 500)


@router.get("/cases/{case_id}")
def case_detail(case_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().get(case_id)
        if not c:
            return fail("案例不存在", 404)
        return ok(c.to_dict())
    except Exception as e:
        return fail(f"查询案例失败: {e}", 500)


@router.post("/cases/{case_id}/comments")
def case_add_comment(case_id: str, req: CaseCommentReq):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().get(case_id)
        if not c:
            return fail("案例不存在", 404)
        comment = c.add_comment(req.author, req.body, req.mentions)
        return ok(comment)
    except Exception as e:
        return fail(f"添加评论失败: {e}", 500)


@router.post("/cases/{case_id}/tasks")
def case_add_task(case_id: str, req: CaseTaskReq):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().get(case_id)
        if not c:
            return fail("案例不存在", 404)
        task = c.add_task(req.title, req.assignee, req.due)
        return ok(task)
    except Exception as e:
        return fail(f"添加任务失败: {e}", 500)


@router.post("/cases/{case_id}/tasks/{task_id}/complete")
def case_complete_task(case_id: str, task_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().get(case_id)
        if not c:
            return fail("案例不存在", 404)
        ok_t = c.complete_task(task_id)
        return ok({"completed": ok_t, "task_id": task_id})
    except Exception as e:
        return fail(f"完成任务失败: {e}", 500)


@router.post("/cases/{case_id}/status")
def case_change_status(case_id: str, req: CaseStatusReq):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().get(case_id)
        if not c:
            return fail("案例不存在", 404)
        c.change_status(req.status, req.operator, req.note)
        return ok(c.to_dict())
    except Exception as e:
        return fail(f"状态变更失败: {e}", 500)


@router.post("/cases/{case_id}/priority")
def case_set_priority(case_id: str, req: CasePriorityReq):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().get(case_id)
        if not c:
            return fail("案例不存在", 404)
        c.set_priority(req.priority)
        return ok(c.to_dict())
    except Exception as e:
        return fail(f"设置优先级失败: {e}", 500)


@router.post("/cases/{case_id}/members")
def case_add_member(case_id: str, req: CaseMemberReq):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().get(case_id)
        if not c:
            return fail("案例不存在", 404)
        c.add_member(req.user, req.role)
        return ok(c.to_dict())
    except Exception as e:
        return fail(f"添加成员失败: {e}", 500)


@router.post("/cases/{case_id}/iocs")
def case_add_ioc(case_id: str, req: CaseIOCReq):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().get(case_id)
        if not c:
            return fail("案例不存在", 404)
        c.add_ioc(req.ioc_type, req.value, req.source)
        return ok(c.to_dict())
    except Exception as e:
        return fail(f"添加IOC失败: {e}", 500)


@router.get("/cases/{case_id}/timeline")
def case_timeline(case_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().get(case_id)
        if not c:
            return fail("案例不存在", 404)
        return ok({"timeline": c.timeline})
    except Exception as e:
        return fail(f"查询时间线失败: {e}", 500)


@router.get("/knowledge/search")
def knowledge_search(keyword: str = Query(""), category: str = Query("")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"results": get_case_manager().search_knowledge(keyword, category)})
    except Exception as e:
        return fail(f"知识检索失败: {e}", 500)


@router.get("/knowledge/templates")
def knowledge_templates():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"templates": CASE_TEMPLATES})
    except Exception as e:
        return fail(f"查询模板失败: {e}", 500)


@router.get("/analytics")
def case_analytics():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_case_manager().analytics())
    except Exception as e:
        return fail(f"查询分析失败: {e}", 500)


# =========================================================================== #
# 6. 威胁情报联动（12 个端点）
# =========================================================================== #
@router.get("/intel/iocs")
def intel_list(ioc_type: Optional[str] = Query(default=None),
               severity: Optional[str] = Query(default=None),
               status: str = Query("active")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"iocs": get_threat_intel().list_indicators(ioc_type, severity, status)})
    except Exception as e:
        return fail(f"查询IOC失败: {e}", 500)


@router.post("/intel/match")
def intel_match(ioc_type: str = Query(...), value: str = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_threat_intel().match_ioc(ioc_type, value))
    except Exception as e:
        return fail(f"IOC匹配失败: {e}", 500)


@router.get("/intel/query/ip/{ip}")
def intel_query_ip(ip: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_threat_intel().query_ip(ip))
    except Exception as e:
        return fail(f"IP查询失败: {e}", 500)


@router.get("/intel/query/domain/{domain}")
def intel_query_domain(domain: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_threat_intel().query_domain(domain))
    except Exception as e:
        return fail(f"域名查询失败: {e}", 500)


@router.get("/intel/query/url")
def intel_query_url(url: str = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_threat_intel().query_url(url))
    except Exception as e:
        return fail(f"URL查询失败: {e}", 500)


@router.get("/intel/query/hash/{file_hash}")
def intel_query_hash(file_hash: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_threat_intel().query_hash(file_hash))
    except Exception as e:
        return fail(f"哈希查询失败: {e}", 500)


@router.get("/intel/actors")
def intel_actors():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"actors": get_threat_intel().list_threat_actors()})
    except Exception as e:
        return fail(f"查询威胁Actor失败: {e}", 500)


@router.get("/intel/high-risk")
def intel_high_risk(min_severity: str = Query("high")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"iocs": get_threat_intel().get_high_risk_iocs(min_severity)})
    except Exception as e:
        return fail(f"查询高风险IOC失败: {e}", 500)


@router.post("/intel/update/{source_id}")
def intel_update(source_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_threat_intel().update_source(source_id))
    except Exception as e:
        return fail(f"情报更新失败: {e}", 500)


@router.post("/intel/cleanup")
def intel_cleanup():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_threat_intel().cleanup_expired())
    except Exception as e:
        return fail(f"清理过期情报失败: {e}", 500)


@router.post("/intel/export")
def intel_export(req: IntelExportReq):
    try:
        g = _guard()
        if g is not None:
            return g
        if req.format == "openioc":
            return ok(get_threat_intel().export_openioc(req.ioc_ids))
        return ok(get_threat_intel().export_stix(req.ioc_ids))
    except Exception as e:
        return fail(f"导出失败: {e}", 500)


@router.post("/intel/share")
def intel_share(req: IntelShareReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_threat_intel().share_to_feed(req.feed_name, req.ioc_ids))
    except Exception as e:
        return fail(f"情报共享失败: {e}", 500)


@router.get("/intel/sources")
def intel_sources():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(INTEL_SOURCES)
    except Exception as e:
        return fail(f"查询情报源失败: {e}", 500)


@router.get("/intel/quality")
def intel_quality():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_threat_intel().quality_report())
    except Exception as e:
        return fail(f"质量评估失败: {e}", 500)


# =========================================================================== #
# 7. 系统设置 & 变量管理（4 个端点）
# =========================================================================== #
@router.get("/settings")
def get_settings():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(SYSTEM_SETTINGS)
    except Exception as e:
        return fail(f"查询设置失败: {e}", 500)


@router.get("/variables")
def list_variables():
    try:
        g = _guard()
        if g is not None:
            return ok(get_playbook_engine().var_mgr.to_dict())
    except Exception as e:
        return fail(f"查询变量失败: {e}", 500)


@router.post("/variables")
def set_variable(req: VariableSetReq):
    try:
        g = _guard()
        if g is not None:
            return g
        get_playbook_engine().var_mgr.set_global(req.key, req.value)
        return ok({"set": True, "key": req.key})
    except Exception as e:
        return fail(f"设置变量失败: {e}", 500)


@router.get("/secrets")
def list_secrets():
    try:
        g = _guard()
        if g is not None:
            return ok({"secrets": get_playbook_engine().var_mgr.list_secrets()})
    except Exception as e:
        return fail(f"查询密钥失败: {e}", 500)


# =========================================================================== #
# 8. 任务查询（2 个端点）
# =========================================================================== #
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
