# -*- coding: utf-8 -*-
"""
soar_routes.py — SOAR 安全编排自动化与响应 REST API（40 个端点）。

路由前缀: /api/v1/soar
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

设计定位：管理/编排/自动化视角，所有响应动作均为 dry-run 模拟，
不实际操作任何生产系统。
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

router = APIRouter(prefix="/api/v1/soar", tags=["SOAR安全编排"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from soar.action_library import get_action_executor, ACTION_LIBRARY, ACTION_CATEGORIES
    from soar.playbook_engine import get_playbook_engine, PLAYBOOK_TEMPLATES, NODE_TYPES
    from soar.alert_triage import get_alert_triage
    from soar.case_manager import get_case_manager, STATUSES, CATEGORIES, SEVERITIES
    from soar.execution_engine import get_execution_engine
    from soar.soar_metrics import get_soar_metrics
    from soar.soar_workflow import get_soar_workflow, WORKFLOW_STEPS
    _MOD_AVAILABLE = True
    logger.info("soar_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("soar_routes: load failed: %s", e)
    # 备选：按包相对路径重试一次（兼容从 api_server 目录启动的场景）
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from soar.action_library import get_action_executor, ACTION_LIBRARY, ACTION_CATEGORIES  # noqa
        from soar.playbook_engine import get_playbook_engine, PLAYBOOK_TEMPLATES, NODE_TYPES  # noqa
        from soar.alert_triage import get_alert_triage  # noqa
        from soar.case_manager import get_case_manager, STATUSES, CATEGORIES, SEVERITIES  # noqa
        from soar.execution_engine import get_execution_engine  # noqa
        from soar.soar_metrics import get_soar_metrics  # noqa
        from soar.soar_workflow import get_soar_workflow, WORKFLOW_STEPS  # noqa
        _MOD_AVAILABLE = True
        logger.info("soar_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("soar_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in TASKS:
        t = TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符 / 无效 Unicode，保证 JSON 序列化安全。"""
    if isinstance(obj, str):
        # 去掉常见控制字符（保留 \t \n \r）
        out_chars = [c for c in obj if ord(c) >= 32 or c in ("\t", "\n", "\r")]
        s = "".join(out_chars)
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
        return fail("SOAR 模块不可用，请检查加载日志", 503)
    return None


def _task_view(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"task_id": t["task_id"], "status": t["status"], "kind": t["kind"],
            "created_at": t["created_at"], "finished_at": t["finished_at"]}


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class IngestAlertRequest(BaseModel):
    title: str = ""
    rule: str = ""
    severity: str = "medium"
    src_ip: str = ""
    dst_ip: str = ""
    user: str = ""
    asset: str = "unknown"
    raw: Dict[str, Any] = Field(default_factory=dict)


class PlaybookCreateRequest(BaseModel):
    name: str
    category: str = "general"
    trigger: Dict[str, Any] = Field(default_factory=dict)


class PlaybookUpdateRequest(BaseModel):
    name: Optional[str] = None
    trigger: Optional[Dict[str, Any]] = None
    nodes: Optional[List[Dict[str, Any]]] = None
    edges: Optional[List[Dict[str, Any]]] = None


class PlaybookInstantiateRequest(BaseModel):
    template_id: str
    name: Optional[str] = None


class PlaybookPublishRequest(BaseModel):
    note: str = ""


class ActionExecuteRequest(BaseModel):
    action_id: str
    params: Dict[str, Any] = Field(default_factory=dict)
    operator: str = "soar-bot"
    dry_run: bool = True


class CaseCreateRequest(BaseModel):
    title: str
    severity: str = "medium"
    category: str = "其他"
    owner: str = ""
    description: str = ""
    related_alerts: List[str] = Field(default_factory=list)


class CaseCommentRequest(BaseModel):
    author: str
    body: str
    mentions: List[str] = Field(default_factory=list)


class RetroRequest(BaseModel):
    summary: str = ""
    root_cause: str = ""
    lessons: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)


class FPRequest(BaseModel):
    reason: str = ""
    analyst: str = ""


class ExecSubmitRequest(BaseModel):
    name: str
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    on_approval: str = "pause"


class ApprovalRequest(BaseModel):
    decision: str = "approve"
    approver: str = ""


class PlaybookTestRequest(BaseModel):
    context: Dict[str, Any] = Field(default_factory=dict)


# =========================================================================== #
# 1. 剧本编排引擎（13 个端点）
# =========================================================================== #
@router.get("/playbooks/templates")
def playbook_templates(category: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        eng = get_playbook_engine()
        return ok({"templates": eng.list_templates(category),
                   "categories": eng.template_categories(),
                   "total": len(eng.list_templates(category))})
    except Exception as e:
        logger.exception("playbook_templates error")
        return fail(f"查询模板失败: {e}", 500)


@router.get("/playbooks/templates/categories")
def playbook_template_categories():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"categories": get_playbook_engine().template_categories()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/playbooks/instantiate")
def playbook_instantiate(req: PlaybookInstantiateRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().instantiate(req.template_id, req.name)
        if not pb:
            return fail("模板不存在", 404)
        return ok(pb)
    except Exception as e:
        logger.exception("playbook_instantiate error")
        return fail(f"实例化失败: {e}", 500)


@router.get("/playbooks")
def playbook_list(status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"playbooks": get_playbook_engine().list_playbooks(status)})
    except Exception as e:
        return fail(f"查询剧本失败: {e}", 500)


@router.post("/playbooks")
def playbook_create(req: PlaybookCreateRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_playbook_engine().create(req.name, req.category, req.trigger))
    except Exception as e:
        logger.exception("playbook_create error")
        return fail(f"创建剧本失败: {e}", 500)


@router.get("/playbooks/{playbook_id}")
def playbook_detail(playbook_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().get(playbook_id)
        if not pb:
            return fail("剧本不存在", 404)
        return ok(pb.to_dict())
    except Exception as e:
        return fail(f"查询剧本失败: {e}", 500)


@router.put("/playbooks/{playbook_id}")
def playbook_update(playbook_id: str, req: PlaybookUpdateRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().update(playbook_id, req.model_dump(exclude_none=True))
        if not pb:
            return fail("剧本不存在", 404)
        return ok(pb)
    except Exception as e:
        logger.exception("playbook_update error")
        return fail(f"更新剧本失败: {e}", 500)


@router.post("/playbooks/{playbook_id}/publish")
def playbook_publish(playbook_id: str, req: PlaybookPublishRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        pb = get_playbook_engine().publish(playbook_id, req.note)
        if not pb:
            return fail("剧本不存在", 404)
        return ok(pb)
    except Exception as e:
        logger.exception("playbook_publish error")
        return fail(f"发布剧本失败: {e}", 500)


@router.delete("/playbooks/{playbook_id}")
def playbook_delete(playbook_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_flag = get_playbook_engine().delete(playbook_id)
        if not ok_flag:
            return fail("剧本不存在", 404)
        return ok({"deleted": playbook_id})
    except Exception as e:
        return fail(f"删除剧本失败: {e}", 500)


@router.get("/playbooks/{playbook_id}/versions")
def playbook_versions(playbook_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"history": get_playbook_engine().version_history(playbook_id)})
    except Exception as e:
        return fail(f"查询版本失败: {e}", 500)


@router.post("/playbooks/{playbook_id}/rollback")
def playbook_rollback(playbook_id: str, version: int = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_flag = get_playbook_engine().rollback(playbook_id, version)
        if not ok_flag:
            return fail("版本不存在或剧本不存在", 404)
        return ok({"rolled_back_to": version, "playbook": get_playbook_engine().get(playbook_id).to_dict()})
    except Exception as e:
        return fail(f"回滚失败: {e}", 500)


@router.get("/playbooks/{playbook_id}/validate")
def playbook_validate(playbook_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_playbook_engine().validate(playbook_id))
    except Exception as e:
        return fail(f"校验失败: {e}", 500)


@router.post("/playbooks/{playbook_id}/test")
def playbook_test(playbook_id: str, req: PlaybookTestRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("playbook_test")
        result = get_playbook_engine().test_run(playbook_id, req.context)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        logger.exception("playbook_test error")
        return fail(f"剧本测试失败: {e}", 500)


# =========================================================================== #
# 2. 响应动作库（6 个端点）
# =========================================================================== #
@router.get("/actions")
def action_list(category: Optional[str] = Query(default=None),
                risk: Optional[str] = Query(default=None),
                keyword: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        ex = get_action_executor()
        return ok({"actions": ex.list_actions(category, risk, keyword),
                   "categories": ACTION_CATEGORIES,
                   "total": len(ex.list_actions(category, risk, keyword))})
    except Exception as e:
        return fail(f"查询动作失败: {e}", 500)


@router.get("/actions/stats")
def action_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_action_executor().stats())
    except Exception as e:
        return fail(f"统计失败: {e}", 500)


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
        return fail(f"查询失败: {e}", 500)


@router.post("/actions/execute")
def action_execute(req: ActionExecuteRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        rec = get_action_executor().execute(req.action_id, req.params,
                                            req.operator, req.dry_run)
        return ok(rec)
    except Exception as e:
        logger.exception("action_execute error")
        return fail(f"动作执行失败: {e}", 500)


@router.post("/executions/{execution_id}/approve")
def action_approve(execution_id: str, approver: str = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_action_executor().approve(execution_id, approver))
    except Exception as e:
        return fail(f"审批失败: {e}", 500)


@router.get("/executions")
def action_history(limit: int = Query(default=50, ge=1, le=500)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"history": get_action_executor().history(limit)})
    except Exception as e:
        return fail(f"查询执行历史失败: {e}", 500)


# =========================================================================== #
# 3. 告警分诊与丰富（10 个端点）
# =========================================================================== #
@router.post("/alerts/ingest")
def alert_ingest(req: IngestAlertRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        t = get_alert_triage()
        rec = t.ingest(req.model_dump())
        return ok(rec)
    except Exception as e:
        logger.exception("alert_ingest error")
        return fail(f"接入告警失败: {e}", 500)


@router.get("/alerts")
def alert_list(status: Optional[str] = Query(default=None),
               priority: Optional[str] = Query(default=None),
               limit: int = Query(default=100, ge=1, le=500)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"alerts": get_alert_triage().list_alerts(status, priority, limit)})
    except Exception as e:
        return fail(f"查询告警失败: {e}", 500)


@router.get("/alerts/{alert_id}/enrich")
def alert_enrich(alert_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_alert_triage().enrich(alert_id))
    except Exception as e:
        return fail(f"富化失败: {e}", 500)


@router.get("/alerts/{alert_id}/score")
def alert_score(alert_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_alert_triage().score(alert_id))
    except Exception as e:
        return fail(f"评分失败: {e}", 500)


@router.get("/alerts/groups/list")
def alert_groups():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"groups": get_alert_triage().list_groups()})
    except Exception as e:
        return fail(f"查询聚合失败: {e}", 500)


@router.get("/alerts/{alert_id}/correlate")
def alert_correlate(alert_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"related": get_alert_triage().correlate(alert_id)})
    except Exception as e:
        return fail(f"关联分析失败: {e}", 500)


@router.post("/alerts/{alert_id}/auto-triage")
def alert_auto_triage(alert_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_alert_triage().auto_triage(alert_id))
    except Exception as e:
        return fail(f"自动分诊失败: {e}", 500)


@router.post("/alerts/{alert_id}/false-positive")
def alert_mark_fp(alert_id: str, req: FPRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_alert_triage().mark_false_positive(alert_id, req.reason, req.analyst))
    except Exception as e:
        return fail(f"标记失败: {e}", 500)


@router.get("/alerts/fp/stats")
def alert_fp_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_alert_triage().fp_stats())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/alerts/dashboard")
def alert_dashboard():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_alert_triage().dashboard())
    except Exception as e:
        return fail(f"查询仪表盘失败: {e}", 500)


# =========================================================================== #
# 4. 案例管理（12 个端点）
# =========================================================================== #
@router.post("/cases")
def case_create(req: CaseCreateRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_case_manager().create(req.title, req.severity, req.category,
                                            req.owner, req.description, req.related_alerts))
    except Exception as e:
        logger.exception("case_create error")
        return fail(f"创建案例失败: {e}", 500)


@router.get("/cases")
def case_list(status: Optional[str] = Query(default=None),
              severity: Optional[str] = Query(default=None),
              owner: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"cases": get_case_manager().list_cases(status, severity, owner)})
    except Exception as e:
        return fail(f"查询案例失败: {e}", 500)


@router.get("/cases/{case_id}")
def case_detail(case_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().get(case_id)
        if not c:
            return fail("案例不存在", 404)
        return ok(c)
    except Exception as e:
        return fail(f"查询案例失败: {e}", 500)


@router.post("/cases/{case_id}/status")
def case_set_status(case_id: str, status: str = Query(...),
                    actor: str = "system", note: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().update_status(case_id, status, actor, note)
        if not c:
            return fail("案例不存在或状态非法", 404)
        return ok(c)
    except Exception as e:
        return fail(f"状态更新失败: {e}", 500)


@router.post("/cases/{case_id}/assign")
def case_assign(case_id: str, new_owner: str = Query(...),
                actor: str = "system"):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().assign(case_id, new_owner, actor)
        if not c:
            return fail("案例不存在", 404)
        return ok(c)
    except Exception as e:
        return fail(f"分配失败: {e}", 500)


@router.post("/cases/{case_id}/evidence")
def case_add_evidence(case_id: str, artifact_id: str = Query(...),
                      source: str = "soar", note: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        ev = get_case_manager().add_evidence(case_id, artifact_id, source, note)
        if not ev:
            return fail("案例不存在", 404)
        return ok(ev)
    except Exception as e:
        return fail(f"挂载证据失败: {e}", 500)


@router.post("/cases/{case_id}/comments")
def case_add_comment(case_id: str, req: CaseCommentRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        cm = get_case_manager().add_comment(case_id, req.author, req.body, req.mentions)
        if not cm:
            return fail("案例不存在", 404)
        return ok(cm)
    except Exception as e:
        return fail(f"评论失败: {e}", 500)


@router.get("/cases/{case_id}/sla")
def case_sla(case_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_case_manager().sla_check(case_id))
    except Exception as e:
        return fail(f"SLA 查询失败: {e}", 500)


@router.post("/cases/{case_id}/escalate")
def case_escalate(case_id: str, level: str = "L2", reason: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        c = get_case_manager().escalate(case_id, level, reason)
        if not c:
            return fail("案例不存在", 404)
        return ok(c)
    except Exception as e:
        return fail(f"升级失败: {e}", 500)


@router.post("/cases/{case_id}/retro")
def case_retro(case_id: str, req: RetroRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        r = get_case_manager().retro(case_id, req.summary, req.root_cause,
                                     req.lessons, req.actions)
        if not r:
            return fail("案例不存在", 404)
        return ok(r)
    except Exception as e:
        logger.exception("case_retro error")
        return fail(f"复盘失败: {e}", 500)


@router.get("/cases/knowledge/list")
def case_knowledge(keyword: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"entries": get_case_manager().knowledge_list(keyword)})
    except Exception as e:
        return fail(f"查询知识库失败: {e}", 500)


@router.get("/cases/{case_id}/report")
def case_report(case_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        r = get_case_manager().report(case_id)
        if not r:
            return fail("案例不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(f"生成报告失败: {e}", 500)


# =========================================================================== #
# 5. 自动化执行引擎（7 个端点）
# =========================================================================== #
@router.post("/executions/submit")
def exec_submit(req: ExecSubmitRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task = get_execution_engine().submit(req.name, req.steps,
                                             req.context, req.on_approval)
        return ok(task)
    except Exception as e:
        logger.exception("exec_submit error")
        return fail(f"提交执行失败: {e}", 500)


@router.post("/executions/{task_id}/run")
def exec_run(task_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_execution_engine().run(task_id))
    except Exception as e:
        logger.exception("exec_run error")
        return fail(f"启动执行失败: {e}", 500)


@router.post("/executions/{task_id}/approve")
def exec_approve(task_id: str, req: ApprovalRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_execution_engine().approve_step(task_id, req.decision, req.approver))
    except Exception as e:
        return fail(f"审批失败: {e}", 500)


@router.get("/executions/list")
def exec_list(status: Optional[str] = Query(default=None),
              limit: int = Query(default=50, ge=1, le=500)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"tasks": get_execution_engine().list_tasks(status, limit)})
    except Exception as e:
        return fail(f"查询执行失败: {e}", 500)


@router.get("/executions/{task_id}")
def exec_detail(task_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        t = get_execution_engine().get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(f"查询执行失败: {e}", 500)


@router.get("/executions/audit/list")
def exec_audit(task_id: Optional[str] = Query(default=None),
               limit: int = Query(default=100, ge=1, le=1000)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"logs": get_execution_engine().audit(task_id, limit)})
    except Exception as e:
        return fail(f"查询审计失败: {e}", 500)


@router.get("/executions/performance/overview")
def exec_performance():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_execution_engine().performance())
    except Exception as e:
        return fail(f"查询性能失败: {e}", 500)


# =========================================================================== #
# 6. 运营度量（5 个端点）
# =========================================================================== #
@router.get("/metrics/summary")
def metrics_summary():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soar_metrics().summary())
    except Exception as e:
        return fail(f"查询度量失败: {e}", 500)


@router.get("/metrics/trend")
def metrics_trend(days: int = Query(default=7, ge=1, le=90)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"trend": get_soar_metrics().trend(days)})
    except Exception as e:
        return fail(f"查询趋势失败: {e}", 500)


@router.get("/metrics/analysts")
def metrics_analysts():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"analysts": get_soar_metrics().analyst_efficiency()})
    except Exception as e:
        return fail(f"查询分析师效率失败: {e}", 500)


@router.get("/metrics/playbooks")
def metrics_playbooks():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"distribution": get_soar_metrics().playbook_distribution()})
    except Exception as e:
        return fail(f"查询剧本分布失败: {e}", 500)


@router.get("/metrics/dashboard")
def metrics_dashboard():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soar_metrics().dashboard())
    except Exception as e:
        return fail(f"查询仪表盘失败: {e}", 500)


# =========================================================================== #
# 7. 综合工作流（4 个端点）
# =========================================================================== #
@router.post("/workflow/run")
def workflow_run(req: IngestAlertRequest,
                 auto_execute: bool = True, create_case: bool = True):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("soar_pipeline")
        result = get_soar_workflow().run_pipeline(req.model_dump(),
                                                 auto_execute, create_case)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        logger.exception("workflow_run error")
        return fail(f"工作流执行失败: {e}", 500)


@router.get("/workflow/runs")
def workflow_runs(limit: int = Query(default=50, ge=1, le=500)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"runs": get_soar_workflow().list_runs(limit)})
    except Exception as e:
        return fail(f"查询工作流失败: {e}", 500)


@router.get("/workflow/runs/{run_id}")
def workflow_detail(run_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        r = get_soar_workflow().get_run(run_id)
        if not r:
            return fail("工作流运行不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/workflow/overview")
def workflow_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_soar_workflow().overview())
    except Exception as e:
        return fail(f"查询总览失败: {e}", 500)
