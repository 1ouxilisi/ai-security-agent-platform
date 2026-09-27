# -*- coding: utf-8 -*-
"""
service_delivery_routes.py — 安全服务交付平台 REST API。

路由前缀: /api/v1/service-delivery
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。
覆盖 6 大模块 + 综合工作流，>=30 个端点。
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

router = APIRouter(prefix="/api/v1/service-delivery",
                   tags=["安全服务交付平台"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，缺失时回退到内置对象）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from service_delivery.project_manager import (
        ProjectManager, PROJECT_TYPES, PROJECT_STAGES, RISK_REGISTER,
    )
    from service_delivery.customer_portal import (
        CustomerPortal, CUSTOMER_TIERS, TICKET_STATUSES,
    )
    from service_delivery.time_billing import (
        TimeBillingEngine, STAFF_RATES, BUDGET_STATUS,
    )
    from service_delivery.sla_manager import (
        SLAManager, SLA_TEMPLATES, SLA_BREACH_LEVELS,
    )
    from service_delivery.deliverable_manager import (
        DeliverableManager, DELIVERABLE_TEMPLATES, REVIEW_STATUS,
    )
    from service_delivery.team_resource import (
        TeamResourceManager, SECURITY_SKILLS, ROLE_PERMISSIONS,
    )
    from service_delivery.delivery_workflow import (
        DeliveryWorkflow, get_delivery_workflow, DELIVERY_STAGES,
    )
    _MOD_AVAILABLE = True
    logger.info("service_delivery_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("service_delivery_routes: load failed: %s", e)
    ProjectManager = None  # type: ignore
    CustomerPortal = None  # type: ignore
    TimeBillingEngine = None  # type: ignore
    SLAManager = None  # type: ignore
    DeliverableManager = None  # type: ignore
    TeamResourceManager = None  # type: ignore
    DeliveryWorkflow = None  # type: ignore
    get_delivery_workflow = None  # type: ignore
    PROJECT_TYPES = {}
    PROJECT_STAGES = []
    RISK_REGISTER = {}
    CUSTOMER_TIERS = {}
    TICKET_STATUSES = []
    STAFF_RATES = {}
    BUDGET_STATUS = {}
    SLA_TEMPLATES = {}
    SLA_BREACH_LEVELS = {}
    DELIVERABLE_TEMPLATES = {}
    REVIEW_STATUS = []
    SECURITY_SKILLS = {}
    ROLE_PERMISSIONS = {}
    DELIVERY_STAGES = []


# --------------------------------------------------------------------------- #
# 单例业务引擎（惰性初始化）
# --------------------------------------------------------------------------- #
_pm: Optional[Any] = None
_cp: Optional[Any] = None
_tb: Optional[Any] = None
_sla: Optional[Any] = None
_dm: Optional[Any] = None
_tr: Optional[Any] = None


def _engines() -> None:
    global _pm, _cp, _tb, _sla, _dm, _tr
    if not _MOD_AVAILABLE:
        return
    if _pm is None:
        _pm = ProjectManager()
        _cp = CustomerPortal()
        _tb = TimeBillingEngine()
        _sla = SLAManager()
        _dm = DeliverableManager()
        _tr = TeamResourceManager()


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
import re as _re
_CTRL_RE = _re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理控制字符，防止 JSON 编码异常。"""
    if isinstance(obj, str):
        return _CTRL_RE.sub(" ", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(x) for x in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("服务交付模块不可用，请检查加载日志", 503)
    _engines()
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class CreateProjectRequest(BaseModel):
    name: str
    type: str = "pentest"
    customer: str = ""
    start_date: str = ""
    end_date: str = ""
    budget: float = 0.0
    manager: str = "未分配"
    description: str = ""


class UpdateProgressRequest(BaseModel):
    progress: int = 0
    stage: Optional[str] = None


class CreateWBSRequest(BaseModel):
    name: str
    owner: str
    start: str
    end: str
    stage: str = "execution"


class CompleteMilestoneRequest(BaseModel):
    name: str


class AddRiskRequest(BaseModel):
    title: str
    category: str = "general"
    probability: float = 0.3
    impact: float = 0.5
    mitigation: str = ""
    owner: str = "项目经理"


class RegisterCustomerRequest(BaseModel):
    name: str
    tier: str = "business"
    contact: str = ""
    email: str = ""
    phone: str = ""
    city: str = ""


class CreateInvoiceRequest(BaseModel):
    customer_id: str
    title: str
    amount: float
    due_date: str


class SubmitTicketRequest(BaseModel):
    subject: str
    priority: str = "medium"
    content: str = ""


class UpdateTicketRequest(BaseModel):
    status: str
    assignee: Optional[str] = None


class LogCommRequest(BaseModel):
    direction: str = "out"
    channel: str = "email"
    sender: str = "客户经理"
    receiver: str = ""
    content: str = ""


class SatisfactionRequest(BaseModel):
    score: int = 5
    comment: str = ""
    project_id: str = ""


class LogTimeRequest(BaseModel):
    project_id: str
    person: str
    level: str = "mid"
    task: str = ""
    hours: float = 1.0
    date: str = ""
    note: str = ""


class SetBudgetRequest(BaseModel):
    approved: float
    committed: float = 0.0


class GenerateBillRequest(BaseModel):
    project_id: str
    customer_id: str
    title: str
    amount: float
    due_date: str


class PaymentRequest(BaseModel):
    amount: float
    method: str = "bank_transfer"


class QuoteRequest(BaseModel):
    customer_id: str
    project_type: str = "pentest"
    estimated_hours: float = 40
    level: str = "senior"
    margin: float = 0.35


class CreateSLAInstanceRequest(BaseModel):
    customer_id: str
    template: str = "P2-high"
    start: str = ""
    end: str = ""


class LogSLAEventRequest(BaseModel):
    response_min: int = 30
    resolve_min: int = 300
    status: str = "resolved"


class CreateDeliverableRequest(BaseModel):
    project_id: str
    template: str = "pentest_report"
    title: str
    owner: str = "张工"


class AddVersionRequest(BaseModel):
    author: str
    note: str = ""


class ReviewRequest(BaseModel):
    reviewer: str
    result: str = "pass"
    comment: str = ""


class SignOffRequest(BaseModel):
    customer_name: str = ""


class AddStaffRequest(BaseModel):
    name: str
    role: str = "consultant"
    level: str = "中级"
    skills: List[str] = Field(default_factory=list)


class AssignRequest(BaseModel):
    emp_id: str
    project_id: str
    role: str = "成员"
    allocation_pct: int = 100
    start: str = ""
    end: str = ""


class AddKnowledgeRequest(BaseModel):
    title: str
    author: str
    domain: str = "通用"
    content: str = ""


class WorkflowKickoffRequest(BaseModel):
    project_id: str
    customer_id: str
    manager: str = "项目经理"


# =========================================================================== #
# 1. 项目管理
# =========================================================================== #
@router.get("/project-types")
def project_types():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"types": PROJECT_TYPES, "stages": PROJECT_STAGES,
                   "risk_register_seed": list(RISK_REGISTER.values())})
    except Exception as e:
        logger.exception("project_types error")
        return fail(f"查询失败: {e}", 500)


@router.get("/projects")
def list_projects(status: Optional[str] = Query(default=None),
                  type: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_pm.list_projects(status, type))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/projects")
def create_project(req: CreateProjectRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        pid = req.start_date or time.strftime("%Y-%m-%d")
        proj = _pm.create_project(req.name, req.type, req.customer,
                                 req.start_date, req.end_date,
                                 req.budget, req.manager, req.description)
        return ok(proj)
    except Exception as e:
        logger.exception("create_project error")
        return fail(f"创建项目失败: {e}", 500)


@router.get("/projects/{pid}")
def get_project(pid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        p = _pm.get_project(pid)
        if not p:
            return fail("项目不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/projects/{pid}/progress")
def update_progress(pid: str, req: UpdateProgressRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        p = _pm.update_progress(pid, req.progress, req.stage)
        if not p:
            return fail("项目不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(f"更新失败: {e}", 500)


@router.get("/projects/{pid}/wbs")
def get_wbs(pid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_pm.get_wbs(pid))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/projects/{pid}/wbs")
def add_wbs(pid: str, req: CreateWBSRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_pm.add_wbs_task(pid, req.name, req.owner,
                                   req.start, req.end, req.stage))
    except Exception as e:
        return fail(f"新增 WBS 失败: {e}", 500)


@router.get("/projects/{pid}/gantt")
def gantt(pid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_pm.gantt_data(pid))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/projects/{pid}/milestones")
def milestones(pid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_pm.get_milestones(pid))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/projects/{pid}/milestones/complete")
def complete_milestone(pid: str, req: CompleteMilestoneRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_flag = _pm.complete_milestone(pid, req.name)
        return ok({"completed": ok_flag, "milestones": _pm.get_milestones(pid)})
    except Exception as e:
        return fail(f"操作失败: {e}", 500)


@router.get("/projects/{pid}/risks")
def project_risks(pid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_pm.list_risks(pid))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/projects/{pid}/risks")
def add_risk(pid: str, req: AddRiskRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_pm.add_risk(pid, req.title, req.category,
                               req.probability, req.impact,
                               req.mitigation, req.owner))
    except Exception as e:
        return fail(f"登记风险失败: {e}", 500)


@router.get("/project-dashboard")
def project_dashboard():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_pm.dashboard())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 2. 客户门户
# =========================================================================== #
@router.get("/customers")
def list_customers(tier: Optional[str] = Query(default=None),
                   status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.list_customers(tier, status))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/customers")
def register_customer(req: RegisterCustomerRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.register_customer(req.name, req.tier, req.contact,
                                        req.email, req.phone, req.city))
    except Exception as e:
        return fail(f"注册客户失败: {e}", 500)


@router.get("/customers/{cid}")
def get_customer(cid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        c = _cp.get_customer(cid)
        if not c:
            return fail("客户不存在", 404)
        return ok(c)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/customers/{cid}/contracts")
def customer_contracts(cid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.list_contracts(cid))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/customers/{cid}/invoices")
def customer_invoices(cid: str,
                      status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.list_invoices(cid, status))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/customers/{cid}/invoices")
def create_customer_invoice(cid: str, req: CreateInvoiceRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.create_invoice(cid, req.title, req.amount, req.due_date))
    except Exception as e:
        return fail(f"创建发票失败: {e}", 500)


@router.get("/customers/{cid}/tickets")
def customer_tickets(cid: str,
                     status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.list_tickets(cid, status))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/customers/{cid}/tickets")
def submit_ticket(cid: str, req: SubmitTicketRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.submit_ticket(cid, req.subject, req.priority, req.content))
    except Exception as e:
        return fail(f"提交工单失败: {e}", 500)


@router.post("/tickets/{tid}")
def update_ticket(tid: str, req: UpdateTicketRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        tk = _cp.update_ticket(tid, req.status, req.assignee)
        if not tk:
            return fail("工单不存在", 404)
        return ok(tk)
    except Exception as e:
        return fail(f"更新工单失败: {e}", 500)


@router.get("/customers/{cid}/communications")
def customer_communications(cid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.get_communications(cid))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/customers/{cid}/communications")
def log_communication(cid: str, req: LogCommRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.log_communication(cid, req.direction, req.channel,
                                         req.sender, req.receiver, req.content))
    except Exception as e:
        return fail(f"记录沟通失败: {e}", 500)


@router.post("/customers/{cid}/satisfaction")
def add_satisfaction(cid: str, req: SatisfactionRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.add_satisfaction(cid, req.score, req.comment,
                                       req.project_id))
    except Exception as e:
        return fail(f"提交评价失败: {e}", 500)


@router.get("/customers/{cid}/assets")
def customer_assets(cid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.list_assets(cid))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/customer-dashboard")
def customer_dashboard():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_cp.customer_dashboard())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 3. 工时与计费
# =========================================================================== #
@router.post("/timesheets")
def log_time(req: LogTimeRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        ts = _tb.log_time(req.project_id, req.person, req.level,
                          req.task, req.hours, req.date, req.note)
        return ok(ts)
    except Exception as e:
        logger.exception("log_time error")
        return fail(f"记录工时失败: {e}", 500)


@router.get("/timesheets")
def list_timesheets(project_id: Optional[str] = Query(default=None),
                    person: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tb.list_timesheets(project_id, person))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/budgets")
def list_budgets():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tb.list_budgets())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/budgets/{pid}")
def set_budget(pid: str, req: SetBudgetRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tb.set_budget(pid, req.approved, req.committed))
    except Exception as e:
        return fail(f"设置预算失败: {e}", 500)


@router.post("/billing-invoices")
def generate_invoice(req: GenerateBillRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tb.generate_invoice(req.project_id, req.customer_id,
                                       req.title, req.amount, req.due_date))
    except Exception as e:
        return fail(f"生成发票失败: {e}", 500)


@router.get("/billing-invoices")
def list_billing_invoices(project_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tb.list_invoices(project_id))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/billing-invoices/{iid}/payments")
def record_payment(iid: str, req: PaymentRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        p = _tb.record_payment(iid, req.amount, req.method)
        if not p:
            return fail("发票不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(f"登记收款失败: {e}", 500)


@router.post("/quotes")
def create_quote(req: QuoteRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tb.create_quote(req.customer_id, req.project_type,
                                   req.estimated_hours, req.level,
                                   req.margin))
    except Exception as e:
        return fail(f"创建报价失败: {e}", 500)


@router.get("/quotes")
def list_quotes():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tb.list_quotes())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/profitability")
def profitability():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tb.profitability())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/billing-dashboard")
def billing_dashboard():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tb.billing_dashboard())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 4. SLA 管理
# =========================================================================== #
@router.get("/sla/templates")
def sla_templates():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"templates": SLA_TEMPLATES,
                   "levels": SLA_BREACH_LEVELS})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/sla/instances")
def create_sla_instance(req: CreateSLAInstanceRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_sla.create_instance(req.customer_id, req.template,
                                       req.start, req.end))
    except Exception as e:
        return fail(f"创建 SLA 失败: {e}", 500)


@router.get("/sla/instances")
def list_sla_instances(customer_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_sla.list_instances(customer_id))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/sla/instances/{sid}/monitor")
def monitor_sla(sid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        m = _sla.monitor(sid)
        if not m:
            return fail("SLA 实例不存在", 404)
        return ok(m)
    except Exception as e:
        return fail(f"监控失败: {e}", 500)


@router.post("/sla/instances/{sid}/events")
def log_sla_event(sid: str, req: LogSLAEventRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        ev = _sla.log_event(sid, req.response_min, req.resolve_min, req.status)
        return ok({"event": ev, "monitor": _sla.monitor(sid)})
    except Exception as e:
        return fail(f"记录事件失败: {e}", 500)


@router.get("/sla/alerts")
def list_sla_alerts(level: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_sla.list_alerts(level))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/sla/instances/{sid}/report")
def sla_report(sid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_sla.report(sid))
    except Exception as e:
        return fail(f"生成报告失败: {e}", 500)


@router.get("/sla-dashboard")
def sla_dashboard():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_sla.dashboard())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 5. 交付物管理
# =========================================================================== #
@router.get("/deliverables")
def list_deliverables(project_id: Optional[str] = Query(default=None),
                      status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_dm.list_items(project_id, status))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/deliverables")
def create_deliverable(req: CreateDeliverableRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_dm.create_item(req.project_id, req.template,
                                  req.title, req.owner))
    except Exception as e:
        return fail(f"创建交付物失败: {e}", 500)


@router.get("/deliverables/{did}/versions")
def deliverable_versions(did: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_dm.list_versions(did))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/deliverables/{did}/versions")
def add_deliverable_version(did: str, req: AddVersionRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        v = _dm.add_version(did, req.author, req.note)
        if not v:
            return fail("交付物不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(f"新增版本失败: {e}", 500)


@router.post("/deliverables/{did}/reviews")
def submit_review(did: str, req: ReviewRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        r = _dm.submit_review(did, req.reviewer, req.result, req.comment)
        if not r:
            return fail("交付物不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(f"提交审核失败: {e}", 500)


@router.post("/deliverables/{did}/quality-check")
def quality_check(did: str):
    try:
        g = _guard()
        if g is not None:
            return g
        r = _dm.quality_check(did)
        if not r:
            return fail("交付物不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(f"质量检查失败: {e}", 500)


@router.post("/deliverables/{did}/sign-off")
def sign_off(did: str, req: SignOffRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        cert = _dm.sign_off(did, req.customer_name)
        if not cert:
            return fail("交付物不存在", 404)
        return ok(cert)
    except Exception as e:
        return fail(f"签收失败: {e}", 500)


@router.post("/deliverables/{did}/archive")
def archive_deliverable(did: str):
    try:
        g = _guard()
        if g is not None:
            return g
        item = _dm.archive(did)
        if not item:
            return fail("交付物不存在", 404)
        return ok(item)
    except Exception as e:
        return fail(f"归档失败: {e}", 500)


@router.get("/deliverable-stats")
def deliverable_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_dm.stats())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 6. 团队与资源
# =========================================================================== #
@router.get("/staff")
def list_staff(role: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tr.list_staff(role))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/staff")
def add_staff(req: AddStaffRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tr.add_staff(req.name, req.role, req.level, req.skills))
    except Exception as e:
        return fail(f"新增人员失败: {e}", 500)


@router.get("/skill-matrix")
def skill_matrix():
    try:
        g = _guard()
        if g is not None:
            return ok(_tr.skill_matrix())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/assignments")
def list_assignments(project_id: Optional[str] = Query(default=None),
                     emp_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(_tr.list_assignments(project_id, emp_id))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/assignments")
def assign_staff(req: AssignRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        a = _tr.assign(req.emp_id, req.project_id, req.role,
                       req.allocation_pct, req.start, req.end)
        if not a:
            return fail("人员不存在", 404)
        return ok(a)
    except Exception as e:
        return fail(f"分配失败: {e}", 500)


@router.get("/utilization")
def utilization():
    try:
        g = _guard()
        if g is not None:
            return ok(_tr.utilization())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/knowledge")
def list_knowledge(domain: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return ok(_tr.list_knowledge(domain))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/knowledge")
def add_knowledge(req: AddKnowledgeRequest):
    try:
        g = _guard()
        if g is not None:
            return ok(_tr.add_knowledge(req.title, req.author,
                                        req.domain, req.content))
    except Exception as e:
        return fail(f"新增知识失败: {e}", 500)


@router.get("/team-dashboard")
def team_dashboard():
    try:
        g = _guard()
        if g is not None:
            return ok(_tr.dashboard())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 7. 综合交付工作流
# =========================================================================== #
@router.post("/workflow/kickoff")
def workflow_kickoff(req: WorkflowKickoffRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_delivery_workflow()
        wid = "WF-" + uuid.uuid4().hex[:8].upper()
        inst = wf.kickoff(wid, req.project_id, req.customer_id, req.manager)
        return ok(inst)
    except Exception as e:
        logger.exception("workflow_kickoff error")
        return fail(f"启动工作流失败: {e}", 500)


@router.post("/workflow/{wid}/advance")
def workflow_advance(wid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        wf = get_delivery_workflow()
        inst = wf.advance(wid)
        if not inst:
            return fail("工作流不存在或已结束", 404)
        return ok(inst)
    except Exception as e:
        return fail(f"推进工作流失败: {e}", 500)


@router.get("/workflow")
def list_workflows():
    try:
        g = _guard()
        if g is not None:
            return ok(get_delivery_workflow().list())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/workflow/{wid}")
def get_workflow(wid: str):
    try:
        g = _guard()
        if g is not None:
            inst = get_delivery_workflow().get(wid)
            if not inst:
                return fail("工作流不存在", 404)
            return ok(inst)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/workflow/{wid}/report")
def workflow_report(wid: str):
    try:
        g = _guard()
        if g is not None:
            wf = get_delivery_workflow()
            inst = wf.get(wid)
            if not inst:
                return fail("工作流不存在", 404)
            report = wf.report(
                wid,
                project_dash=_pm.dashboard() if _pm else None,
                billing_dash=_tb.billing_dashboard() if _tb else None,
                sla_dash=_sla.dashboard() if _sla else None,
                deliverable_stats=_dm.stats() if _dm else None,
                team_dash=_tr.dashboard() if _tr else None,
                customer_dash=_cp.customer_dashboard() if _cp else None,
            )
            return ok(report)
    except Exception as e:
        logger.exception("workflow_report error")
        return fail(f"生成报告失败: {e}", 500)


# =========================================================================== #
# 8. 任务查询（异步模拟）
# =========================================================================== #
@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        t = _TASKS.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/health")
def health():
    try:
        return ok({
            "module": "service_delivery",
            "version": "14.4.0",
            "available": _MOD_AVAILABLE,
            "engines_initialized": _pm is not None,
            "endpoints_expected": ">=30",
        })
    except Exception as e:
        return fail(f"健康检查失败: {e}", 500)
