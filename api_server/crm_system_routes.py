# -*- coding: utf-8 -*-
"""
crm_system_routes.py — 客户管理 CRM REST API（40+ 端点）。

路由前缀: /api/v1/crm-system
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

router = APIRouter(prefix="/api/v1/crm-system", tags=["客户管理CRM"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from crm_system import DB, seed_if_needed, now_str
    from crm_system.customer_manager import manager as customers
    from crm_system.sales_pipeline import pipeline
    from crm_system.communication_activity import comm
    from crm_system.product_pricing import pricing
    from crm_system.customer_service import service
    from crm_system.crm_dashboard import dashboard
    seed_if_needed()
    _MOD_AVAILABLE = True
    logger.info("crm_system_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("crm_system_routes: load failed: %s", e)


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
    """递归清理数据中的控制字符，防止序列化/编码问题。"""
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("CRM 模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class CustomerReq(BaseModel):
    name: str = ""
    industry: str = ""
    size: str = ""
    region: str = ""
    level: str = "C"
    source: str = "官网咨询"
    stage: str = "线索"
    website: str = ""
    address: str = ""
    tags: List[str] = Field(default_factory=list)
    remark: str = ""
    custom_fields: Dict[str, Any] = Field(default_factory=dict)
    owner: str = "system"


class CustomerUpdateReq(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None
    size: Optional[str] = None
    region: Optional[str] = None
    level: Optional[str] = None
    source: Optional[str] = None
    website: Optional[str] = None
    address: Optional[str] = None
    remark: Optional[str] = None
    tags: Optional[List[str]] = None
    custom_fields: Optional[Dict[str, Any]] = None


class ContactReq(BaseModel):
    customer_id: str = ""
    name: str = ""
    title: str = ""
    phone: str = ""
    email: str = ""
    decision_role: str = "影响者"
    preference: str = "电话"
    birthday: str = ""
    anniversary: str = ""


class StageReq(BaseModel):
    stage: str
    note: str = ""


class OpportunityReq(BaseModel):
    name: str = ""
    customer_id: str = ""
    contact_id: str = ""
    amount: float = 0
    stage: str = "线索"
    expected_close: str = ""
    owner: str = ""
    competitor: str = ""


class FollowupReq(BaseModel):
    type: str = "电话"
    content: str = ""
    result: str = ""
    next_action: str = ""
    next_followup: str = ""


class QuoteReq(BaseModel):
    name: str = ""
    customer_id: str = ""
    opportunity_id: str = ""
    items: List[Dict[str, Any]] = Field(default_factory=list)
    discount: float = 0
    valid_until: str = ""


class ContractReq(BaseModel):
    name: str = ""
    customer_id: str = ""
    amount: float = 0
    period: str = "12个月"
    payment_method: str = "年付"
    terms: List[str] = Field(default_factory=list)
    template_id: str = ""
    end_date: str = ""


class OrderReq(BaseModel):
    customer_id: str = ""
    source_quote_id: str = ""
    items: List[Dict[str, Any]] = Field(default_factory=list)
    discount: float = 0
    amount: float = 0


class CommReq(BaseModel):
    customer_id: str = ""
    contact_id: str = ""
    type: str = "电话"
    content: str = ""
    participants: List[str] = Field(default_factory=list)
    result: str = ""
    next_action: str = ""


class ActivityReq(BaseModel):
    name: str = ""
    type: str = "线上研讨会"
    time: str = ""
    location: str = ""
    content: str = ""
    customer_ids: List[str] = Field(default_factory=list)
    contact_ids: List[str] = Field(default_factory=list)
    cost: float = 0
    leads: int = 0
    revenue_generated: float = 0


class TaskReq(BaseModel):
    title: str = ""
    type: str = "跟进"
    customer_id: str = ""
    opportunity_id: str = ""
    owner: str = ""
    due_date: str = ""
    priority: str = "中"
    repeat: str = "不重复"
    remind: bool = True


class ReminderReq(BaseModel):
    type: str = "自定义"
    customer_id: str = ""
    title: str = ""
    due: str = ""
    channel: str = "站内"


class EmailReq(BaseModel):
    customer_id: str = ""
    to: str = ""
    subject: str = ""
    body: str = ""
    template: str = ""


class CallReq(BaseModel):
    customer_id: str = ""
    direction: str = "out"
    phone: str = ""
    duration_sec: int = 0
    result: str = ""


class ProductReq(BaseModel):
    name: str = ""
    category: str = "SaaS产品"
    description: str = ""
    price: float = 0
    pricing_strategy: str = "标准定价"


class InvoiceReq(BaseModel):
    customer_id: str = ""
    order_id: str = ""
    type: str = "增值税专用发票"
    title: str = ""
    tax_number: str = ""
    amount: float = 0
    items: List[Dict[str, Any]] = Field(default_factory=list)


class TicketReq(BaseModel):
    customer_id: str = ""
    title: str = ""
    category: str = "技术支持"
    priority: str = "中"
    assignee: str = ""
    description: str = ""


class TicketReplyReq(BaseModel):
    author: str = "客服"
    content: str = ""


class SurveyReq(BaseModel):
    name: str = ""
    template: str = "标准NPS"
    questions: List[str] = Field(default_factory=list)
    channel: str = "邮件"
    customer_ids: List[str] = Field(default_factory=list)


class SurveyRespReq(BaseModel):
    respondent: str = ""
    answers: Dict[str, Any] = Field(default_factory=dict)
    nps: int = 0


class RevenueReq(BaseModel):
    customer_id: str = ""
    order_id: str = ""
    type: str = "新购"
    amount: float = 0
    installments: int = 1
    is_refund: bool = False


# =========================================================================== #
# 1. 客户管理
# =========================================================================== #
@router.get("/customers")
def list_customers(keyword: str = "", stage: str = "", industry: str = "",
                   level: str = "", region: str = ""):
    try:
        g = _guard()
        if g:
            return g
        rows = customers.list_customers(keyword, stage, industry, level, region)
        return ok(rows)
    except Exception as e:  # pragma: no cover
        logger.exception("list_customers failed")
        return fail(str(e))


@router.post("/customers")
def create_customer(req: CustomerReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(customers.create_customer(req.model_dump()))
    except Exception as e:
        logger.exception("create_customer failed")
        return fail(str(e))


@router.get("/customers/{cid}")
def get_customer_360(cid: str):
    try:
        g = _guard()
        if g:
            return g
        v = customers.view_360(cid)
        if not v:
            return fail("客户不存在", 404)
        return ok(v)
    except Exception as e:
        logger.exception("get_customer_360 failed")
        return fail(str(e))


@router.put("/customers/{cid}")
def update_customer(cid: str, req: CustomerUpdateReq):
    try:
        g = _guard()
        if g:
            return g
        v = customers.update_customer(cid, {k: val for k, val in req.model_dump().items() if val is not None})
        if not v:
            return fail("客户不存在", 404)
        return ok(v)
    except Exception as e:
        logger.exception("update_customer failed")
        return fail(str(e))


@router.delete("/customers/{cid}")
def delete_customer(cid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok({"deleted": customers.delete_customer(cid)})
    except Exception as e:
        logger.exception("delete_customer failed")
        return fail(str(e))


@router.get("/customers/{cid}/contacts")
def customer_contacts(cid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(customers.list_contacts(cid))
    except Exception as e:
        return fail(str(e))


@router.post("/customers/{cid}/contacts")
def add_customer_contact(cid: str, req: ContactReq):
    try:
        g = _guard()
        if g:
            return g
        data = req.model_dump()
        data["customer_id"] = cid
        return ok(customers.add_contact(data))
    except Exception as e:
        return fail(str(e))


@router.get("/customers/{cid}/lifecycle")
def customer_lifecycle(cid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(customers.lifecycle(cid))
    except Exception as e:
        return fail(str(e))


@router.get("/customers/{cid}/health")
def customer_health(cid: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(customers.compute_health(cid))
    except Exception as e:
        return fail(str(e))


@router.post("/customers/{cid}/stage")
def change_customer_stage(cid: str, req: StageReq):
    try:
        g = _guard()
        if g:
            return g
        v = customers.change_stage(cid, req.stage, req.note)
        if not v:
            return fail("客户不存在或阶段非法", 400)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.get("/segments")
def customer_segments():
    try:
        g = _guard()
        if g:
            return g
        return ok(customers.segments())
    except Exception as e:
        return fail(str(e))


@router.get("/contacts")
def list_all_contacts(customer_id: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(customers.list_contacts(customer_id))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 2. 销售漏斗与商机
# =========================================================================== #
@router.get("/pipeline/funnel")
def sales_funnel():
    try:
        g = _guard()
        if g:
            return g
        return ok(pipeline.funnel())
    except Exception as e:
        return fail(str(e))


@router.get("/opportunities")
def list_opportunities(stage: str = "", customer_id: str = "", owner: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(pipeline.list_opportunities(stage, customer_id, owner))
    except Exception as e:
        return fail(str(e))


@router.post("/opportunities")
def create_opportunity(req: OpportunityReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(pipeline.create_opportunity(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.get("/opportunities/{oid}")
def get_opportunity(oid: str):
    try:
        g = _guard()
        if g:
            return g
        v = pipeline.get_opportunity(oid)
        if not v:
            return fail("商机不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.post("/opportunities/{oid}/stage")
def advance_opp_stage(oid: str, req: StageReq):
    try:
        g = _guard()
        if g:
            return g
        v = pipeline.advance_stage(oid, req.stage, req.note)
        if not v:
            return fail("商机不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.post("/opportunities/{oid}/win")
def win_opp(oid: str, reason: str = ""):
    try:
        g = _guard()
        if g:
            return g
        v = pipeline.win_opportunity(oid, reason)
        if not v:
            return fail("商机不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.post("/opportunities/{oid}/follow-ups")
def add_followup(oid: str, req: FollowupReq):
    try:
        g = _guard()
        if g:
            return g
        v = pipeline.add_followup(oid, req.model_dump())
        if not v:
            return fail("商机不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.get("/quotes")
def list_quotes(customer_id: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(pipeline.list_quotes(customer_id))
    except Exception as e:
        return fail(str(e))


@router.post("/quotes")
def create_quote(req: QuoteReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(pipeline.create_quote(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.post("/quotes/{qid}/convert")
def convert_quote(qid: str):
    try:
        g = _guard()
        if g:
            return g
        v = pipeline.quote_to_order(qid)
        if not v:
            return fail("报价单不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.get("/contracts")
def list_contracts(customer_id: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(pipeline.list_contracts(customer_id))
    except Exception as e:
        return fail(str(e))


@router.post("/contracts")
def create_contract(req: ContractReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(pipeline.create_contract(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.post("/contracts/{cid}/sign")
def sign_contract(cid: str, esigned: bool = True):
    try:
        g = _guard()
        if g:
            return g
        v = pipeline.sign_contract(cid, esigned)
        if not v:
            return fail("合同不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.get("/orders")
def list_orders(customer_id: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(pipeline.list_orders(customer_id))
    except Exception as e:
        return fail(str(e))


@router.post("/orders")
def create_order(req: OrderReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(pipeline.create_order(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.post("/orders/{oid}/status")
def update_order_status(oid: str, field: str, value: str):
    try:
        g = _guard()
        if g:
            return g
        v = pipeline.update_order_status(oid, field, value)
        if not v:
            return fail("订单不存在或字段非法", 400)
        return ok(v)
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 3. 沟通与活动
# =========================================================================== #
@router.get("/communications")
def list_communications(customer_id: str = "", ctype: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.list_communications(customer_id, ctype))
    except Exception as e:
        return fail(str(e))


@router.post("/communications")
def add_communication(req: CommReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.add_communication(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.get("/marketing-activities")
def list_marketing_activities():
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.list_activities())
    except Exception as e:
        return fail(str(e))


@router.post("/marketing-activities")
def create_marketing_activity(req: ActivityReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.create_activity(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.get("/tasks")
def list_tasks(status: str = "", owner: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.list_tasks(status, owner))
    except Exception as e:
        return fail(str(e))


@router.post("/tasks")
def create_task(req: TaskReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.create_task(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.post("/tasks/{tid}/complete")
def complete_task(tid: str):
    try:
        g = _guard()
        if g:
            return g
        v = comm.complete_task(tid)
        if not v:
            return fail("任务不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.get("/reminders")
def list_reminders(include_done: bool = False):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.list_reminders(include_done))
    except Exception as e:
        return fail(str(e))


@router.post("/reminders")
def add_reminder(req: ReminderReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.add_reminder(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.get("/reminders/check")
def check_reminders():
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.check_reminders())
    except Exception as e:
        return fail(str(e))


@router.post("/emails/send")
def send_email(req: EmailReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.send_email(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.get("/emails")
def list_emails(customer_id: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.list_emails(customer_id))
    except Exception as e:
        return fail(str(e))


@router.get("/email-stats")
def email_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.email_stats())
    except Exception as e:
        return fail(str(e))


@router.post("/calls/log")
def log_call(req: CallReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.log_call(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.get("/calls")
def list_calls(customer_id: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.list_calls(customer_id))
    except Exception as e:
        return fail(str(e))


@router.get("/call-stats")
def call_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(comm.call_stats())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 4. 产品与定价
# =========================================================================== #
@router.get("/products")
def list_products(keyword: str = "", category: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(pricing.list_products(keyword, category))
    except Exception as e:
        return fail(str(e))


@router.post("/products")
def create_product(req: ProductReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(pricing.create_product(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.get("/pricing/strategies")
def list_pricing_strategies():
    try:
        g = _guard()
        if g:
            return g
        return ok(pricing.list_pricing_strategies())
    except Exception as e:
        return fail(str(e))


@router.post("/pricing/calculate")
def calculate_price(base_price: float = 0, strategy: str = "标准定价",
                    qty: int = 1, users: int = 1):
    try:
        g = _guard()
        if g:
            return g
        return ok(pricing.apply_discount(base_price, strategy, qty, users))
    except Exception as e:
        return fail(str(e))


@router.get("/templates/quotes")
def list_quote_templates():
    try:
        g = _guard()
        if g:
            return g
        return ok(pricing.list_quote_templates())
    except Exception as e:
        return fail(str(e))


@router.get("/templates/contracts")
def list_contract_templates():
    try:
        g = _guard()
        if g:
            return g
        return ok(pricing.list_contract_templates())
    except Exception as e:
        return fail(str(e))


@router.get("/invoices")
def list_invoices(customer_id: str = "", status: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(pricing.list_invoices(customer_id, status))
    except Exception as e:
        return fail(str(e))


@router.post("/invoices")
def create_invoice(req: InvoiceReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(pricing.create_invoice(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.post("/invoices/{iid}/status")
def update_invoice_status(iid: str, status: str):
    try:
        g = _guard()
        if g:
            return g
        v = pricing.update_invoice_status(iid, status)
        if not v:
            return fail("发票不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.post("/revenue/recognize")
def recognize_revenue(req: RevenueReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(pricing.recognize_revenue(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.get("/revenue/summary")
def revenue_summary():
    try:
        g = _guard()
        if g:
            return g
        return ok(pricing.revenue_summary())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 5. 客户服务
# =========================================================================== #
@router.get("/tickets")
def list_tickets(status: str = "", customer_id: str = "", priority: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(service.list_tickets(status, customer_id, priority))
    except Exception as e:
        return fail(str(e))


@router.post("/tickets")
def create_ticket(req: TicketReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(service.create_ticket(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.post("/tickets/{tid}/reply")
def reply_ticket(tid: str, req: TicketReplyReq):
    try:
        g = _guard()
        if g:
            return g
        v = service.reply_ticket(tid, req.model_dump())
        if not v:
            return fail("工单不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.post("/tickets/{tid}/resolve")
def resolve_ticket(tid: str, rating: int = 0):
    try:
        g = _guard()
        if g:
            return g
        v = service.resolve_ticket(tid, rating if rating > 0 else None)
        if not v:
            return fail("工单不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.get("/kb/articles")
def list_kb(keyword: str = "", category: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(service.list_kb(keyword, category))
    except Exception as e:
        return fail(str(e))


@router.get("/community/posts")
def list_community(section: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(service.list_community(section))
    except Exception as e:
        return fail(str(e))


@router.post("/surveys")
def create_survey(req: SurveyReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(service.create_survey(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.post("/surveys/{sid}/responses")
def submit_survey(sid: str, req: SurveyRespReq):
    try:
        g = _guard()
        if g:
            return g
        v = service.submit_survey_response(sid, req.model_dump())
        if not v:
            return fail("调查不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.get("/surveys/{sid}/stats")
def survey_stats(sid: str):
    try:
        g = _guard()
        if g:
            return g
        v = service.survey_stats(sid)
        if not v:
            return fail("调查不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e))


@router.get("/customer-success")
def customer_success_list():
    try:
        g = _guard()
        if g:
            return g
        return ok(service.customer_success_list())
    except Exception as e:
        return fail(str(e))


@router.get("/service/report")
def service_report():
    try:
        g = _guard()
        if g:
            return g
        return ok(service.service_report())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 6. 运营仪表盘
# =========================================================================== #
@router.get("/dashboard/sales")
def dash_sales():
    try:
        g = _guard()
        if g:
            return g
        return ok(dashboard.sales_dashboard())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/customers")
def dash_customers():
    try:
        g = _guard()
        if g:
            return g
        return ok(dashboard.customer_dashboard())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/revenue")
def dash_revenue():
    try:
        g = _guard()
        if g:
            return g
        return ok(dashboard.revenue_dashboard())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/service")
def dash_service():
    try:
        g = _guard()
        if g:
            return g
        return ok(dashboard.service_dashboard())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/marketing")
def dash_marketing():
    try:
        g = _guard()
        if g:
            return g
        return ok(dashboard.marketing_dashboard())
    except Exception as e:
        return fail(str(e))


@router.get("/settings")
def system_settings():
    try:
        g = _guard()
        if g:
            return g
        return ok(dashboard.system_settings())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 任务/异步模拟
# =========================================================================== #
@router.post("/tasks/export")
def export_data(kind: str = "customers"):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task(f"export_{kind}")
        if kind == "customers":
            result = customers.list_customers()
        elif kind == "orders":
            result = pipeline.list_orders()
        elif kind == "invoices":
            result = pricing.list_invoices()
        else:
            result = []
        _finish_task(tid, {"kind": kind, "count": len(result), "data": result})
        return ok({"task_id": tid, "task": _TASKS[tid]})
    except Exception as e:
        return fail(str(e))


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        t = _TASKS.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e))


@router.get("/health")
def crm_health():
    try:
        return ok({
            "module_available": _MOD_AVAILABLE,
            "customers": len(getattr(DB, "customers", {})),
            "opportunities": len(getattr(DB, "opportunities", {})),
            "orders": len(getattr(DB, "orders", {})),
            "tickets": len(getattr(DB, "tickets", {})),
            "products": len(getattr(DB, "products", {})),
        })
    except Exception as e:
        return fail(str(e))
