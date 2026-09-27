# -*- coding: utf-8 -*-
"""
api_server/commercial_ultra_pro_routes.py — 方向4：商业产品化 REST API。

路由前缀: /api/v1/commercial-ultra-pro
统一响应: {"success": bool, "data": ..., "error": ...}
覆盖：支付/订阅/客户/SLA/工单/API计费/多租户/管理后台（90+ 端点）。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/commercial-ultra-pro",
                    tags=["商业产品化 Ultra Pro"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from commercial_ultra_pro.payment_system import get_payment_system
    from commercial_ultra_pro.subscription_management import get_subscription_manager
    from commercial_ultra_pro.customer_management import get_customer_manager
    from commercial_ultra_pro.sla_monitor import get_sla_monitor
    from commercial_ultra_pro.ticket_system import get_ticket_system
    from commercial_ultra_pro.api_billing import get_api_billing
    from commercial_ultra_pro.multi_tenant import get_multi_tenant
    from commercial_ultra_pro.admin_dashboard import get_admin_dashboard
    _MOD_AVAILABLE = True
    logger.info("commercial_ultra_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("commercial_ultra_pro_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from commercial_ultra_pro.payment_system import get_payment_system  # noqa
        from commercial_ultra_pro.subscription_management import get_subscription_manager  # noqa
        from commercial_ultra_pro.customer_management import get_customer_manager  # noqa
        from commercial_ultra_pro.sla_monitor import get_sla_monitor  # noqa
        from commercial_ultra_pro.ticket_system import get_ticket_system  # noqa
        from commercial_ultra_pro.api_billing import get_api_billing  # noqa
        from commercial_ultra_pro.multi_tenant import get_multi_tenant  # noqa
        from commercial_ultra_pro.admin_dashboard import get_admin_dashboard  # noqa
        _MOD_AVAILABLE = True
        logger.info("commercial_ultra_pro_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("commercial_ultra_pro_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
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
        return fail("商业产品化模块不可用，请检查加载日志", 503)
    return None


# =========================================================================== #
# 请求模型
# =========================================================================== #
class PayConfigReq(BaseModel):
    settings: Dict[str, Any] = Field(default_factory=dict)


class CreateOrderReq(BaseModel):
    customer_id: str
    subject: str
    amount: float
    channel: str = "alipay"
    trade_type: str = "face_to_face"
    description: str = ""


class NotifyReq(BaseModel):
    out_trade_no: str = ""
    trade_status: str = "TRADE_SUCCESS"
    total_amount: str = ""


class RefundReq(BaseModel):
    amount: Optional[float] = None
    reason: str = ""


class SubscribeReq(BaseModel):
    customer_id: str
    plan: str = "pro"
    period: str = "monthly"
    auto_renew: bool = False


class OnDemandReq(BaseModel):
    customer_id: str
    pack_key: str = "pack_1k"


class CancelReq(BaseModel):
    immediate: bool = False


class AutoRenewReq(BaseModel):
    enabled: bool


class FeatureReq(BaseModel):
    customer_id: str
    feature: str


class UsageReq(BaseModel):
    customer_id: str
    scans: int = 0
    api_calls: int = 0
    reports: int = 0


class CustomerReq(BaseModel):
    name: str
    contact: str = ""
    phone: str = ""
    email: str = ""
    address: str = ""
    industry: str = ""
    scale: str = ""
    level: str = "普通"
    source: str = "官网"
    status: str = "潜在"
    tags: List[str] = Field(default_factory=list)
    note: str = ""


class ContractReq(BaseModel):
    customer_id: str
    name: str
    ctype: str = "年框"
    amount: float = 0.0
    start_date: str = ""
    end_date: str = ""
    attach: str = ""
    note: str = ""


class RenewContractReq(BaseModel):
    new_end_date: str
    new_amount: Optional[float] = None


class BillReq(BaseModel):
    customer_id: str
    period: str = ""
    items: List[Dict[str, Any]] = Field(default_factory=list)
    note: str = ""


class PayBillReq(BaseModel):
    pay_order_id: str = ""


class InvoiceReq(BaseModel):
    customer_id: str
    invoice_type: str = "增值税普通发票"
    title: str = ""
    tax_no: str = ""
    amount: float = 0.0


class IssueInvoiceReq(BaseModel):
    pdf_attach: str = ""


class MailInvoiceReq(BaseModel):
    address: str = ""


class ProbeReq(BaseModel):
    service: str = "api"
    ok: bool = True
    latency_ms: float = 12.0
    check_type: str = "http"


class ResolveIncidentReq(BaseModel):
    root_cause: str = ""
    impact: str = ""


class SetTargetReq(BaseModel):
    target: str
    service: str = "default"


class RecoverReq(BaseModel):
    service: str = "api"
    action: str = "restart"


class TicketCreateReq(BaseModel):
    customer_id: str
    title: str
    ttype: str = "技术支持"
    priority: str = "中"
    description: str = ""
    attachments: List[str] = Field(default_factory=list)
    channel: str = "web"


class AssignReq(BaseModel):
    agent: str


class ClaimReq(BaseModel):
    agent: str


class ReplyReq(BaseModel):
    content: str
    author: str = ""
    internal: bool = False


class StatusReq(BaseModel):
    status: str


class LinkReq(BaseModel):
    related_id: str


class RateReq(BaseModel):
    stars: int
    text: str = ""


class AgentReq(BaseModel):
    agent: str


class CreateKeyReq(BaseModel):
    customer_id: str
    name: str
    permission: str = "read"
    daily_limit: int = 10000
    monthly_limit: int = -1


class KeyValueReq(BaseModel):
    key_value: str


class CallReq(BaseModel):
    key_value: str
    endpoint: str
    status_code: int = 200
    response_bytes: int = 0


class APIBillReq(BaseModel):
    customer_id: str
    plan: str = "pro"


class TenantReq(BaseModel):
    name: str
    ttype: str = "企业"
    quota: Dict[str, int] = Field(default_factory=dict)
    config: Dict[str, Any] = Field(default_factory=dict)


class TenantUpdateReq(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
    expires_at: Optional[str] = None
    quota: Optional[Dict[str, int]] = None
    config: Optional[Dict[str, Any]] = None


class AddUserReq(BaseModel):
    username: str
    role: str = "操作员"


class PermReq(BaseModel):
    user_id: str
    perm: str
    target_tenant: str


class ConsumeReq(BaseModel):
    resource: str
    amount: int = 1


# =========================================================================== #
# 1. 管理后台仪表盘（7 端点）
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    g = _guard()
    if g:
        return g
    return ok(get_admin_dashboard().overview())


@router.get("/dashboard/revenue")
def dash_revenue():
    g = _guard()
    if g:
        return g
    return ok(get_admin_dashboard().revenue_detail())


@router.get("/dashboard/customers")
def dash_customers():
    g = _guard()
    if g:
        return g
    return ok(get_admin_dashboard().customer_view())


@router.get("/dashboard/sla")
def dash_sla():
    g = _guard()
    if g:
        return g
    return ok(get_admin_dashboard().sla_view())


@router.get("/dashboard/tickets")
def dash_tickets():
    g = _guard()
    if g:
        return g
    return ok(get_admin_dashboard().ticket_view())


@router.get("/dashboard/tenants")
def dash_tenants():
    g = _guard()
    if g:
        return g
    return ok(get_admin_dashboard().tenant_view())


@router.get("/dashboard/system-health")
def dash_health():
    g = _guard()
    if g:
        return g
    return ok(get_admin_dashboard().system_health())


# =========================================================================== #
# 2. 支付系统（14 端点）
# =========================================================================== #
@router.get("/pay/config")
def pay_config(channel: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok(get_payment_system().get_config(channel))


@router.put("/pay/config/{channel}")
def pay_update_config(channel: str, req: PayConfigReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_payment_system().update_config(channel, req.settings))
    except Exception as e:
        return fail(str(e))


@router.post("/pay/orders")
def pay_create_order(req: CreateOrderReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_payment_system().create_order(
            req.customer_id, req.subject, req.amount, req.channel,
            req.trade_type, req.description))
    except Exception as e:
        return fail(str(e))


@router.post("/pay/orders/{order_id}/pay")
def pay_pay(order_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_payment_system().pay(order_id))
    except Exception as e:
        return fail(str(e))


@router.post("/pay/orders/{order_id}/notify")
def pay_notify(order_id: str, req: NotifyReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_payment_system().notify(
            order_id, out_trade_no=req.out_trade_no,
            trade_status=req.trade_status, total_amount=req.total_amount))
    except Exception as e:
        return fail(str(e))


@router.get("/pay/orders/{order_id}")
def pay_query(order_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_payment_system().query(order_id))
    except Exception as e:
        return fail(str(e), 404)


@router.post("/pay/orders/{order_id}/refund")
def pay_refund(order_id: str, req: RefundReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_payment_system().refund(order_id, req.amount, req.reason))
    except Exception as e:
        return fail(str(e))


@router.get("/pay/orders")
def pay_list_orders(customer_id: Optional[str] = None,
                     channel: Optional[str] = None,
                     status: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_payment_system().list_orders(customer_id, channel, status)})


@router.get("/pay/refunds")
def pay_list_refunds(order_id: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_payment_system().list_refunds(order_id)})


@router.get("/pay/reconciliation")
def pay_reconciliation(channel: Optional[str] = None, date: str = ""):
    g = _guard()
    if g:
        return g
    return ok(get_payment_system().reconciliation(channel, date))


@router.get("/pay/stats")
def pay_stats():
    g = _guard()
    if g:
        return g
    return ok(get_payment_system().stats())


# =========================================================================== #
# 3. 订阅管理（12 端点）
# =========================================================================== #
@router.get("/sub/plans")
def sub_plans():
    g = _guard()
    if g:
        return g
    return ok(get_subscription_manager().plans())


@router.post("/sub/subscribe")
def sub_subscribe(req: SubscribeReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_subscription_manager().subscribe(
            req.customer_id, req.plan, req.period, req.auto_renew))
    except Exception as e:
        return fail(str(e))


@router.post("/sub/ondemand")
def sub_ondemand(req: OnDemandReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_subscription_manager().buy_ondemand_pack(req.customer_id, req.pack_key))
    except Exception as e:
        return fail(str(e))


@router.post("/sub/cancel/{customer_id}")
def sub_cancel(customer_id: str, req: CancelReq):
    g = _guard()
    if g:
        return g
    return ok(get_subscription_manager().cancel(customer_id, req.immediate))


@router.put("/sub/auto-renew/{customer_id}")
def sub_auto_renew(customer_id: str, req: AutoRenewReq):
    g = _guard()
    if g:
        return g
    return ok(get_subscription_manager().set_auto_renew(customer_id, req.enabled))


@router.get("/sub/reminders")
def sub_reminders():
    g = _guard()
    if g:
        return g
    return ok({"items": get_subscription_manager().expiry_reminders()})


@router.post("/sub/check-feature")
def sub_check_feature(req: FeatureReq):
    g = _guard()
    if g:
        return g
    return ok(get_subscription_manager().check_feature(req.customer_id, req.feature))


@router.post("/sub/usage")
def sub_usage(req: UsageReq):
    g = _guard()
    if g:
        return g
    return ok(get_subscription_manager().usage_report(
        req.customer_id, req.scans, req.api_calls, req.reports))


@router.get("/sub/usage/{customer_id}")
def sub_get_usage(customer_id: str):
    g = _guard()
    if g:
        return g
    return ok(get_subscription_manager().get_usage(customer_id))


@router.get("/sub/list")
def sub_list():
    g = _guard()
    if g:
        return g
    return ok({"items": get_subscription_manager().list_subscriptions()})


@router.get("/sub/history")
def sub_history(customer_id: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_subscription_manager().history(customer_id)})


@router.get("/sub/stats")
def sub_stats():
    g = _guard()
    if g:
        return g
    return ok(get_subscription_manager().stats())


# =========================================================================== #
# 4. 客户管理（20 端点）
# =========================================================================== #
@router.post("/cust/customers")
def cust_create(req: CustomerReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().create_customer(
            req.name, req.contact, req.phone, req.email, req.address,
            req.industry, req.scale, req.level, req.source, req.status,
            req.tags, req.note))
    except Exception as e:
        return fail(str(e))


@router.put("/cust/customers/{customer_id}")
def cust_update(customer_id: str, req: CustomerReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().update_customer(
            customer_id, name=req.name, contact=req.contact, phone=req.phone,
            email=req.email, address=req.address, industry=req.industry,
            scale=req.scale, level=req.level, source=req.source,
            status=req.status, tags=req.tags, note=req.note))
    except Exception as e:
        return fail(str(e))


@router.get("/cust/customers/{customer_id}")
def cust_get(customer_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().get_customer(customer_id))
    except Exception as e:
        return fail(str(e), 404)


@router.get("/cust/customers")
def cust_list(level: Optional[str] = None, status: Optional[str] = None,
               source: Optional[str] = None, keyword: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_customer_manager().list_customers(level, status, source, keyword)})


@router.delete("/cust/customers/{customer_id}")
def cust_delete(customer_id: str):
    g = _guard()
    if g:
        return g
    return ok({"deleted": get_customer_manager().delete_customer(customer_id)})


@router.post("/cust/contracts")
def cust_create_contract(req: ContractReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().create_contract(
            req.customer_id, req.name, req.ctype, req.amount,
            req.start_date, req.end_date, req.attach, req.note))
    except Exception as e:
        return fail(str(e))


@router.post("/cust/contracts/{contract_id}/renew")
def cust_renew_contract(contract_id: str, req: RenewContractReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().renew_contract(
            contract_id, req.new_end_date, req.new_amount))
    except Exception as e:
        return fail(str(e))


@router.get("/cust/contracts")
def cust_list_contracts(customer_id: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_customer_manager().list_contracts(customer_id)})


@router.get("/cust/contract-reminders")
def cust_contract_reminders():
    g = _guard()
    if g:
        return g
    return ok({"items": get_customer_manager().contract_expiry_reminders()})


@router.post("/cust/bills")
def cust_generate_bill(req: BillReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().generate_bill(
            req.customer_id, req.period, req.items, req.note))
    except Exception as e:
        return fail(str(e))


@router.post("/cust/bills/{bill_id}/pay")
def cust_pay_bill(bill_id: str, req: PayBillReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().pay_bill(bill_id, req.pay_order_id))
    except Exception as e:
        return fail(str(e))


@router.get("/cust/bills")
def cust_list_bills(customer_id: Optional[str] = None,
                     status: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_customer_manager().list_bills(customer_id, status)})


@router.get("/cust/overdue")
def cust_overdue():
    g = _guard()
    if g:
        return g
    return ok({"items": get_customer_manager().overdue_reminders()})


@router.post("/cust/invoices")
def cust_apply_invoice(req: InvoiceReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().apply_invoice(
            req.customer_id, req.invoice_type, req.title, req.tax_no, req.amount))
    except Exception as e:
        return fail(str(e))


@router.post("/cust/invoices/{invoice_id}/issue")
def cust_issue_invoice(invoice_id: str, req: IssueInvoiceReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().issue_invoice(invoice_id, req.pdf_attach))
    except Exception as e:
        return fail(str(e))


@router.post("/cust/invoices/{invoice_id}/void")
def cust_void_invoice(invoice_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().void_invoice(invoice_id))
    except Exception as e:
        return fail(str(e))


@router.post("/cust/invoices/{invoice_id}/mail")
def cust_mail_invoice(invoice_id: str, req: MailInvoiceReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_manager().mail_invoice(invoice_id, req.address))
    except Exception as e:
        return fail(str(e))


@router.get("/cust/invoices")
def cust_list_invoices(customer_id: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_customer_manager().list_invoices(customer_id)})


@router.get("/cust/stats")
def cust_stats():
    g = _guard()
    if g:
        return g
    return ok(get_customer_manager().stats())


# =========================================================================== #
# 5. SLA 监控（12 端点）
# =========================================================================== #
@router.post("/sla/probe")
def sla_probe(req: ProbeReq):
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().health_check(
        req.service, req.ok, req.latency_ms, req.check_type))


@router.post("/sla/incidents/{incident_id}/resolve")
def sla_resolve(incident_id: str, req: ResolveIncidentReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_sla_monitor().resolve_incident(
            incident_id, req.root_cause, req.impact))
    except Exception as e:
        return fail(str(e), 404)


@router.get("/sla/incidents")
def sla_incidents(open_only: bool = False):
    g = _guard()
    if g:
        return g
    return ok({"items": get_sla_monitor().list_incidents(open_only)})


@router.get("/sla/alerts")
def sla_alerts(ack: Optional[bool] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_sla_monitor().list_alerts(ack)})


@router.post("/sla/alerts/{alert_id}/ack")
def sla_ack(alert_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_sla_monitor().ack_alert(alert_id))
    except Exception as e:
        return fail(str(e), 404)


@router.get("/sla/availability")
def sla_availability(service: Optional[str] = None, window: str = "month"):
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().availability(service, window))


@router.get("/sla/response-time")
def sla_response_time(service: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().response_time(service))


@router.put("/sla/target")
def sla_set_target(req: SetTargetReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_sla_monitor().set_target(req.target, req.service))
    except Exception as e:
        return fail(str(e))


@router.get("/sla/report")
def sla_report(service: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().sla_report(service))


@router.post("/sla/auto-recover")
def sla_auto_recover(req: RecoverReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_sla_monitor().auto_recover(req.service, req.action))
    except Exception as e:
        return fail(str(e))


@router.get("/sla/recoveries")
def sla_recoveries():
    g = _guard()
    if g:
        return g
    return ok({"items": get_sla_monitor().list_recoveries()})


@router.get("/sla/dashboard")
def sla_dashboard():
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().dashboard())


# =========================================================================== #
# 6. 工单系统（14 端点）
# =========================================================================== #
@router.post("/ticket/tickets")
def ticket_create(req: TicketCreateReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ticket_system().create_ticket(
            req.customer_id, req.title, req.ttype, req.priority,
            req.description, req.attachments, req.channel))
    except Exception as e:
        return fail(str(e))


@router.post("/ticket/tickets/{ticket_id}/auto-assign")
def ticket_auto_assign(ticket_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ticket_system().auto_assign(ticket_id))
    except Exception as e:
        return fail(str(e))


@router.post("/ticket/tickets/{ticket_id}/assign")
def ticket_assign(ticket_id: str, req: AssignReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ticket_system().assign(ticket_id, req.agent))
    except Exception as e:
        return fail(str(e))


@router.post("/ticket/tickets/{ticket_id}/claim")
def ticket_claim(ticket_id: str, req: ClaimReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ticket_system().claim(ticket_id, req.agent))
    except Exception as e:
        return fail(str(e))


@router.post("/ticket/tickets/{ticket_id}/transfer")
def ticket_transfer(ticket_id: str, req: AssignReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ticket_system().transfer(ticket_id, req.agent))
    except Exception as e:
        return fail(str(e))


@router.post("/ticket/agents")
def ticket_register_agent(req: AgentReq):
    g = _guard()
    if g:
        return g
    return ok(get_ticket_system().register_agent(req.agent))


@router.post("/ticket/tickets/{ticket_id}/reply")
def ticket_reply(ticket_id: str, req: ReplyReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ticket_system().reply(ticket_id, req.content, req.author, req.internal))
    except Exception as e:
        return fail(str(e))


@router.put("/ticket/tickets/{ticket_id}/status")
def ticket_set_status(ticket_id: str, req: StatusReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ticket_system().set_status(ticket_id, req.status))
    except Exception as e:
        return fail(str(e))


@router.post("/ticket/tickets/{ticket_id}/link")
def ticket_link(ticket_id: str, req: LinkReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ticket_system().link_ticket(ticket_id, req.related_id))
    except Exception as e:
        return fail(str(e))


@router.post("/ticket/tickets/{ticket_id}/rate")
def ticket_rate(ticket_id: str, req: RateReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ticket_system().rate(ticket_id, req.stars, req.text))
    except Exception as e:
        return fail(str(e))


@router.get("/ticket/tickets/{ticket_id}")
def ticket_get(ticket_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ticket_system().get_ticket(ticket_id))
    except Exception as e:
        return fail(str(e), 404)


@router.get("/ticket/tickets")
def ticket_list(status: Optional[str] = None, ttype: Optional[str] = None,
                 priority: Optional[str] = None,
                 customer_id: Optional[str] = None,
                 assignee: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_ticket_system().list_tickets(
        status, ttype, priority, customer_id, assignee)})


@router.get("/ticket/stats")
def ticket_stats():
    g = _guard()
    if g:
        return g
    return ok(get_ticket_system().stats())


# =========================================================================== #
# 7. API 计费（11 端点）
# =========================================================================== #
@router.post("/apibilling/keys")
def api_create_key(req: CreateKeyReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_api_billing().create_key(
            req.customer_id, req.name, req.permission,
            req.daily_limit, req.monthly_limit))
    except Exception as e:
        return fail(str(e))


@router.get("/apibilling/keys")
def api_list_keys(customer_id: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_api_billing().list_keys(customer_id)})


@router.post("/apibilling/keys/disable")
def api_disable_key(req: KeyValueReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_api_billing().disable_key(req.key_value))
    except Exception as e:
        return fail(str(e))


@router.post("/apibilling/keys/rotate")
def api_rotate_key(req: KeyValueReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_api_billing().rotate_key(req.key_value))
    except Exception as e:
        return fail(str(e))


@router.post("/apibilling/calls")
def api_record_call(req: CallReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_api_billing().record_call(
            req.key_value, req.endpoint, req.status_code, req.response_bytes))
    except Exception as e:
        return fail(str(e))


@router.get("/apibilling/usage")
def api_usage(customer_id: Optional[str] = None,
               key_id: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok(get_api_billing().usage_stats(customer_id, key_id))


@router.post("/apibilling/bills")
def api_monthly_bill(req: APIBillReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_api_billing().generate_monthly_bill(req.customer_id, req.plan))
    except Exception as e:
        return fail(str(e))


@router.get("/apibilling/bills")
def api_list_bills(customer_id: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_api_billing().list_bills(customer_id)})


@router.get("/apibilling/rate-limit-config")
def api_rate_config():
    g = _guard()
    if g:
        return g
    return ok(get_api_billing().rate_limit_config())


@router.get("/apibilling/stats")
def api_stats():
    g = _guard()
    if g:
        return g
    return ok(get_api_billing().stats())


# =========================================================================== #
# 8. 多租户（13 端点）
# =========================================================================== #
@router.post("/tenant/tenants")
def tenant_create(req: TenantReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_multi_tenant().create_tenant(req.name, req.ttype,
                                                     req.quota, req.config))
    except Exception as e:
        return fail(str(e))


@router.put("/tenant/tenants/{tenant_id}")
def tenant_update(tenant_id: str, req: TenantUpdateReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_multi_tenant().update_tenant(
            tenant_id, name=req.name, type=req.type, status=req.status,
            expires_at=req.expires_at, quota=req.quota, config=req.config))
    except Exception as e:
        return fail(str(e))


@router.post("/tenant/tenants/{tenant_id}/disable")
def tenant_disable(tenant_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_multi_tenant().disable_tenant(tenant_id))
    except Exception as e:
        return fail(str(e), 404)


@router.get("/tenant/tenants/{tenant_id}")
def tenant_get(tenant_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_multi_tenant().get_tenant(tenant_id))
    except Exception as e:
        return fail(str(e), 404)


@router.get("/tenant/tenants")
def tenant_list(ttype: Optional[str] = None, status: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_multi_tenant().list_tenants(ttype, status)})


@router.delete("/tenant/tenants/{tenant_id}")
def tenant_delete(tenant_id: str):
    g = _guard()
    if g:
        return g
    return ok({"deleted": get_multi_tenant().delete_tenant(tenant_id)})


@router.post("/tenant/tenants/{tenant_id}/users")
def tenant_add_user(tenant_id: str, req: AddUserReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_multi_tenant().add_user(tenant_id, req.username, req.role))
    except Exception as e:
        return fail(str(e))


@router.get("/tenant/tenants/{tenant_id}/users")
def tenant_list_users(tenant_id: str):
    g = _guard()
    if g:
        return g
    return ok({"items": get_multi_tenant().list_users(tenant_id)})


@router.post("/tenant/check-permission")
def tenant_check_perm(req: PermReq):
    g = _guard()
    if g:
        return g
    return ok(get_multi_tenant().check_permission(
        req.user_id, req.perm, req.target_tenant))


@router.post("/tenant/tenants/{tenant_id}/consume")
def tenant_consume(tenant_id: str, req: ConsumeReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_multi_tenant().consume_resource(tenant_id, req.resource, req.amount))
    except Exception as e:
        return fail(str(e))


@router.get("/tenant/tenants/{tenant_id}/resources")
def tenant_resources(tenant_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_multi_tenant().resource_usage(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.get("/tenant/stats")
def tenant_stats():
    g = _guard()
    if g:
        return g
    return ok(get_multi_tenant().stats())
