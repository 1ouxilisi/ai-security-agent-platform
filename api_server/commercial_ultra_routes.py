# -*- coding: utf-8 -*-
"""
api_server/commercial_ultra_routes.py — 方向4：商业产品体验极致 REST API。

路由前缀: /api/v1/commercial-ultra
统一响应: {"success": bool, "data": ..., "error": ...}
覆盖：品牌官网 / 产品演示 / 客户门户Pro / 计费系统Pro / SLA监控Pro /
      备份恢复 / 帮助中心 / 仪表盘聚合（50+ 端点）。
前端页面: GET /commercial-ultra  → commercial_ultra_console.html
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/commercial-ultra", tags=["商业产品体验极致"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from commercial_ultra.brand_website import get_brand_website
    from commercial_ultra.product_demo import get_product_demo
    from commercial_ultra.customer_portal_pro import get_customer_portal_pro
    from commercial_ultra.billing_system_pro import get_billing_system_pro
    from commercial_ultra.sla_monitor_pro import get_sla_monitor_pro
    from commercial_ultra.backup_recovery import get_backup_recovery
    from commercial_ultra.help_center import get_help_center
    from commercial_ultra.commercial_ultra_dashboard import (
        get_commercial_ultra_dashboard)
    _MOD_AVAILABLE = True
    logger.info("commercial_ultra_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("commercial_ultra_routes: load failed: %s", e)
    try:
        import sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from commercial_ultra.brand_website import get_brand_website  # noqa
        from commercial_ultra.product_demo import get_product_demo  # noqa
        from commercial_ultra.customer_portal_pro import get_customer_portal_pro  # noqa
        from commercial_ultra.billing_system_pro import get_billing_system_pro  # noqa
        from commercial_ultra.sla_monitor_pro import get_sla_monitor_pro  # noqa
        from commercial_ultra.backup_recovery import get_backup_recovery  # noqa
        from commercial_ultra.help_center import get_help_center  # noqa
        from commercial_ultra.commercial_ultra_dashboard import (  # noqa
            get_commercial_ultra_dashboard)
        _MOD_AVAILABLE = True
        logger.info("commercial_ultra_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("commercial_ultra_routes: fallback load failed: %s", e2)


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
        return fail("商业极致模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class LeadReq(BaseModel):
    name: str = ""
    email: str = ""
    message: str = ""


class RegisterReq(BaseModel):
    email: str
    password: str
    company: str = ""
    contact: str = ""


class LoginReq(BaseModel):
    email: str
    password: str


class ProfileReq(BaseModel):
    company: Optional[str] = None
    contact: Optional[str] = None
    phone: Optional[str] = None


class ChangePwdReq(BaseModel):
    old: str
    new: str


class ProjectReq(BaseModel):
    name: str
    target: str
    kind: str = "web"


class ScanBillingReq(BaseModel):
    customer_id: str
    count: int = 1


class SubscribeReq(BaseModel):
    customer_id: str
    plan: str = "pro"
    period: str = "monthly"


class PayReq(BaseModel):
    gateway: str = "alipay"


class ProbeReq(BaseModel):
    ok: bool = True
    latency_ms: float = 20.0


class BackupReq(BaseModel):
    label: str = ""


class PolicyReq(BaseModel):
    auto: Optional[bool] = None
    interval_minutes: Optional[int] = None
    retain: Optional[int] = None
    compress: Optional[bool] = None
    encrypt: Optional[bool] = None


def _portal_customer(token: Optional[str]) -> Any:
    if not token:
        return None, fail("缺少 Authorization: Bearer <token>", 401)
    who = get_customer_portal_pro().whoami(token)
    if not who:
        return None, fail("会话无效或已过期", 401)
    return who["customer_id"], None


# =========================================================================== #
# 1. 仪表盘聚合（3 个端点）
# =========================================================================== #
@router.get("/overview")
def cu_overview():
    g = _guard()
    if g:
        return g
    return ok(get_commercial_ultra_dashboard().overview())


@router.get("/scorecard")
def cu_scorecard():
    g = _guard()
    if g:
        return g
    return ok(get_commercial_ultra_dashboard().scorecard())


@router.get("/all")
def cu_all():
    """批量接口合并演示。"""
    g = _guard()
    if g:
        return g
    return ok(get_commercial_ultra_dashboard().all_in_one())


# =========================================================================== #
# 2. 品牌官网（8 个端点）
# =========================================================================== #
@router.get("/website/home")
def web_home():
    g = _guard()
    if g:
        return g
    return ok(get_brand_website().home())


@router.get("/website/features")
def web_features():
    g = _guard()
    if g:
        return g
    return ok(get_brand_website().features())


@router.get("/website/pricing")
def web_pricing():
    g = _guard()
    if g:
        return g
    return ok(get_brand_website().pricing())


@router.get("/website/docs")
def web_docs():
    g = _guard()
    if g:
        return g
    return ok(get_brand_website().docs())


@router.get("/website/contact")
def web_contact():
    g = _guard()
    if g:
        return g
    return ok(get_brand_website().contact())


@router.post("/website/lead")
def web_lead(req: LeadReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_brand_website().submit_lead(req.name, req.email, req.message))
    except Exception as e:
        return fail(str(e))


@router.get("/website/leads")
def web_leads():
    g = _guard()
    if g:
        return g
    return ok({"items": get_brand_website().leads()})


@router.get("/website/analytics")
def web_analytics():
    g = _guard()
    if g:
        return g
    return ok(get_brand_website().analytics())


# =========================================================================== #
# 3. 产品演示（5 个端点）
# =========================================================================== #
@router.get("/demo/scenes")
def demo_scenes():
    g = _guard()
    if g:
        return g
    return ok({"items": get_product_demo().scenes()})


@router.post("/demo/start")
def demo_start():
    g = _guard()
    if g:
        return g
    return ok(get_product_demo().start())


@router.post("/demo/next/{demo_id}")
def demo_next(demo_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_product_demo().next_step(demo_id))
    except Exception as e:
        return fail(str(e))


@router.post("/demo/run-all/{demo_id}")
def demo_run_all(demo_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_product_demo().run_all(demo_id))
    except Exception as e:
        return fail(str(e))


@router.get("/demo/status/{demo_id}")
def demo_status(demo_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_product_demo().status(demo_id))
    except Exception as e:
        return fail(str(e), 404)


# =========================================================================== #
# 4. 客户门户 Pro（12 个端点）
# =========================================================================== #
@router.post("/portal/register")
def portal_register(req: RegisterReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_portal_pro().register(
            req.email, req.password, req.company, req.contact))
    except Exception as e:
        return fail(str(e))


@router.post("/portal/login")
def portal_login(req: LoginReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_portal_pro().login(req.email, req.password))
    except Exception as e:
        return fail(str(e), 401)


@router.post("/portal/logout")
def portal_logout(authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    return ok({"logged_out": get_customer_portal_pro().logout(token)})


@router.get("/portal/me")
def portal_me(authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    who = get_customer_portal_pro().whoami(token)
    if not who:
        return fail("会话无效或已过期", 401)
    return ok(who)


@router.put("/portal/profile")
def portal_profile(req: ProfileReq, authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    cid, err = _portal_customer(token)
    if err:
        return err
    try:
        return ok(get_customer_portal_pro().update_profile(
            cid, company=req.company, contact=req.contact, phone=req.phone))
    except Exception as e:
        return fail(str(e))


@router.post("/portal/change-password")
def portal_change_pwd(req: ChangePwdReq, authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    cid, err = _portal_customer(token)
    if err:
        return err
    try:
        get_customer_portal_pro().change_password(cid, req.old, req.new)
        return ok({"changed": True})
    except Exception as e:
        return fail(str(e))


@router.get("/portal/projects")
def portal_list_projects(authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    cid, err = _portal_customer(token)
    if err:
        return err
    return ok({"items": get_customer_portal_pro().list_projects(cid)})


@router.post("/portal/projects")
def portal_create_project(req: ProjectReq, authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    cid, err = _portal_customer(token)
    if err:
        return err
    return ok(get_customer_portal_pro().create_project(cid, req.name, req.target, req.kind))


@router.get("/portal/projects/{project_id}")
def portal_get_project(project_id: str, authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    cid, err = _portal_customer(token)
    if err:
        return err
    try:
        return ok(get_customer_portal_pro().get_project(cid, project_id))
    except Exception as e:
        return fail(str(e), 403)


@router.delete("/portal/projects/{project_id}")
def portal_delete_project(project_id: str, authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    cid, err = _portal_customer(token)
    if err:
        return err
    try:
        return ok({"deleted": get_customer_portal_pro().delete_project(cid, project_id)})
    except Exception as e:
        return fail(str(e), 403)


@router.get("/portal/projects/{project_id}/reports")
def portal_list_reports(project_id: str, authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    cid, err = _portal_customer(token)
    if err:
        return err
    try:
        return ok({"items": get_customer_portal_pro().list_reports(cid, project_id)})
    except Exception as e:
        return fail(str(e), 403)


@router.get("/portal/reports/{report_id}")
def portal_get_report(report_id: str, authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    cid, err = _portal_customer(token)
    if err:
        return err
    try:
        return ok(get_customer_portal_pro().get_report(cid, report_id))
    except Exception as e:
        return fail(str(e), 403)


# =========================================================================== #
# 5. 计费系统 Pro（9 个端点）
# =========================================================================== #
@router.get("/billing/pricing")
def billing_pricing():
    g = _guard()
    if g:
        return g
    return ok(get_billing_system_pro().pricing())


@router.post("/billing/scan")
def billing_record_scan(req: ScanBillingReq):
    g = _guard()
    if g:
        return g
    return ok(get_billing_system_pro().record_scan(req.customer_id, req.count))


@router.post("/billing/subscribe")
def billing_subscribe(req: SubscribeReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_billing_system_pro().subscribe(req.customer_id, req.plan, req.period))
    except Exception as e:
        return fail(str(e))


@router.post("/billing/pay/{invoice_id}")
def billing_pay(invoice_id: str, req: PayReq):
    """发起支付（Stripe / 支付宝预留）。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(get_billing_system_pro().pay(invoice_id, req.gateway))
    except Exception as e:
        return fail(str(e))


@router.post("/billing/pay/{invoice_id}/confirm")
def billing_confirm(invoice_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_billing_system_pro().confirm_payment(invoice_id))
    except Exception as e:
        return fail(str(e))


@router.get("/billing/invoices")
def billing_invoices(customer_id: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_billing_system_pro().list_invoices(customer_id)})


@router.get("/billing/invoices/{invoice_id}")
def billing_invoice_detail(invoice_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_billing_system_pro().get_invoice(invoice_id))
    except Exception as e:
        return fail(str(e), 404)


@router.get("/billing/account/{customer_id}")
def billing_account(customer_id: str):
    g = _guard()
    if g:
        return g
    return ok(get_billing_system_pro().account(customer_id))


@router.get("/billing/stats")
def billing_stats():
    g = _guard()
    if g:
        return g
    return ok(get_billing_system_pro().admin_stats())


# =========================================================================== #
# 6. SLA 监控 Pro（7 个端点）
# =========================================================================== #
@router.get("/sla/status-page")
def sla_status_page():
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor_pro().status_page())


@router.get("/sla/availability")
def sla_availability():
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor_pro().availability())


@router.post("/sla/probe")
def sla_probe(req: ProbeReq):
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor_pro().probe(req.ok, req.latency_ms))


@router.post("/sla/auto-recover")
def sla_auto_recover():
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor_pro().auto_recover())


@router.get("/sla/incidents")
def sla_incidents(open_only: bool = False):
    g = _guard()
    if g:
        return g
    return ok({"items": get_sla_monitor_pro().list_incidents(open_only)})


@router.get("/sla/alerts")
def sla_alerts():
    g = _guard()
    if g:
        return g
    return ok({"items": get_sla_monitor_pro().list_alerts()})


@router.get("/sla/health")
def sla_health():
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor_pro().health())


# =========================================================================== #
# 7. 备份恢复（7 个端点）
# =========================================================================== #
@router.post("/backup/create")
def backup_create(req: BackupReq):
    g = _guard()
    if g:
        return g
    return ok(get_backup_recovery().backup(req.label))


@router.get("/backup/list")
def backup_list():
    g = _guard()
    if g:
        return g
    return ok({"items": get_backup_recovery().list_backups()})


@router.post("/backup/restore/{backup_id}")
def backup_restore(backup_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_backup_recovery().restore(backup_id))
    except Exception as e:
        return fail(str(e), 404)


@router.delete("/backup/{backup_id}")
def backup_delete(backup_id: str):
    g = _guard()
    if g:
        return g
    return ok({"deleted": get_backup_recovery().delete_backup(backup_id)})


@router.get("/backup/policy")
def backup_policy():
    g = _guard()
    if g:
        return g
    return ok(get_backup_recovery().get_policy())


@router.put("/backup/policy")
def backup_set_policy(req: PolicyReq):
    g = _guard()
    if g:
        return g
    return ok(get_backup_recovery().set_policy(
        auto=req.auto, interval_minutes=req.interval_minutes,
        retain=req.retain, compress=req.compress, encrypt=req.encrypt))


@router.post("/backup/simulate-drift")
def backup_drift():
    """模拟运行时数据漂移（演示备份 vs 恢复）。"""
    g = _guard()
    if g:
        return g
    return ok(get_backup_recovery().simulate_drift())


# =========================================================================== #
# 8. 帮助中心（5 个端点）
# =========================================================================== #
@router.get("/help/docs")
def help_docs():
    g = _guard()
    if g:
        return g
    return ok({"items": get_help_center().docs()})


@router.get("/help/docs/{doc_id}")
def help_doc_detail(doc_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_help_center().doc_detail(doc_id))
    except Exception as e:
        return fail(str(e), 404)


@router.get("/help/faq")
def help_faq():
    g = _guard()
    if g:
        return g
    return ok({"items": get_help_center().faq()})


@router.get("/help/videos")
def help_videos():
    g = _guard()
    if g:
        return g
    return ok({"items": get_help_center().videos()})


@router.get("/help/search")
def help_search(q: str = Query(..., description="检索关键词")):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_help_center().search(q))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 9. 前端页面路由（自包含，避免依赖 app.py 注入）
# =========================================================================== #
@router.get("/page", include_in_schema=False)
def commercial_ultra_page():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "commercial_ultra_console.html")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>商业极致控制台页面未找到</h1>")
