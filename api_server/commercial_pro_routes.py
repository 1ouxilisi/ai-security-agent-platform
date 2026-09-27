# -*- coding: utf-8 -*-
"""
api_server/commercial_pro_routes.py — 方向4：商业成熟度大升级 REST API。

路由前缀: /api/v1/commercial-pro
统一响应: {"success": bool, "data": ..., "error": ...}
覆盖：真实 License / 客户门户 / 计费系统 / SLA 保障 / 商业化聚合（40+ 端点）。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/commercial-pro", tags=["商业成熟度大升级"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from commercial_pro.license_real import get_license_manager, generate_machine_code
    from commercial_pro.customer_portal import get_customer_portal
    from commercial_pro.billing_system import get_billing_system
    from commercial_pro.sla_monitor import get_sla_monitor
    from commercial_pro.commercial_dashboard import get_commercial_dashboard
    _MOD_AVAILABLE = True
    logger.info("commercial_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("commercial_pro_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from commercial_pro.license_real import get_license_manager, generate_machine_code  # noqa
        from commercial_pro.customer_portal import get_customer_portal  # noqa
        from commercial_pro.billing_system import get_billing_system  # noqa
        from commercial_pro.sla_monitor import get_sla_monitor  # noqa
        from commercial_pro.commercial_dashboard import get_commercial_dashboard  # noqa
        _MOD_AVAILABLE = True
        logger.info("commercial_pro_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("commercial_pro_routes: fallback load failed: %s", e2)


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
        return fail("商业化模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class IssueLicenseReq(BaseModel):
    customer: str = "新客户"
    tier: str = "pro"
    seats: int = 1
    duration_days: int = 365
    note: str = ""


class ActivateReq(BaseModel):
    license_key: str
    machine_code: str = ""


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
    note: Optional[str] = None


class ChangePwdReq(BaseModel):
    old: str
    new: str


class ProjectReq(BaseModel):
    name: str
    target: str
    kind: str = "web"


class ReportReq(BaseModel):
    title: str
    summary: Dict[str, Any] = Field(default_factory=dict)


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
    latency_ms: float = 12.0


class BackupReq(BaseModel):
    label: str = ""


def _portal_customer(token: Optional[str]) -> Any:
    """从 token 解析客户，返回 (customer_id, error_response)。"""
    if not token:
        return None, fail("缺少 Authorization: Bearer <token>", 401)
    who = get_customer_portal().whoami(token)
    if not who:
        return None, fail("会话无效或已过期", 401)
    return who["customer_id"], None


# =========================================================================== #
# 1. 聚合总览（3 个端点）
# =========================================================================== #
@router.get("/overview")
def cp_overview():
    g = _guard()
    if g:
        return g
    return ok(get_commercial_dashboard().overview())


@router.get("/scorecard")
def cp_scorecard():
    g = _guard()
    if g:
        return g
    return ok(get_commercial_dashboard().scorecard())


@router.get("/all")
def cp_all():
    """一站式聚合（批量接口合并演示）。"""
    g = _guard()
    if g:
        return g
    return ok({
        "overview": get_commercial_dashboard().overview(),
        "scorecard": get_commercial_dashboard().scorecard(),
        "billing": get_commercial_dashboard().billing_view(),
        "sla": get_commercial_dashboard().sla_view(),
    })


# =========================================================================== #
# 2. 真实 License 系统（10 个端点）
# =========================================================================== #
@router.get("/license/machine-code")
def lic_machine_code():
    """生成当前机器硬件指纹（CPU/磁盘/MAC → SHA-256）。"""
    g = _guard()
    if g:
        return g
    return ok(generate_machine_code())


@router.get("/license/key-info")
def lic_key_info():
    """签名后端信息（RSA-PSS / 降级）。"""
    g = _guard()
    if g:
        return g
    return ok(get_license_manager().key_info())


@router.get("/license/tiers")
def lic_tiers():
    """功能分级能力矩阵。"""
    g = _guard()
    if g:
        return g
    return ok(get_license_manager().tiers())


@router.get("/license/list")
def lic_list():
    """License 管理：列出全部已签发 License。"""
    g = _guard()
    if g:
        return g
    return ok({"total": len(get_license_manager().list_licenses()),
               "items": get_license_manager().list_licenses()})


@router.post("/license/issue")
def lic_issue(req: IssueLicenseReq):
    """签发 License（管理员操作）。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(get_license_manager().issue(
            req.customer, req.tier, req.seats, req.duration_days, req.note))
    except Exception as e:
        return fail(str(e))


@router.post("/license/activate")
def lic_activate(req: ActivateReq):
    """在线激活：绑定机器码。"""
    g = _guard()
    if g:
        return g
    mc = req.machine_code or generate_machine_code()["machine_code"]
    res = get_license_manager().activate(req.license_key, mc)
    if not res.get("success"):
        return fail(res.get("reason", "激活失败"), 400)
    return ok(res)


@router.get("/license/verify")
def lic_verify_query(key: str = Query(...)):
    """校验当前机器上的 License。"""
    g = _guard()
    if g:
        return g
    mc = generate_machine_code()["machine_code"]
    return ok(get_license_manager().verify(key, mc))


@router.get("/license/remind")
def lic_remind():
    """当前机器 License 过期提醒。"""
    g = _guard()
    if g:
        return g
    mc = generate_machine_code()["machine_code"]
    return ok(get_license_manager().remind(mc))


@router.get("/license/{license_key}")
def lic_detail(license_key: str):
    """License 详情校验。"""
    g = _guard()
    if g:
        return g
    mc = generate_machine_code()["machine_code"]
    v = get_license_manager().verify(license_key, mc)
    if not v.get("valid"):
        return ok(v)
    return ok(v)


# =========================================================================== #
# 3. 客户门户（13 个端点）
# =========================================================================== #
@router.post("/portal/register")
def portal_register(req: RegisterReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_portal().register(
            req.email, req.password, req.company, req.contact))
    except Exception as e:
        return fail(str(e))


@router.post("/portal/login")
def portal_login(req: LoginReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_portal().login(req.email, req.password))
    except Exception as e:
        return fail(str(e), 401)


@router.post("/portal/logout")
def portal_logout(authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    return ok({"logged_out": get_customer_portal().logout(token)})


@router.get("/portal/me")
def portal_me(authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    who = get_customer_portal().whoami(token)
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
        return ok(get_customer_portal().update_profile(
            cid, company=req.company, contact=req.contact,
            phone=req.phone, note=req.note))
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
        get_customer_portal().change_password(cid, req.old, req.new)
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
    return ok({"items": get_customer_portal().list_projects(cid)})


@router.post("/portal/projects")
def portal_create_project(req: ProjectReq, authorization: Optional[str] = Header(None)):
    g = _guard()
    if g:
        return g
    token = (authorization or "").replace("Bearer ", "").strip()
    cid, err = _portal_customer(token)
    if err:
        return err
    return ok(get_customer_portal().create_project(cid, req.name, req.target, req.kind))


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
        return ok(get_customer_portal().get_project(cid, project_id))
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
        return ok({"deleted": get_customer_portal().delete_project(cid, project_id)})
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
        return ok({"items": get_customer_portal().list_reports(cid, project_id)})
    except Exception as e:
        return fail(str(e), 403)


@router.post("/portal/projects/{project_id}/reports")
def portal_upload_report(project_id: str, req: ReportReq):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_customer_portal().upload_report(project_id, req.title, req.summary))
    except Exception as e:
        return fail(str(e))


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
        return ok(get_customer_portal().get_report(cid, report_id))
    except Exception as e:
        return fail(str(e), 403)


# =========================================================================== #
# 4. 计费系统（9 个端点）
# =========================================================================== #
@router.get("/billing/pricing")
def billing_pricing():
    g = _guard()
    if g:
        return g
    return ok(get_billing_system().pricing())


@router.post("/billing/scan")
def billing_record_scan(req: ScanBillingReq):
    """按扫描次数记账。"""
    g = _guard()
    if g:
        return g
    return ok(get_billing_system().record_scan(req.customer_id, req.count))


@router.post("/billing/subscribe")
def billing_subscribe(req: SubscribeReq):
    """按月/年订阅套餐。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(get_billing_system().subscribe(req.customer_id, req.plan, req.period))
    except Exception as e:
        return fail(str(e))


@router.post("/billing/pay/{invoice_id}")
def billing_pay(invoice_id: str, req: PayReq):
    """发起支付（Stripe/支付宝预留）。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(get_billing_system().pay(invoice_id, req.gateway))
    except Exception as e:
        return fail(str(e))


@router.post("/billing/pay/{invoice_id}/confirm")
def billing_confirm(invoice_id: str):
    """模拟支付成功回调。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(get_billing_system().confirm_payment(invoice_id))
    except Exception as e:
        return fail(str(e))


@router.get("/billing/invoices")
def billing_invoices(customer_id: Optional[str] = None):
    g = _guard()
    if g:
        return g
    return ok({"items": get_billing_system().list_invoices(customer_id)})


@router.get("/billing/invoices/{invoice_id}")
def billing_invoice_detail(invoice_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_billing_system().get_invoice(invoice_id))
    except Exception as e:
        return fail(str(e), 404)


@router.get("/billing/account/{customer_id}")
def billing_account(customer_id: str):
    g = _guard()
    if g:
        return g
    return ok(get_billing_system().account(customer_id))


@router.get("/billing/stats")
def billing_stats():
    g = _guard()
    if g:
        return g
    return ok(get_billing_system().admin_stats())


# =========================================================================== #
# 5. SLA 保障（8 个端点）
# =========================================================================== #
@router.get("/sla/status-page")
def sla_status_page():
    """公开状态页。"""
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().status_page())


@router.get("/sla/availability")
def sla_availability():
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().availability())


@router.post("/sla/probe")
def sla_probe(req: ProbeReq):
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().probe(req.ok, req.latency_ms))


@router.post("/sla/auto-recover")
def sla_auto_recover():
    """故障自动恢复。"""
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().auto_recover())


@router.get("/sla/incidents")
def sla_incidents(open_only: bool = False):
    g = _guard()
    if g:
        return g
    return ok({"items": get_sla_monitor().list_incidents(open_only)})


@router.post("/sla/backup")
def sla_backup(req: BackupReq):
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().backup(req.label))


@router.get("/sla/backups")
def sla_backups():
    g = _guard()
    if g:
        return g
    return ok({"items": get_sla_monitor().list_backups()})


@router.post("/sla/restore/{backup_id}")
def sla_restore(backup_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_sla_monitor().restore(backup_id))
    except Exception as e:
        return fail(str(e), 404)


@router.get("/sla/health")
def sla_health():
    g = _guard()
    if g:
        return g
    return ok(get_sla_monitor().health())
