# -*- coding: utf-8 -*-
"""
enterprise_saas_routes.py — 企业级多租户与计费 REST API（60+ 端点）。

路由前缀: /api/v1/enterprise-saas
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。
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

router = APIRouter(prefix="/api/v1/enterprise-saas",
                    tags=["企业级多租户与计费"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from enterprise_saas import multi_tenant, billing_system
    from enterprise_saas import customer_portal, sso_identity
    from enterprise_saas import audit_compliance, enterprise_dashboard
    _MOD_AVAILABLE = True
    logger.info("enterprise_saas_routes: modules loaded OK")
except Exception as e:
    logger.exception("enterprise_saas_routes: load failed: %s", e)


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


def _finish_task(task_id: str, result: Any,
                error: Optional[str] = None) -> None:
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
    """递归清理控制字符。"""
    if isinstance(obj, str):
        return "".join(c for c in obj if c >= " " or c in "\n\r\t")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(i) for i in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse(
        {"success": False, "data": None, "error": _clean(message)},
        status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("企业级SaaS模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class CreateTenantRequest(BaseModel):
    name: str
    slug: str = ""
    plan: str = "basic"
    tier: str = "basic"
    contact: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


class TenantConfigRequest(BaseModel):
    config: Dict[str, Any] = Field(default_factory=dict)


class TenantQuotaRequest(BaseModel):
    quota: Dict[str, Any] = Field(default_factory=dict)


class TenantStatusRequest(BaseModel):
    status: str


class TenantTagsRequest(BaseModel):
    tags: List[str] = Field(default_factory=list)


class TenantTierRequest(BaseModel):
    tier: str


class LifecycleRequest(BaseModel):
    action: str


class SubscribeRequest(BaseModel):
    plan_id: str
    billing_cycle: str = "monthly"


class ChangePlanRequest(BaseModel):
    plan_id: str


class UsageRecordRequest(BaseModel):
    metric: str
    quantity: float = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PaymentRequest(BaseModel):
    invoice_id: str
    method: str = "alipay"


class RefundRequest(BaseModel):
    payment_id: str
    reason: str = ""


class ProfileUpdateRequest(BaseModel):
    updates: Dict[str, Any] = Field(default_factory=dict)


class ChangePasswordRequest(BaseModel):
    old_pwd: str
    new_pwd: str


class NotificationPrefsRequest(BaseModel):
    prefs: Dict[str, bool] = Field(default_factory=dict)


class SecurityPrefsRequest(BaseModel):
    prefs: Dict[str, Any] = Field(default_factory=dict)


class CreateTeamRequest(BaseModel):
    name: str
    description: str = ""


class CreateProjectRequest(BaseModel):
    name: str
    config: Dict[str, Any] = Field(default_factory=dict)


class CreateEnterpriseAPIKeyRequest(BaseModel):
    name: str
    permissions: List[str] = Field(default_factory=list)
    expires_days: int = 90


class CreateTicketRequest(BaseModel):
    subject: str
    description: str
    priority: str = "normal"


class SAMLConfigRequest(BaseModel):
    idp_metadata_url: str
    entity_id: str = ""
    attribute_mapping: Dict[str, str] = Field(default_factory=dict)


class OIDCConfigRequest(BaseModel):
    client_id: str
    client_secret: str
    issuer: str
    scopes: str = "openid email profile"


class LDAPConfigRequest(BaseModel):
    server_url: str
    bind_dn: str
    base_dn: str
    user_filter: str = "(uid={username})"


class SSOLoginRequest(BaseModel):
    protocol: str
    email: str = ""
    ip: str = ""
    user_agent: str = ""


class MFASetupRequest(BaseModel):
    method: str = "totp"


class MFAVerifyRequest(BaseModel):
    code: str


class AuditLogRequest(BaseModel):
    event_type: str
    user_id: str = ""
    action: str = ""
    resource: str = ""
    detail: str = ""
    ip: str = ""


class ComplianceAssessmentRequest(BaseModel):
    framework_id: str


class DataClassifyRequest(BaseModel):
    data_name: str
    data_type: str
    sensitivity: str = "internal"
    owner: str = ""


class ConsentRequest(BaseModel):
    consent_type: str
    granted: bool = True
    scope: str = ""


class DSRequestRequest(BaseModel):
    request_type: str
    details: str = ""


class SettingsUpdateRequest(BaseModel):
    updates: Dict[str, Any] = Field(default_factory=dict)


class AlertCreateRequest(BaseModel):
    level: str = "warning"
    title: str
    message: str


class InvoiceTitleRequest(BaseModel):
    title: str
    tax_id: str
    address: str = ""
    bank: str = ""
    phone: str = ""


class UserRegisterRequest(BaseModel):
    email: str
    name: str
    role_id: str = "viewer"


class InviteRequest(BaseModel):
    email: str
    role_id: str = "viewer"


class CustomRoleRequest(BaseModel):
    name: str
    permissions: List[str] = Field(default_factory=list)
    description: str = ""


class ChargeCalcRequest(BaseModel):
    billing_mode: str = "hybrid"
    usage_metrics: Dict[str, float] = Field(default_factory=dict)


# =========================================================================== #
# 1. 多租户管理端点 (15)
# =========================================================================== #

@router.post("/tenants", summary="创建租户")
def ep_create_tenant(req: CreateTenantRequest):
    try:
        g = _guard()
        if g:
            return g
        t = multi_tenant.create_tenant(
            name=req.name, slug=req.slug, plan=req.plan,
            tier=req.tier, contact=req.contact, tags=req.tags)
        return ok(t)
    except Exception as e:
        logger.exception("create_tenant error")
        return fail(str(e))


@router.get("/tenants", summary="租户列表")
def ep_list_tenants(status: str = Query("", alias="status"),
                    tier: str = Query(""),
                    page: int = 1, page_size: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(multi_tenant.list_tenants(status=status, tier=tier,
                                             page=page, page_size=page_size))
    except Exception as e:
        logger.exception("list_tenants error")
        return fail(str(e))


@router.get("/tenants/{tenant_id}", summary="租户详情")
def ep_get_tenant(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        t = multi_tenant.get_tenant(tenant_id)
        if not t:
            return fail("租户不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e))


@router.put("/tenants/{tenant_id}/config", summary="更新租户配置")
def ep_update_tenant_config(tenant_id: str, req: TenantConfigRequest):
    try:
        g = _guard()
        if g:
            return g
        t = multi_tenant.update_tenant_config(tenant_id, req.config)
        if not t:
            return fail("租户不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e))


@router.put("/tenants/{tenant_id}/quota", summary="更新租户配额")
def ep_update_tenant_quota(tenant_id: str, req: TenantQuotaRequest):
    try:
        g = _guard()
        if g:
            return g
        t = multi_tenant.update_tenant_quota(tenant_id, req.quota)
        if not t:
            return fail("租户不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e))


@router.put("/tenants/{tenant_id}/status", summary="设置租户状态")
def ep_set_tenant_status(tenant_id: str, req: TenantStatusRequest):
    try:
        g = _guard()
        if g:
            return g
        t = multi_tenant.set_tenant_status(tenant_id, req.status)
        if not t:
            return fail("状态无效或租户不存在", 400)
        return ok(t)
    except Exception as e:
        return fail(str(e))


@router.put("/tenants/{tenant_id}/tags", summary="设置租户标签")
def ep_set_tenant_tags(tenant_id: str, req: TenantTagsRequest):
    try:
        g = _guard()
        if g:
            return g
        t = multi_tenant.set_tenant_tags(tenant_id, req.tags)
        if not t:
            return fail("租户不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e))


@router.put("/tenants/{tenant_id}/tier", summary="设置租户分级")
def ep_set_tenant_tier(tenant_id: str, req: TenantTierRequest):
    try:
        g = _guard()
        if g:
            return g
        t = multi_tenant.set_tenant_tier(tenant_id, req.tier)
        if not t:
            return fail("租户不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/stats", summary="租户统计")
def ep_tenant_stats(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(multi_tenant.tenant_stats(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/lifecycle", summary="租户生命周期转换")
def ep_lifecycle(tenant_id: str, req: LifecycleRequest):
    try:
        g = _guard()
        if g:
            return g
        t = multi_tenant.tenant_lifecycle_transition(tenant_id, req.action)
        if not t:
            return fail("租户不存在或操作无效", 400)
        return ok(t)
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/lifecycle", summary="租户生命周期状态")
def ep_get_lifecycle(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(multi_tenant.get_tenant_lifecycle(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.get("/roles", summary="角色列表")
def ep_list_roles(include_system: bool = True):
    try:
        g = _guard()
        if g:
            return g
        return ok(multi_tenant.list_roles(include_system=include_system))
    except Exception as e:
        return fail(str(e))


@router.post("/roles/custom", summary="创建自定义角色")
def ep_create_custom_role(tenant_id: str, req: CustomRoleRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(multi_tenant.create_custom_role(
            tenant_id, req.name, req.permissions, req.description))
    except Exception as e:
        return fail(str(e))


@router.get("/permissions", summary="权限点列表")
def ep_list_permissions():
    try:
        g = _guard()
        if g:
            return g
        return ok(multi_tenant.list_permissions())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 2. 用户管理端点 (8)
# =========================================================================== #

@router.post("/users/register", summary="注册用户")
def ep_register_user(tenant_id: str, req: UserRegisterRequest):
    try:
        g = _guard()
        if g:
            return g
        u = multi_tenant.register_user(
            tenant_id, req.email, req.name, req.role_id)
        if not u:
            return fail("注册失败", 400)
        return ok(u)
    except Exception as e:
        return fail(str(e))


@router.get("/users", summary="用户列表")
def ep_list_users(tenant_id: str = "", status: str = "",
                  page: int = 1, page_size: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(multi_tenant.list_users(
            tenant_id=tenant_id, status=status,
            page=page, page_size=page_size))
    except Exception as e:
        return fail(str(e))


@router.get("/users/{user_id}", summary="用户详情")
def ep_get_user(user_id: str):
    try:
        g = _guard()
        if g:
            return g
        u = multi_tenant.get_user(user_id)
        if not u:
            return fail("用户不存在", 404)
        return ok(u)
    except Exception as e:
        return fail(str(e))


@router.put("/users/{user_id}/status", summary="设置用户状态")
def ep_set_user_status(user_id: str, req: TenantStatusRequest):
    try:
        g = _guard()
        if g:
            return g
        u = multi_tenant.set_user_status(user_id, req.status)
        if not u:
            return fail("状态无效或用户不存在", 400)
        return ok(u)
    except Exception as e:
        return fail(str(e))


@router.post("/users/{user_id}/roles/{role_id}", summary="分配角色")
def ep_assign_role(user_id: str, role_id: str):
    try:
        g = _guard()
        if g:
            return g
        u = multi_tenant.assign_role(user_id, role_id)
        if not u:
            return fail("用户或角色不存在", 404)
        return ok(u)
    except Exception as e:
        return fail(str(e))


@router.post("/users/{user_id}/permissions", summary="获取用户权限")
def ep_user_permissions(user_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(multi_tenant.get_user_permissions(user_id))
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/invite", summary="邀请用户")
def ep_invite_user(tenant_id: str, req: InviteRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(multi_tenant.invite_user(
            tenant_id, req.email, req.role_id))
    except Exception as e:
        return fail(str(e))


@router.get("/audit/logs", summary="租户审计日志")
def ep_audit_logs(tenant_id: str = "", action: str = "",
                  page: int = 1, page_size: int = 50):
    try:
        g = _guard()
        if g:
            return g
        return ok(multi_tenant.get_audit_logs(
            tenant_id=tenant_id, action=action,
            page=page, page_size=page_size))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 3. 订阅与计费端点 (15)
# =========================================================================== #

@router.get("/plans", summary="订阅计划列表")
def ep_list_plans():
    try:
        g = _guard()
        if g:
            return g
        return ok(billing_system.list_plans())
    except Exception as e:
        return fail(str(e))


@router.get("/plans/compare", summary="计划功能对比")
def ep_compare_plans():
    try:
        g = _guard()
        if g:
            return g
        return ok(billing_system.compare_plans())
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/subscribe", summary="开通订阅")
def ep_subscribe(tenant_id: str, req: SubscribeRequest):
    try:
        g = _guard()
        if g:
            return g
        s = billing_system.subscribe(
            tenant_id, req.plan_id, req.billing_cycle)
        if not s:
            return fail("计划不存在", 404)
        return ok(s)
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/subscription", summary="获取订阅")
def ep_get_subscription(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(billing_system.get_subscription(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.put("/tenants/{tenant_id}/upgrade", summary="升级订阅")
def ep_upgrade(tenant_id: str, req: ChangePlanRequest):
    try:
        g = _guard()
        if g:
            return g
        s = billing_system.upgrade_subscription(tenant_id, req.plan_id)
        if not s:
            return fail("订阅或计划不存在", 404)
        return ok(s)
    except Exception as e:
        return fail(str(e))


@router.put("/tenants/{tenant_id}/downgrade", summary="降级订阅")
def ep_downgrade(tenant_id: str, req: ChangePlanRequest):
    try:
        g = _guard()
        if g:
            return g
        s = billing_system.downgrade_subscription(tenant_id, req.plan_id)
        if not s:
            return fail("订阅或计划不存在", 404)
        return ok(s)
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/renew", summary="续费订阅")
def ep_renew(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        s = billing_system.renew_subscription(tenant_id)
        if not s:
            return fail("订阅不存在", 404)
        return ok(s)
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/cancel", summary="取消订阅")
def ep_cancel(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        s = billing_system.cancel_subscription(tenant_id)
        if not s:
            return fail("订阅不存在", 404)
        return ok(s)
    except Exception as e:
        return fail(str(e))


@router.get("/subscriptions", summary="所有订阅列表")
def ep_list_subscriptions(page: int = 1, page_size: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(billing_system.list_subscriptions(page, page_size))
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/usage/record", summary="记录用量")
def ep_record_usage(tenant_id: str, req: UsageRecordRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(billing_system.record_usage(
            tenant_id, req.metric, req.quantity, req.metadata))
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/usage", summary="用量汇总")
def ep_usage_summary(tenant_id: str, period: str = "month"):
    try:
        g = _guard()
        if g:
            return g
        return ok(billing_system.get_usage_summary(tenant_id, period))
    except Exception as e:
        return fail(str(e))


@router.get("/invoices", summary="发票列表")
def ep_list_invoices(tenant_id: str = "", status: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(billing_system.list_invoices(tenant_id=tenant_id,
                                               status=status))
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/payment", summary="处理支付")
def ep_payment(tenant_id: str, req: PaymentRequest):
    try:
        g = _guard()
        if g:
            return g
        p = billing_system.process_payment(
            tenant_id, req.invoice_id, req.method)
        if not p:
            return fail("发票不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/refund", summary="申请退款")
def ep_refund(tenant_id: str, req: RefundRequest):
    try:
        g = _guard()
        if g:
            return g
        r = billing_system.request_refund(
            tenant_id, req.payment_id, req.reason)
        if not r:
            return fail("支付记录不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(str(e))


@router.get("/revenue/stats", summary="收入统计")
def ep_revenue_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(billing_system.revenue_stats())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 4. 客户门户端点 (12)
# =========================================================================== #

@router.get("/users/{user_id}/profile", summary="获取个人资料")
def ep_get_profile(user_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.get_profile(user_id))
    except Exception as e:
        return fail(str(e))


@router.put("/users/{user_id}/profile", summary="更新个人资料")
def ep_update_profile(user_id: str, req: ProfileUpdateRequest):
    try:
        g = _guard()
        if g:
            return g
        p = customer_portal.update_profile(user_id, req.updates)
        if not p:
            return fail("用户不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(str(e))


@router.post("/users/{user_id}/change-password", summary="修改密码")
def ep_change_password(user_id: str, req: ChangePasswordRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.change_password(
            user_id, req.old_pwd, req.new_pwd))
    except Exception as e:
        return fail(str(e))


@router.post("/teams", summary="创建团队")
def ep_create_team(tenant_id: str, req: CreateTeamRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.create_team(
            tenant_id, req.name, req.description))
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/teams", summary="团队列表")
def ep_list_teams(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.list_teams(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.post("/projects", summary="创建项目")
def ep_create_project(tenant_id: str, req: CreateProjectRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.create_portal_project(
            tenant_id, req.name, req.config))
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/projects", summary="项目列表")
def ep_list_projects(tenant_id: str, include_archived: bool = False):
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.list_portal_projects(
            tenant_id, include_archived))
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/api-keys", summary="创建API密钥")
def ep_create_api_key(tenant_id: str, req: CreateEnterpriseAPIKeyRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.create_api_key(
            tenant_id, req.name, req.permissions, req.expires_days))
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/api-keys", summary="API密钥列表")
def ep_list_api_keys(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.list_api_keys(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.get("/faq", summary="FAQ列表")
def ep_list_faq(category: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.list_faq(category))
    except Exception as e:
        return fail(str(e))


@router.post("/tickets", summary="创建工单")
def ep_create_ticket(tenant_id: str, user_id: str,
                     req: CreateTicketRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.create_ticket(
            tenant_id, user_id, req.subject, req.description, req.priority))
    except Exception as e:
        return fail(str(e))


@router.get("/status-page", summary="服务状态页")
def ep_status_page():
    try:
        g = _guard()
        if g:
            return g
        return ok(customer_portal.get_status_page())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 5. SSO与身份管理端点 (12)
# =========================================================================== #

@router.post("/tenants/{tenant_id}/sso/saml", summary="配置SAML SSO")
def ep_config_saml(tenant_id: str, req: SAMLConfigRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.configure_saml(
            tenant_id, req.idp_metadata_url, req.entity_id,
            req.attribute_mapping))
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/sso/oidc", summary="配置OIDC SSO")
def ep_config_oidc(tenant_id: str, req: OIDCConfigRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.configure_oidc(
            tenant_id, req.client_id, req.client_secret,
            req.issuer, req.scopes))
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/sso/ldap", summary="配置LDAP")
def ep_config_ldap(tenant_id: str, req: LDAPConfigRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.configure_ldap(
            tenant_id, req.server_url, req.bind_dn,
            req.base_dn, req.user_filter))
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/sso/configs", summary="SSO配置列表")
def ep_list_sso_configs(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.list_sso_configs(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.post("/sso/login", summary="SSO登录")
def ep_sso_login(tenant_id: str, req: SSOLoginRequest):
    try:
        g = _guard()
        if g:
            return g
        result = sso_identity.sso_login(
            tenant_id, req.protocol,
            {"email": req.email, "ip": req.ip,
             "user_agent": req.user_agent})
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.post("/sso/logout", summary="SSO登出")
def ep_sso_logout(session_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.sso_logout(session_id))
    except Exception as e:
        return fail(str(e))


@router.post("/users/{user_id}/mfa/setup", summary="设置MFA")
def ep_setup_mfa(user_id: str, req: MFASetupRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.setup_mfa(user_id, req.method))
    except Exception as e:
        return fail(str(e))


@router.post("/users/{user_id}/mfa/verify", summary="验证MFA")
def ep_verify_mfa(user_id: str, req: MFAVerifyRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.verify_mfa(user_id, req.code))
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/login-logs", summary="登录日志")
def ep_login_logs(tenant_id: str, status: str = "",
                  page: int = 1, page_size: int = 50):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.get_login_logs(
            tenant_id=tenant_id, status=status,
            page=page, page_size=page_size))
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/risk-report", summary="风险报告")
def ep_risk_report(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.get_risk_report(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.get("/sessions", summary="活跃会话")
def ep_active_sessions(tenant_id: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.get_active_sessions(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.post("/identity/onboard", summary="身份入职")
def ep_identity_onboard(tenant_id: str, email: str,
                        name: str, dept: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(sso_identity.identity_onboard(
            tenant_id, email, name, dept))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 6. 审计与合规端点 (10)
# =========================================================================== #

@router.post("/audit/log", summary="记录审计事件")
def ep_log_audit(req: AuditLogRequest, tenant_id: str = ""):
    try:
        g = _guard()
        if g:
            return g
        return ok(audit_compliance.log_event(
            tenant_id, req.event_type, req.user_id,
            req.action, req.resource, req.detail, req.ip))
    except Exception as e:
        return fail(str(e))


@router.get("/audit/query", summary="查询审计日志")
def ep_query_audit(tenant_id: str = "", event_type: str = "",
                   user_id: str = "", page: int = 1, page_size: int = 50):
    try:
        g = _guard()
        if g:
            return g
        return ok(audit_compliance.query_audit_logs(
            tenant_id=tenant_id, event_type=event_type,
            user_id=user_id, page=page, page_size=page_size))
    except Exception as e:
        return fail(str(e))


@router.get("/audit/verify", summary="验证日志完整性")
def ep_verify_integrity():
    try:
        g = _guard()
        if g:
            return g
        return ok(audit_compliance.verify_log_integrity())
    except Exception as e:
        return fail(str(e))


@router.get("/compliance/frameworks", summary="合规框架列表")
def ep_list_frameworks():
    try:
        g = _guard()
        if g:
            return g
        return ok(audit_compliance.list_frameworks())
    except Exception as e:
        return fail(str(e))


@router.post("/tenants/{tenant_id}/compliance/assess",
             summary="执行合规评估")
def ep_compliance_assess(tenant_id: str, req: ComplianceAssessmentRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(audit_compliance.run_compliance_assessment(
            tenant_id, req.framework_id))
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/compliance/report",
            summary="合规报告")
def ep_compliance_report(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(audit_compliance.get_compliance_report(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.post("/data/classify", summary="数据分类分级")
def ep_classify_data(tenant_id: str, req: DataClassifyRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(audit_compliance.classify_data(
            tenant_id, req.data_name, req.data_type,
            req.sensitivity, req.owner))
    except Exception as e:
        return fail(str(e))


@router.get("/tenants/{tenant_id}/data-catalog",
            summary="数据目录")
def ep_data_catalog(tenant_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(audit_compliance.list_data_catalog(tenant_id))
    except Exception as e:
        return fail(str(e))


@router.post("/privacy/consent", summary="记录用户同意")
def ep_record_consent(user_id: str, req: ConsentRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(audit_compliance.record_consent(
            user_id, req.consent_type, req.granted, req.scope))
    except Exception as e:
        return fail(str(e))


@router.post("/privacy/dsr", summary="数据主体权利请求")
def ep_dsr(user_id: str, req: DSRequestRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(audit_compliance.submit_data_subject_request(
            user_id, req.request_type, req.details))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 7. 企业管理控制台端点 (8)
# =========================================================================== #

@router.get("/dashboard/overview", summary="企业总览")
def ep_dashboard_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(enterprise_dashboard.get_overview())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/tenants", summary="租户管理列表")
def ep_dashboard_tenants(status: str = "",
                         page: int = 1, page_size: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(enterprise_dashboard.tenant_management_list(
            status=status, page=page, page_size=page_size))
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/users", summary="用户管理列表")
def ep_dashboard_users(tenant_id: str = "", status: str = "",
                       page: int = 1, page_size: int = 20):
    try:
        g = _guard()
        if g:
            return g
        return ok(enterprise_dashboard.user_management_list(
            tenant_id=tenant_id, status=status,
            page=page, page_size=page_size))
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/billing", summary="计费管理总览")
def ep_dashboard_billing():
    try:
        g = _guard()
        if g:
            return g
        return ok(enterprise_dashboard.billing_overview())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/analytics", summary="运营分析")
def ep_dashboard_analytics(period: str = "30d"):
    try:
        g = _guard()
        if g:
            return g
        return ok(enterprise_dashboard.operational_analytics(period))
    except Exception as e:
        return fail(str(e))


@router.get("/settings", summary="系统设置")
def ep_get_settings():
    try:
        g = _guard()
        if g:
            return g
        return ok(enterprise_dashboard.get_system_settings())
    except Exception as e:
        return fail(str(e))


@router.put("/settings/{section}", summary="更新系统设置")
def ep_update_settings(section: str, req: SettingsUpdateRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(enterprise_dashboard.update_system_settings(
            section, req.updates))
    except Exception as e:
        return fail(str(e))


@router.get("/alerts", summary="告警列表")
def ep_list_alerts():
    try:
        g = _guard()
        if g:
            return g
        return ok(enterprise_dashboard.get_alerts())
    except Exception as e:
        return fail(str(e))
