# -*- coding: utf-8 -*-
"""商业化 API 路由。

提供多租户管理、计费订阅、API Key、数据安全、用户认证等接口。
所有引擎采用延迟导入，单个引擎不可用不影响整个路由模块导入。
"""
import os
import traceback
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field


router = APIRouter(prefix="/api/v1/commercial", tags=["商业化管理"])


# ============== 请求模型 ==============

class TenantCreateRequest(BaseModel):
    tenant_id: str = Field(..., description="租户唯一标识")
    name: str = Field(..., description="租户名称")
    plan: str = Field("FREE", description="订阅计划: FREE/PRO/ENTERPRISE")
    quotas: Optional[Dict[str, int]] = Field(None, description="自定义配额")


class TenantQuotaUpdate(BaseModel):
    quota_type: str = Field(..., description="配额类型: scan_count/storage_mb/api_calls_daily/users/api_keys")
    value: int = Field(..., description="配额值")


class SubscribeRequest(BaseModel):
    plan: str = Field(..., description="订阅计划: FREE/PRO/ENTERPRISE")
    cycle: str = Field("monthly", description="计费周期: monthly/yearly")


class OrderRequest(BaseModel):
    tenant_id: str = Field(..., description="租户ID")
    plan: str = Field(..., description="计划")
    cycle: str = Field("monthly", description="monthly/yearly")


class PayRequest(BaseModel):
    payment_method: str = Field("simulated", description="支付方式")


class CommercialApiKeyCreateRequest(BaseModel):
    tenant_id: str = Field(..., description="租户ID")
    username: str = Field(..., description="用户名")
    name: str = Field("", description="Key 备注名")
    permissions: Optional[List[str]] = None
    rate_limit: Optional[int] = None


class UserCreateRequest(BaseModel):
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")
    tenant_id: str = Field("default", description="租户ID")
    role: str = Field("user", description="角色")
    email: str = Field("", description="邮箱")


class LoginRequest(BaseModel):
    username: str
    password: str
    ip: str = ""
    user_agent: str = ""


# ============== 引擎装配（延迟导入 + 单例） ==============

_engines: Dict[str, Any] = {}


def _get_engines() -> Dict[str, Any]:
    """装配引擎（首次调用时初始化）。"""
    if _engines:
        return _engines
    try:
        from commercial.multi_tenant import get_tenant_manager
        from commercial.billing import get_billing_engine
        from commercial.api_gateway import get_api_gateway
        from commercial.data_security import get_data_security
        tm = get_tenant_manager("data/tenants")
        billing = get_billing_engine("data/tenants", tm)
        gateway = get_api_gateway("data/tenants", tm)
        sec = get_data_security("data", tm)
        _engines.update({"tm": tm, "billing": billing,
                         "gateway": gateway, "sec": sec})
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500,
                            detail=f"商业化引擎初始化失败: {e}")
    return _engines


def _get_user_manager():
    """获取 UserManager（延迟导入）。"""
    from utils.multi_user import user_manager
    return user_manager


# ============== 租户管理 ==============

@router.post("/tenants", summary="创建租户")
def create_tenant(req: TenantCreateRequest):
    eng = _get_engines()
    try:
        tenant = eng["tm"].create_tenant(
            req.tenant_id, req.name, req.plan, quotas=req.quotas)
        # 同步订阅关系
        eng["billing"].subscribe(req.tenant_id, req.plan, "monthly")
        return {"status": "success", "tenant": tenant}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/tenants", summary="租户列表")
def list_tenants():
    eng = _get_engines()
    return {"tenants": eng["tm"].list_tenants()}


@router.get("/tenants/{tenant_id}", summary="租户详情")
def get_tenant(tenant_id: str):
    eng = _get_engines()
    t = eng["tm"].get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="租户不存在")
    t["usage"] = eng["tm"].usage_snapshot(tenant_id)
    return t


@router.put("/tenants/{tenant_id}/quota", summary="更新租户配额")
def update_quota(tenant_id: str, req: TenantQuotaUpdate):
    eng = _get_engines()
    ok = eng["tm"].update_quota(tenant_id, req.quota_type, req.value)
    if not ok:
        raise HTTPException(status_code=404, detail="租户不存在")
    return {"status": "success", "tenant_id": tenant_id,
            "quota_type": req.quota_type, "value": req.value}


@router.post("/tenants/{tenant_id}/disable", summary="禁用租户")
def disable_tenant(tenant_id: str):
    eng = _get_engines()
    ok = eng["tm"].disable_tenant(tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail="租户不存在")
    return {"status": "disabled", "tenant_id": tenant_id}


@router.post("/tenants/{tenant_id}/enable", summary="启用租户")
def enable_tenant(tenant_id: str):
    eng = _get_engines()
    ok = eng["tm"].enable_tenant(tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail="租户不存在")
    return {"status": "active", "tenant_id": tenant_id}


# ============== 计费 ==============

@router.post("/billing/subscribe", summary="订阅计划")
def subscribe(tenant_id: str, req: SubscribeRequest):
    eng = _get_engines()
    try:
        sub = eng["billing"].subscribe(tenant_id, req.plan, req.cycle)
        return {"status": "success", "subscription": sub}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/billing/subscription/{tenant_id}", summary="获取订阅")
def get_subscription(tenant_id: str):
    eng = _get_engines()
    sub = eng["billing"].get_subscription(tenant_id)
    if not sub:
        raise HTTPException(status_code=404, detail="无订阅")
    return sub


@router.post("/billing/order", summary="创建订单")
def create_order(req: OrderRequest):
    eng = _get_engines()
    try:
        order = eng["billing"].create_order(req.tenant_id, req.plan, req.cycle)
        return order
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/billing/pay/{order_id}", summary="支付订单（模拟）")
def pay_order(order_id: str, req: PayRequest):
    eng = _get_engines()
    try:
        return eng["billing"].pay_order(order_id, req.payment_method)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/billing/usage/{tenant_id}", summary="获取用量")
def get_usage(tenant_id: str, period: Optional[str] = None):
    eng = _get_engines()
    usage = eng["billing"].get_usage(tenant_id, period)
    usage["overage"] = eng["billing"].check_overage(tenant_id)
    usage["quota_snapshot"] = eng["tm"].usage_snapshot(tenant_id)
    return usage


@router.get("/billing/invoice/{order_id}", summary="获取发票")
def get_invoice(order_id: str):
    eng = _get_engines()
    try:
        path = eng["billing"].generate_invoice(order_id)
        if os.path.exists(path):
            return FileResponse(path, media_type="text/html",
                                filename=os.path.basename(path))
        return {"invoice_path": path}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============== API Key ==============

@router.post("/api-keys", summary="创建 API Key")
def create_api_key(req: CommercialApiKeyCreateRequest):
    eng = _get_engines()
    plain, key_id = eng["gateway"].create_api_key(
        req.tenant_id, req.username, req.name,
        req.permissions, req.rate_limit)
    return {"status": "success", "key": plain, "key_id": key_id,
            "warning": "请妥善保存，明文仅显示一次"}


@router.get("/api-keys/{tenant_id}", summary="列出租户 API Key")
def list_api_keys(tenant_id: str):
    eng = _get_engines()
    return {"api_keys": eng["gateway"].list_api_keys(tenant_id)}


@router.delete("/api-keys/{key_id}", summary="吊销 API Key")
def revoke_api_key(key_id: str):
    eng = _get_engines()
    ok = eng["gateway"].revoke_api_key(key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Key 不存在")
    return {"status": "revoked", "key_id": key_id}


@router.get("/api-keys/stats/{key_id}", summary="Key 调用统计")
def api_key_stats(key_id: str):
    eng = _get_engines()
    stats = eng["gateway"].get_api_key_stats(key_id)
    if not stats:
        raise HTTPException(status_code=404, detail="Key 不存在")
    return stats


# ============== 数据安全 ==============

@router.post("/data/export/{tenant_id}", summary="导出租户数据")
def export_data(tenant_id: str):
    eng = _get_engines()
    path = eng["sec"].export_tenant_data(tenant_id)
    return {"status": "success", "path": path}


@router.post("/data/delete/{tenant_id}", summary="彻底删除租户数据")
def delete_data(tenant_id: str):
    eng = _get_engines()
    result = eng["sec"].delete_tenant_data(tenant_id)
    return {"status": "success", **result}


@router.get("/data/audit/{tenant_id}", summary="查询审计日志")
def get_audit(tenant_id: str, limit: int = 100):
    eng = _get_engines()
    return {"logs": eng["sec"].get_audit_logs(tenant_id, limit)}


# ============== 用户管理 / 认证 ==============

@router.post("/users", summary="创建租户用户")
def create_user(req: UserCreateRequest):
    um = _get_user_manager()
    user = um.create_user(req.username, req.password, req.email,
                          req.role, req.tenant_id)
    if not user:
        raise HTTPException(status_code=400,
                            detail="用户已存在或角色无效")
    return {"status": "success", "username": user.username,
            "tenant_id": user.tenant_id, "role": user.role}


@router.get("/users/{tenant_id}", summary="列出租户用户")
def list_users(tenant_id: str):
    um = _get_user_manager()
    users = um.list_users(tenant_id)
    return {"users": [{"username": u.username, "role": u.role,
                       "email": u.email, "is_active": u.is_active,
                       "last_login": u.last_login} for u in users]}


@router.post("/auth/login", summary="登录")
def login(req: LoginRequest):
    um = _get_user_manager()
    token = um.login(req.username, req.password, req.ip, req.user_agent)
    if not token:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    user = um.get_user(req.username)
    return {"status": "success", "session_token": token,
            "tenant_id": user.tenant_id if user else "default",
            "role": user.role if user else "user"}


@router.post("/auth/logout", summary="登出")
def logout(session_token: str):
    um = _get_user_manager()
    um.logout(session_token)
    return {"status": "logged_out"}
