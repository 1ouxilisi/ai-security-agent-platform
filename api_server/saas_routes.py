#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
saas_routes 模块 — SaaS 化管理 API（第10轮升级）

前缀: /api/v1/saas
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点包裹 try-except，不返回 500。

注意：本模块仅用于授权的安全产品。
"""

import os
import sys
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from saas.auth_manager import auth_manager            # noqa: E402
from saas.mfa_manager import mfa_manager              # noqa: E402
from saas.user_manager import user_manager            # noqa: E402
from saas.invitation_manager import invitation_manager  # noqa: E402
from saas.tenant_manager import TenantManager         # noqa: E402

router = APIRouter(prefix="/api/v1/saas", tags=["SaaS管理"])

_tenant_manager = TenantManager(db_path=os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "tenants.json"))


def _ok(data: Any = None) -> Dict[str, Any]:
    """统一成功响应。"""
    return {"success": True, "data": data, "error": None}


def _err(msg: str) -> Dict[str, Any]:
    """统一失败响应。"""
    return {"success": False, "data": None, "error": msg}


# ============================ 请求模型 ============================
class RegisterIn(BaseModel):
    username: str
    email: str
    password: str
    phone: Optional[str] = None


class LoginIn(BaseModel):
    identifier: str
    password: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None


class RefreshIn(BaseModel):
    refresh_token: str


class ResetReqIn(BaseModel):
    email_or_phone: str


class ResetConfirmIn(BaseModel):
    token: str
    new_password: str


class ChangePwdIn(BaseModel):
    user_id: str
    old_password: str
    new_password: str


class LogoutIn(BaseModel):
    session_id: str


class UserCreateIn(BaseModel):
    username: str
    email: str
    password: str
    display_name: Optional[str] = ""
    department: Optional[str] = ""
    position: Optional[str] = ""
    phone: Optional[str] = ""


class UserUpdateIn(BaseModel):
    display_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    department: Optional[str] = None
    position: Optional[str] = None
    status: Optional[str] = None


class ImportIn(BaseModel):
    csv_data: str


class InvitationIn(BaseModel):
    email: str
    role: str = "user"
    expires_in_days: int = 7
    max_uses: int = 1
    message: Optional[str] = None


class TenantCreateIn(BaseModel):
    name: str
    plan: str = "free"
    owner_email: str = ""
    owner_name: str = ""


# ============================ 认证（9） ============================
@router.post("/auth/register", summary="用户注册")
async def auth_register(body: RegisterIn):
    try:
        return _ok(auth_manager.register(body.username, body.email, body.password, body.phone))
    except ValueError as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"注册失败: {e}")


@router.post("/auth/login", summary="用户登录")
async def auth_login(body: LoginIn):
    try:
        return _ok(auth_manager.login(body.identifier, body.password, body.ip, body.user_agent))
    except ValueError as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"登录失败: {e}")


@router.post("/auth/logout", summary="登出")
async def auth_logout(body: LogoutIn):
    try:
        return _ok({"revoked": auth_manager.logout(body.session_id)})
    except Exception as e:
        return _err(f"登出失败: {e}")


@router.post("/auth/refresh", summary="刷新Token")
async def auth_refresh(body: RefreshIn):
    try:
        return _ok(auth_manager.refresh_token(body.refresh_token))
    except ValueError as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"刷新失败: {e}")


@router.post("/auth/password/reset", summary="请求重置密码")
async def auth_reset_request(body: ResetReqIn):
    try:
        return _ok(auth_manager.reset_password_request(body.email_or_phone))
    except Exception as e:
        return _err(f"请求失败: {e}")


@router.post("/auth/password/reset/confirm", summary="确认重置密码")
async def auth_reset_confirm(body: ResetConfirmIn):
    try:
        return _ok({"changed": auth_manager.reset_password_confirm(body.token, body.new_password)})
    except ValueError as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"重置失败: {e}")


@router.post("/auth/password/change", summary="修改密码")
async def auth_change_password(body: ChangePwdIn):
    try:
        return _ok({"changed": auth_manager.change_password(
            body.user_id, body.old_password, body.new_password)})
    except ValueError as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"修改失败: {e}")


@router.get("/auth/sessions", summary="会话列表")
async def auth_sessions(user_id: str = Query(...)):
    try:
        return _ok(auth_manager.get_sessions(user_id))
    except Exception as e:
        return _err(f"获取会话失败: {e}")


@router.post("/auth/sessions/{session_id}/revoke", summary="撤销会话")
async def auth_revoke_session(session_id: str):
    try:
        return _ok({"revoked": auth_manager.revoke_session(session_id)})
    except Exception as e:
        return _err(f"撤销失败: {e}")


@router.get("/auth/login-logs", summary="登录日志")
async def auth_login_logs(user_id: Optional[str] = None, limit: int = 50):
    try:
        return _ok(auth_manager.get_login_logs(user_id, limit))
    except Exception as e:
        return _err(f"获取日志失败: {e}")


# ============================ MFA（8） ============================
@router.get("/mfa/methods", summary="MFA方法列表")
async def mfa_methods():
    try:
        return _ok({
            "methods": [
                {"key": "totp", "name": "TOTP 验证器", "desc": "RFC6238，30秒动态码"},
                {"key": "hotp", "name": "HOTP", "desc": "RFC4226，计数器动态码"},
                {"key": "webauthn", "name": "安全密钥", "desc": "WebAuthn / FIDO2"},
                {"key": "sms", "name": "短信", "desc": "6位短信验证码"},
                {"key": "email", "name": "邮件", "desc": "6位邮件验证码"},
            ]
        })
    except Exception as e:
        return _err(str(e))


@router.post("/mfa/totp/enable", summary="启用TOTP")
async def mfa_totp_enable(user_id: str = Query(...)):
    try:
        return _ok(mfa_manager.enable_totp(user_id))
    except Exception as e:
        return _err(f"启用失败: {e}")


@router.post("/mfa/totp/verify", summary="验证TOTP")
async def mfa_totp_verify(user_id: str = Query(...), code: str = Query(...)):
    try:
        return _ok({"verified": mfa_manager.verify_totp(user_id, code)})
    except Exception as e:
        return _err(f"验证失败: {e}")


@router.post("/mfa/totp/backup-codes", summary="生成备份码")
async def mfa_backup_codes(user_id: str = Query(...), count: int = 10):
    try:
        return _ok({"codes": mfa_manager.generate_backup_codes(user_id, count)})
    except Exception as e:
        return _err(f"生成失败: {e}")


@router.post("/mfa/webauthn/register", summary="注册WebAuthn")
async def mfa_webauthn_register_begin(user_id: str = Query(...)):
    try:
        return _ok(mfa_manager.webauthn_register_begin(user_id))
    except Exception as e:
        return _err(f"注册失败: {e}")


@router.post("/mfa/webauthn/verify", summary="验证WebAuthn")
async def mfa_webauthn_verify(user_id: str = Query(...)):
    try:
        begin = mfa_manager.webauthn_verify_begin(user_id)
        return _ok(begin)
    except Exception as e:
        return _err(f"验证失败: {e}")


@router.post("/mfa/disable", summary="禁用MFA")
async def mfa_disable(user_id: str = Query(...)):
    try:
        return _ok({"disabled": mfa_manager.disable_mfa(user_id)})
    except Exception as e:
        return _err(f"禁用失败: {e}")


@router.get("/mfa/status", summary="MFA状态")
async def mfa_status(user_id: str = Query(...)):
    try:
        return _ok(mfa_manager.get_mfa_status(user_id))
    except Exception as e:
        return _err(f"获取状态失败: {e}")


@router.get("/mfa/trusted-devices", summary="受信任设备")
async def mfa_trusted_devices(user_id: str = Query(...)):
    try:
        return _ok(mfa_manager.get_trusted_devices(user_id))
    except Exception as e:
        return _err(f"获取设备失败: {e}")


# ============================ 用户（9+） ============================
# 注意：/users/stats 必须声明在 /users/{user_id} 之前
@router.get("/users/stats", summary="用户统计")
async def users_stats():
    try:
        return _ok(user_manager.get_stats())
    except Exception as e:
        return _err(f"统计失败: {e}")


@router.get("/users", summary="用户列表")
async def users_list(
    page: int = 1, page_size: int = 20,
    status: Optional[str] = None,
    department: Optional[str] = None,
    keyword: Optional[str] = None,
):
    try:
        return _ok(user_manager.list_users(page, page_size,
                                           status=status, department=department, keyword=keyword))
    except Exception as e:
        return _err(f"列表失败: {e}")


@router.post("/users", summary="创建用户")
async def users_create(body: UserCreateIn):
    try:
        return _ok(user_manager.create_user(
            body.username, body.email, body.password,
            display_name=body.display_name, department=body.department,
            position=body.position, phone=body.phone))
    except ValueError as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"创建失败: {e}")


@router.post("/users/import", summary="批量导入")
async def users_import(body: ImportIn):
    try:
        return _ok(user_manager.import_users(body.csv_data))
    except ValueError as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"导入失败: {e}")


@router.get("/users/{user_id}", summary="用户详情")
async def users_detail(user_id: str):
    try:
        u = user_manager.get_user(user_id)
        if not u:
            return _err("用户不存在")
        return _ok(u)
    except Exception as e:
        return _err(f"查询失败: {e}")


@router.put("/users/{user_id}", summary="更新用户")
async def users_update(user_id: str, body: UserUpdateIn):
    try:
        u = user_manager.update_user(user_id, **body.model_dump(exclude_none=True))
        if not u:
            return _err("用户不存在")
        return _ok(u)
    except Exception as e:
        return _err(f"更新失败: {e}")


@router.delete("/users/{user_id}", summary="删除用户")
async def users_delete(user_id: str):
    try:
        return _ok({"deleted": user_manager.delete_user(user_id)})
    except Exception as e:
        return _err(f"删除失败: {e}")


@router.post("/users/{user_id}/lock", summary="锁定用户")
async def users_lock(user_id: str):
    try:
        return _ok({"locked": user_manager.lock_user(user_id)})
    except Exception as e:
        return _err(f"锁定失败: {e}")


@router.post("/users/{user_id}/unlock", summary="解锁用户")
async def users_unlock(user_id: str):
    try:
        return _ok({"unlocked": user_manager.unlock_user(user_id)})
    except Exception as e:
        return _err(f"解锁失败: {e}")


@router.get("/users/export", summary="导出用户")
async def users_export(format: str = "json"):
    try:
        return _ok({"data": user_manager.export_users(format)})
    except Exception as e:
        return _err(f"导出失败: {e}")


# ============================ 邀请（5+） ============================
@router.get("/invitations/stats", summary="邀请统计")
async def invitations_stats():
    try:
        return _ok(invitation_manager.get_stats())
    except Exception as e:
        return _err(f"统计失败: {e}")


@router.get("/invitations", summary="邀请列表")
async def invitations_list(status: Optional[str] = None, page: int = 1, page_size: int = 20):
    try:
        return _ok(invitation_manager.list_invitations(status, page, page_size))
    except Exception as e:
        return _err(f"列表失败: {e}")


@router.post("/invitations", summary="创建邀请")
async def invitations_create(body: InvitationIn):
    try:
        inv = invitation_manager.create_invitation(
            body.email, body.role, body.expires_in_days, body.max_uses, body.message)
        invitation_manager.send_invitation(inv["invitation_id"])
        return _ok(inv)
    except Exception as e:
        return _err(f"创建失败: {e}")


@router.post("/invitations/{invitation_id}/resend", summary="重新发送邀请")
async def invitations_resend(invitation_id: str):
    try:
        return _ok({"resent": invitation_manager.resend_invitation(invitation_id)})
    except Exception as e:
        return _err(f"重发失败: {e}")


@router.post("/invitations/{invitation_id}/revoke", summary="撤销邀请")
async def invitations_revoke(invitation_id: str):
    try:
        return _ok({"revoked": invitation_manager.revoke_invitation(invitation_id)})
    except Exception as e:
        return _err(f"撤销失败: {e}")


@router.post("/invitations/accept", summary="接受邀请")
async def invitations_accept(token: str, password: Optional[str] = None):
    try:
        return _ok(invitation_manager.accept_invitation(token, password))
    except ValueError as e:
        return _err(str(e))
    except Exception as e:
        return _err(f"接受失败: {e}")


# ============================ 租户（3） ============================
@router.get("/tenants", summary="租户列表")
async def tenants_list():
    try:
        items = [dict(t.__dict__) for t in _tenant_manager.tenants.values()]
        return _ok({"items": items, "total": len(items)})
    except Exception as e:
        return _err(f"列表失败: {e}")


@router.post("/tenants", summary="创建租户")
async def tenants_create(body: TenantCreateIn):
    try:
        t = _tenant_manager.create_tenant(body.name, body.plan, body.owner_email, body.owner_name)
        return _ok(dict(t.__dict__))
    except Exception as e:
        return _err(f"创建失败: {e}")


@router.get("/tenants/{tenant_id}/stats", summary="租户统计")
async def tenants_stats(tenant_id: str):
    try:
        stats = _tenant_manager.get_usage_stats(tenant_id)
        if not stats:
            return _err("租户不存在")
        return _ok(stats)
    except Exception as e:
        return _err(f"统计失败: {e}")
