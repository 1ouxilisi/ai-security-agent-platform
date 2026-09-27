# -*- coding: utf-8 -*-
"""
sso_routes.py — SSO / LDAP 集成 REST API。

路由前缀：/api/v1/sso
统一响应格式：{"success": bool, "data": ..., "error": ...}
所有端点 try/except 包裹，不向外抛出 500。

端点分组：
    SAML 6 个 / OAuth2 6 个 / LDAP 6 个 / SSO 统一 5 个
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 保证从任意工作目录导入 sso 包
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sso", tags=["SSO/LDAP集成"])

# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from sso import ldap_manager, oauth2_manager, saml_manager, sso_manager
    _MOD_AVAILABLE = True
    logger.info("sso_routes: SSO/LDAP 模块加载成功")
except Exception as e:  # pragma: no cover
    logger.exception("sso_routes: 加载失败: %s", e)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _fail(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": message},
                        status_code=status)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return _fail("SSO/LDAP 模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class SamlConfigReq(BaseModel):
    name: str
    entity_id: str = ""
    sso_url: str = ""
    slo_url: Optional[str] = None
    certificate: Optional[str] = None
    attribute_mapping: Optional[Dict[str, str]] = None


class SamlConfigUpdate(BaseModel):
    name: Optional[str] = None
    sso_url: Optional[str] = None
    slo_url: Optional[str] = None
    certificate: Optional[str] = None
    attribute_mapping: Optional[Dict[str, str]] = None
    enabled: Optional[bool] = None


class OAuth2ConfigReq(BaseModel):
    name: str
    provider: str = "custom"
    client_id: str = ""
    client_secret: str = ""
    auth_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    scopes: Optional[str] = None
    redirect_uri: str = ""
    attribute_mapping: Optional[Dict[str, str]] = None


class OAuth2ConfigUpdate(BaseModel):
    name: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    auth_url: Optional[str] = None
    token_url: Optional[str] = None
    userinfo_url: Optional[str] = None
    scopes: Optional[str] = None
    redirect_uri: Optional[str] = None
    attribute_mapping: Optional[Dict[str, str]] = None
    enabled: Optional[bool] = None


class LdapConfigReq(BaseModel):
    name: str
    host: str
    port: int = 389
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    use_ssl: bool = False
    use_tls: bool = False
    timeout: int = 10
    user_search_base: Optional[str] = None
    user_filter: Optional[str] = None
    attribute_mapping: Optional[Dict[str, str]] = None


class LdapConfigUpdate(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    base_dn: Optional[str] = None
    bind_dn: Optional[str] = None
    bind_password: Optional[str] = None
    use_ssl: Optional[bool] = None
    use_tls: Optional[bool] = None
    timeout: Optional[int] = None
    attribute_mapping: Optional[Dict[str, str]] = None
    enabled: Optional[bool] = None


class AcsReq(BaseModel):
    saml_response: str = ""
    relay_state: Optional[str] = None


# =========================================================================== #
# SAML 端点（6）
# =========================================================================== #
@router.get("/saml/config")
def saml_list_config():
    """列出全部 SAML 配置。"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(saml_manager.list_configs())
    except Exception as e:
        logger.exception("saml_list_config error")
        return _fail(str(e))


@router.post("/saml/config")
def saml_create_config(req: SamlConfigReq):
    """创建 SAML 配置。"""
    try:
        g = _guard()
        if g:
            return g
        cfg = saml_manager.create_config(
            name=req.name, entity_id=req.entity_id, sso_url=req.sso_url,
            slo_url=req.slo_url, certificate=req.certificate,
            attribute_mapping=req.attribute_mapping)
        return _ok(cfg)
    except Exception as e:
        logger.exception("saml_create_config error")
        return _fail(str(e))


@router.put("/saml/config/{config_id}")
def saml_update_config(config_id: str, req: SamlConfigUpdate):
    """更新 SAML 配置。"""
    try:
        g = _guard()
        if g:
            return g
        kwargs = {k: v for k, v in req.model_dump().items() if v is not None}
        cfg = saml_manager.update_config(config_id, **kwargs)
        if not cfg:
            return _fail("配置不存在", 404)
        return _ok(cfg)
    except Exception as e:
        logger.exception("saml_update_config error")
        return _fail(str(e))


@router.get("/saml/config/{config_id}/metadata")
def saml_metadata(config_id: str):
    """获取 SP 元数据 XML。"""
    try:
        g = _guard()
        if g:
            return g
        xml = saml_manager.get_sp_metadata(config_id)
        return _ok({"config_id": config_id, "metadata": xml, "content_type": "application/xml"})
    except Exception as e:
        logger.exception("saml_metadata error")
        return _fail(str(e))


@router.post("/saml/{config_id}/login")
def saml_login(config_id: str, relay_state: Optional[str] = Body(None, embed=True)):
    """SP 发起 SSO，返回 IdP 跳转地址。"""
    try:
        g = _guard()
        if g:
            return g
        result = saml_manager.initiate_sso(config_id, relay_state=relay_state)
        return _ok(result)
    except Exception as e:
        logger.exception("saml_login error")
        return _fail(str(e))


@router.post("/saml/{config_id}/acs")
def saml_acs(config_id: str, req: AcsReq):
    """ACS：处理 IdP 回传的 SAML Response。"""
    try:
        g = _guard()
        if g:
            return g
        result = saml_manager.process_acs(config_id, req.saml_response)
        return _ok(result)
    except Exception as e:
        logger.exception("saml_acs error")
        return _fail(str(e))


# =========================================================================== #
# OAuth2 / OIDC 端点（6）
# =========================================================================== #
@router.get("/oauth2/config")
def oauth2_list_config():
    """列出全部 OAuth2 配置。"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(oauth2_manager.list_configs())
    except Exception as e:
        logger.exception("oauth2_list_config error")
        return _fail(str(e))


@router.post("/oauth2/config")
def oauth2_create_config(req: OAuth2ConfigReq):
    """创建 OAuth2 配置。"""
    try:
        g = _guard()
        if g:
            return g
        cfg = oauth2_manager.create_config(
            name=req.name, provider=req.provider, client_id=req.client_id,
            client_secret=req.client_secret, auth_url=req.auth_url,
            token_url=req.token_url, userinfo_url=req.userinfo_url,
            scopes=req.scopes, redirect_uri=req.redirect_uri,
            attribute_mapping=req.attribute_mapping)
        return _ok(cfg)
    except Exception as e:
        logger.exception("oauth2_create_config error")
        return _fail(str(e))


@router.put("/oauth2/config/{config_id}")
def oauth2_update_config(config_id: str, req: OAuth2ConfigUpdate):
    """更新 OAuth2 配置。"""
    try:
        g = _guard()
        if g:
            return g
        kwargs = {k: v for k, v in req.model_dump().items() if v is not None}
        cfg = oauth2_manager.update_config(config_id, **kwargs)
        if not cfg:
            return _fail("配置不存在", 404)
        return _ok(cfg)
    except Exception as e:
        logger.exception("oauth2_update_config error")
        return _fail(str(e))


@router.get("/oauth2/{config_id}/login")
def oauth2_login(config_id: str, state: Optional[str] = Query(None),
                 scope: Optional[str] = Query(None)):
    """获取 OAuth2 授权跳转 URL。"""
    try:
        g = _guard()
        if g:
            return g
        result = oauth2_manager.get_auth_url(config_id, state=state, scope=scope)
        return _ok(result)
    except Exception as e:
        logger.exception("oauth2_login error")
        return _fail(str(e))


@router.get("/oauth2/{config_id}/callback")
def oauth2_callback(config_id: str, code: str = Query(""), state: Optional[str] = Query(None),
                   redirect_uri: Optional[str] = Query(None)):
    """OAuth2 回调：用 code 换 token 并拉取用户信息。"""
    try:
        g = _guard()
        if g:
            return g
        token_res = oauth2_manager.exchange_token(config_id, code, redirect_uri=redirect_uri)
        if not token_res.get("success"):
            return _ok({"success": False, "error": token_res.get("error"), "state": state})
        token = token_res["token"]
        ui = oauth2_manager.get_user_info(config_id, token.get("access_token", ""))
        return _ok({"success": True, "token": token, "user_info": ui.get("user_info", {}),
                    "state": state})
    except Exception as e:
        logger.exception("oauth2_callback error")
        return _fail(str(e))


@router.post("/oauth2/{config_id}/refresh")
def oauth2_refresh(config_id: str, refresh_token: str = Body("", embed=True)):
    """刷新 Access Token。"""
    try:
        g = _guard()
        if g:
            return g
        result = oauth2_manager.refresh_access_token(config_id, refresh_token)
        return _ok(result)
    except Exception as e:
        logger.exception("oauth2_refresh error")
        return _fail(str(e))


# =========================================================================== #
# LDAP 端点（6）
# =========================================================================== #
@router.get("/ldap/config")
def ldap_list_config():
    """列出全部 LDAP 配置。"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(ldap_manager.list_configs())
    except Exception as e:
        logger.exception("ldap_list_config error")
        return _fail(str(e))


@router.post("/ldap/config")
def ldap_create_config(req: LdapConfigReq):
    """创建 LDAP 配置。"""
    try:
        g = _guard()
        if g:
            return g
        cfg = ldap_manager.create_config(
            name=req.name, host=req.host, port=req.port, base_dn=req.base_dn,
            bind_dn=req.bind_dn, bind_password=req.bind_password,
            use_ssl=req.use_ssl, use_tls=req.use_tls, timeout=req.timeout,
            user_search_base=req.user_search_base, user_filter=req.user_filter,
            attribute_mapping=req.attribute_mapping)
        return _ok(cfg)
    except Exception as e:
        logger.exception("ldap_create_config error")
        return _fail(str(e))


@router.put("/ldap/config/{config_id}")
def ldap_update_config(config_id: str, req: LdapConfigUpdate):
    """更新 LDAP 配置。"""
    try:
        g = _guard()
        if g:
            return g
        kwargs = {k: v for k, v in req.model_dump().items() if v is not None}
        cfg = ldap_manager.update_config(config_id, **kwargs)
        if not cfg:
            return _fail("配置不存在", 404)
        return _ok(cfg)
    except Exception as e:
        logger.exception("ldap_update_config error")
        return _fail(str(e))


@router.post("/ldap/{config_id}/test")
def ldap_test(config_id: str):
    """测试 LDAP 连接。"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(ldap_manager.test_connection(config_id))
    except Exception as e:
        logger.exception("ldap_test error")
        return _fail(str(e))


@router.post("/ldap/{config_id}/sync")
def ldap_sync(config_id: str, sync_type: str = Body("full", embed=True)):
    """同步 LDAP 用户 / 组。"""
    try:
        g = _guard()
        if g:
            return g
        users = ldap_manager.sync_users(config_id, sync_type=sync_type or "full")
        groups = ldap_manager.sync_groups(config_id)
        return _ok({"users": users, "groups": groups})
    except Exception as e:
        logger.exception("ldap_sync error")
        return _fail(str(e))


@router.get("/ldap/{config_id}/users")
def ldap_users(config_id: str, search_filter: Optional[str] = Query(None),
               limit: int = Query(100)):
    """查询 LDAP 用户列表。"""
    try:
        g = _guard()
        if g:
            return g
        users = ldap_manager.get_users(config_id, search_filter=search_filter, limit=limit)
        groups = ldap_manager.get_groups(config_id)
        ous = ldap_manager.get_ous(config_id)
        return _ok({"users": users, "groups": groups, "ous": ous, "total": len(users)})
    except Exception as e:
        logger.exception("ldap_users error")
        return _fail(str(e))


# =========================================================================== #
# SSO 统一端点（5）
# =========================================================================== #
@router.get("/providers")
def list_providers(provider_type: Optional[str] = Query(None)):
    """列出 SSO 提供商（可按类型过滤）。"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(sso_manager.list_providers(provider_type))
    except Exception as e:
        logger.exception("list_providers error")
        return _fail(str(e))


@router.get("/login")
def sso_login(provider_id: Optional[str] = Query(None),
              redirect_url: Optional[str] = Query(None)):
    """统一 SSO 登录入口，返回登录 URL。"""
    try:
        g = _guard()
        if g:
            return g
        result = sso_manager.initiate_login(provider_id=provider_id, redirect_url=redirect_url)
        return _ok(result)
    except Exception as e:
        logger.exception("sso_login error")
        return _fail(str(e))


@router.get("/session")
def sso_session(session_id: str = Query(...)):
    """查询 SSO 会话。"""
    try:
        g = _guard()
        if g:
            return g
        sess = sso_manager.get_sso_session(session_id)
        if not sess:
            return _fail("会话不存在或已过期", 404)
        return _ok(dict(sess))
    except Exception as e:
        logger.exception("sso_session error")
        return _fail(str(e))


@router.post("/logout")
def sso_logout(session_id: str = Body("", embed=True)):
    """销毁 SSO 会话（登出）。"""
    try:
        g = _guard()
        if g:
            return g
        ok = sso_manager.destroy_sso_session(session_id)
        return _ok({"logged_out": ok, "session_id": session_id})
    except Exception as e:
        logger.exception("sso_logout error")
        return _fail(str(e))


@router.get("/stats")
def sso_stats(time_range: str = Query("30d")):
    """获取 SSO 统计。"""
    try:
        g = _guard()
        if g:
            return g
        return _ok(sso_manager.get_stats(time_range))
    except Exception as e:
        logger.exception("sso_stats error")
        return _fail(str(e))


__all__ = ["router"]
