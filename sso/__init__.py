# -*- coding: utf-8 -*-
"""
sso — SSO / LDAP 集成模块（第 10 轮升级）。

统一封装企业级身份集成能力：
    - SAML 2.0（SP/IdP、ACS、SLO、断言映射）
    - OAuth 2.0 / OIDC（四种授权模式、JWT 验签、UserInfo）
    - LDAP / Active Directory（绑定认证、用户/组/OU 同步、连接池）
    - SSO 统一管理（提供商、策略、会话、统计）

对外暴露四个核心类及模块级单例：
    SAMLManager / saml_manager
    OAuth2Manager / oauth2_manager
    LDAPManager / ldap_manager
    SSOManager / sso_manager
"""

from __future__ import annotations

from sso.ldap_manager import LDAPManager, ldap_manager
from sso.oauth2_manager import OAuth2Manager, oauth2_manager
from sso.saml_manager import SAMLManager, saml_manager
from sso.sso_manager import SSOManager, sso_manager

__version__ = "1.0.0"

__all__ = [
    "SAMLManager", "saml_manager",
    "OAuth2Manager", "oauth2_manager",
    "LDAPManager", "ldap_manager",
    "SSOManager", "sso_manager",
    "__version__",
]
