# -*- coding: utf-8 -*-
"""
enterprise_saas — 企业级多租户与计费 SaaS 平台核心包。

模块清单：
- multi_tenant.py      多租户架构（租户/组织/用户/RBAC/数据隔离/生命周期）
- billing_system.py    订阅与计费（计划/订阅/计费/用量/发票/支付）
- customer_portal.py   客户自助门户（个人/账户/团队/项目/资源/帮助）
- sso_identity.py      企业SSO与身份管理（SAML/OIDC/LDAP/MFA/审计）
- audit_compliance.py  审计与合规（日志/完整性/合规框架/数据治理/隐私）
- enterprise_dashboard.py 企业管理控制台（总览/租户/用户/计费/运营/设置）
"""

from __future__ import annotations

__version__ = "23.4.0"
__all__ = [
    "multi_tenant",
    "billing_system",
    "customer_portal",
    "sso_identity",
    "audit_compliance",
    "enterprise_dashboard",
]
