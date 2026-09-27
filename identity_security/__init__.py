#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
identity_security — 身份安全与 IAM 深化模块（第 17 轮升级方向 3）。

提供身份治理 / 权限审计 / 威胁检测 / 特权管理 / 访问认证 / 运营仪表盘：
    - identity_governance         身份治理与目录（AD/LDAP/Okta/Azure AD 同步、身份图谱、生命周期、数据质量）
    - permission_audit             权限审计与治理（盘点/风险/复核/最小权限/变更监控）
    - identity_threat_detection    异常登录与身份威胁检测（基线/暴力破解/攻击链/MFA）
    - privileged_access           特权账户管理 PAM（盘点/风险/会话/审批/服务账户）
    - access_authentication       访问认证与 SSO（策略/SSO/RBAC-ABAC-PBAC/申请/日志）
    - identity_dashboard          身份安全运营仪表盘（态势/告警/热力图/合规/度量）

设计定位：
    - 仅做身份治理与检测视角的分析、盘点、报告，不提供攻击代码。
    - 第三方库（ldap3、okta 等）一律 try-import，缺失时回退模拟数据。
    - Python 3.14 兼容，from __future__ import annotations。
"""

from __future__ import annotations

__version__ = "17.3.0"
__round__ = 17
__direction__ = 3

try:
    from identity_security.identity_governance import (
        IdentityGovernance, DIRECTORY_TYPES, LIFECYCLE_STAGES, ACCOUNT_STATES,
    )
except Exception:  # pragma: no cover
    IdentityGovernance = None  # type: ignore
    DIRECTORY_TYPES = {}
    LIFECYCLE_STAGES = []
    ACCOUNT_STATES = []

try:
    from identity_security.permission_audit import (
        PermissionAuditor, ROLE_LIBRARY, PERMISSION_SEVERITY,
    )
except Exception:  # pragma: no cover
    PermissionAuditor = None  # type: ignore
    ROLE_LIBRARY = {}
    PERMISSION_SEVERITY = {}

try:
    from identity_security.identity_threat_detection import (
        IdentityThreatDetector, ATTACK_TTP,
    )
except Exception:  # pragma: no cover
    IdentityThreatDetector = None  # type: ignore
    ATTACK_TTP = {}

try:
    from identity_security.privileged_access import (
        PrivilegedAccessManager, PRIV_TYPES,
    )
except Exception:  # pragma: no cover
    PrivilegedAccessManager = None  # type: ignore
    PRIV_TYPES = []

try:
    from identity_security.access_authentication import (
        AccessAuthentication, POLICY_TEMPLATES,
    )
except Exception:  # pragma: no cover
    AccessAuthentication = None  # type: ignore
    POLICY_TEMPLATES = {}

try:
    from identity_security.identity_dashboard import IdentityDashboard
except Exception:  # pragma: no cover
    IdentityDashboard = None  # type: ignore

__all__ = [
    "__version__", "__round__", "__direction__",
    "IdentityGovernance", "DIRECTORY_TYPES", "LIFECYCLE_STAGES", "ACCOUNT_STATES",
    "PermissionAuditor", "ROLE_LIBRARY", "PERMISSION_SEVERITY",
    "IdentityThreatDetector", "ATTACK_TTP",
    "PrivilegedAccessManager", "PRIV_TYPES",
    "AccessAuthentication", "POLICY_TEMPLATES",
    "IdentityDashboard",
]
