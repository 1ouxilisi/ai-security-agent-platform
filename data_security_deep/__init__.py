#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data_security_deep — 数据安全与隐私保护深度平台（第 24 轮升级方向 3）。

在第 13 轮 data_security 基础上深度扩展：
    - data_classification       数据分类分级深度引擎（资产发现/分类/分级/敏感识别/数据地图/资产目录）
    - dlp_engine                DLP 数据防泄漏深度引擎（传输监控/使用监控/检测/策略/防护动作/事件管理）
    - privacy_compute           隐私计算与数据加密（加密/密钥管理/脱敏/隐私计算/匿名化/数据水印）
    - access_audit              数据访问控制与审计（访问控制/审批/审计/异常检测/防滥用/合规报告）
    - privacy_compliance        隐私合规管理（8大框架/合规评估/数据主体权利/同意管理/隐私政策/培训）
    - data_security_dashboard    数据安全控制台（总览/资产/防护/合规/监控/系统设置）

设计定位：
    - 仅做数据安全治理、检测、防护视角的分析与模拟，不提供任何攻击/窃密工具。
    - 所有功能仅用于经过授权的数据安全治理场景，输出报告与加固建议。
    - 第三方库一律 try-import，不可用时自动回退到内嵌模拟/离线数据。
    - 全部内存字典模拟，不建数据库表。
"""

from __future__ import annotations

__version__ = "24.3.0"
__round__ = 24
__direction__ = 3

# 核心类与工厂函数（try-import，避免单个模块缺失导致整个包不可用）
try:
    from data_security_deep.data_classification import (
        DataClassificationEngine,
        CLASSIFICATION_LEVELS_DEEP,
        SENSITIVE_PATTERNS,
        BUSINESS_DOMAINS,
    )
except Exception:  # pragma: no cover
    DataClassificationEngine = None  # type: ignore
    CLASSIFICATION_LEVELS_DEEP = {}
    SENSITIVE_PATTERNS = {}
    BUSINESS_DOMAINS = {}

try:
    from data_security_deep.dlp_engine import (
        DLPEngineDeep,
        DLP_PROFILES,
        PROTECTION_ACTIONS,
    )
except Exception:  # pragma: no cover
    DLPEngineDeep = None  # type: ignore
    DLP_PROFILES = {}
    PROTECTION_ACTIONS = {}

try:
    from data_security_deep.privacy_compute import (
        PrivacyComputeEngine,
        ENCRYPTION_ALGORITHMS,
        PRIVACY_COMPUTE_TECHS,
        ANONYMIZATION_METHODS,
    )
except Exception:  # pragma: no cover
    PrivacyComputeEngine = None  # type: ignore
    ENCRYPTION_ALGORITHMS = {}
    PRIVACY_COMPUTE_TECHS = {}
    ANONYMIZATION_METHODS = {}

try:
    from data_security_deep.access_audit import (
        AccessAuditEngine,
        ACCESS_CONTROL_MODES,
        ANOMALY_RULES,
    )
except Exception:  # pragma: no cover
    AccessAuditEngine = None  # type: ignore
    ACCESS_CONTROL_MODES = {}
    ANOMALY_RULES = {}

try:
    from data_security_deep.privacy_compliance import (
        PrivacyComplianceManager,
        COMPLIANCE_FRAMEWORKS_DEEP,
        DATA_SUBJECT_RIGHTS,
        CONSENT_CHANNELS,
    )
except Exception:  # pragma: no cover
    PrivacyComplianceManager = None  # type: ignore
    COMPLIANCE_FRAMEWORKS_DEEP = {}
    DATA_SUBJECT_RIGHTS = {}
    CONSENT_CHANNELS = {}

try:
    from data_security_deep.data_security_dashboard import (
        DataSecurityDashboard,
        DASHBOARD_METRICS,
    )
except Exception:  # pragma: no cover
    DataSecurityDashboard = None  # type: ignore
    DASHBOARD_METRICS = {}

__all__ = [
    "__version__", "__round__", "__direction__",
    "DataClassificationEngine", "CLASSIFICATION_LEVELS_DEEP",
    "SENSITIVE_PATTERNS", "BUSINESS_DOMAINS",
    "DLPEngineDeep", "DLP_PROFILES", "PROTECTION_ACTIONS",
    "PrivacyComputeEngine", "ENCRYPTION_ALGORITHMS",
    "PRIVACY_COMPUTE_TECHS", "ANONYMIZATION_METHODS",
    "AccessAuditEngine", "ACCESS_CONTROL_MODES", "ANOMALY_RULES",
    "PrivacyComplianceManager", "COMPLIANCE_FRAMEWORKS_DEEP",
    "DATA_SUBJECT_RIGHTS", "CONSENT_CHANNELS",
    "DataSecurityDashboard", "DASHBOARD_METRICS",
]
