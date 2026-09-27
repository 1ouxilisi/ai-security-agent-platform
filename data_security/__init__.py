#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data_security — 数据安全与隐私保护模块（第 13 轮升级）。

提供数据安全防御/评估/检测视角的一体化能力：
    - data_classification         数据分类分级器（PII/PCI/PHI/财务/商密识别与分级）
    - dlp_engine                  数据泄露防护(DLP)引擎
    - privacy_compliance          隐私合规评估器（GDPR/个保法/CCPA/DSAR/DPIA）
    - encryption_key_management   加密与密钥管理器
    - access_control              数据访问控制器
    - data_security_workflow      数据安全综合评估工作流

设计定位：
    - 仅做检测、评估、防御视角的数据安全分析，不提供攻击/窃密工具。
    - 所有功能仅用于经过授权的数据安全治理，输出检测报告与加固建议。
    - 第三方库一律 try-import，不可用时自动回退到内嵌模拟/离线数据。
    - Python 3.14 兼容。
"""

from __future__ import annotations

__version__ = "13.0.0"
__round__ = 13

# 核心类与工厂函数（try-import，避免单个模块缺失导致整个包不可用）
try:
    from data_security.data_classification import (
        DataClassifier, SENSITIVE_TYPES_LIBRARY, CLASSIFICATION_LEVELS,
    )
except Exception:  # pragma: no cover
    DataClassifier = None  # type: ignore
    SENSITIVE_TYPES_LIBRARY = {}
    CLASSIFICATION_LEVELS = {}

try:
    from data_security.dlp_engine import DLPEngine, DLP_POLICY_LIBRARY
except Exception:  # pragma: no cover
    DLPEngine = None  # type: ignore
    DLP_POLICY_LIBRARY = {}

try:
    from data_security.privacy_compliance import PrivacyComplianceAssessor, COMPLIANCE_FRAMEWORKS
except Exception:  # pragma: no cover
    PrivacyComplianceAssessor = None  # type: ignore
    COMPLIANCE_FRAMEWORKS = {}

try:
    from data_security.encryption_key_management import EncryptionKeyManager, CRYPTO_ALGORITHM_LIBRARY
except Exception:  # pragma: no cover
    EncryptionKeyManager = None  # type: ignore
    CRYPTO_ALGORITHM_LIBRARY = {}

try:
    from data_security.access_control import DataAccessController, PRIVILEGE_RISK_LIBRARY
except Exception:  # pragma: no cover
    DataAccessController = None  # type: ignore
    PRIVILEGE_RISK_LIBRARY = {}

try:
    from data_security.data_security_workflow import DataSecurityWorkflow, get_security_workflow, SECURITY_WORKFLOW_STEPS
except Exception:  # pragma: no cover
    DataSecurityWorkflow = None  # type: ignore
    get_security_workflow = None  # type: ignore
    SECURITY_WORKFLOW_STEPS = []

__all__ = [
    "__version__",
    "__round__",
    "DataClassifier",
    "SENSITIVE_TYPES_LIBRARY",
    "CLASSIFICATION_LEVELS",
    "DLPEngine",
    "DLP_POLICY_LIBRARY",
    "PrivacyComplianceAssessor",
    "COMPLIANCE_FRAMEWORKS",
    "EncryptionKeyManager",
    "CRYPTO_ALGORITHM_LIBRARY",
    "DataAccessController",
    "PRIVILEGE_RISK_LIBRARY",
    "DataSecurityWorkflow",
    "get_security_workflow",
    "SECURITY_WORKFLOW_STEPS",
]
