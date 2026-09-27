# -*- coding: utf-8 -*-
"""enterprise_security — 方向5：企业级安全与合规。

子模块:
  rbac               — RBAC 权限体系（管理员/分析师/审计员/只读用户）
  audit_log          — 操作审计日志（谁在何时做了什么）
  data_encryption    — AES-256 敏感数据加解密
  security_baseline  — 系统自身安全基线检查
  compliance_report  — 等保2.0 / ISO27001 合规报告
  enterprise_dashboard — 企业安全控制台聚合视图
"""
from __future__ import annotations

from .rbac import RBACManager, ROLES, PERMISSIONS, ROLE_PERMISSIONS
from .audit_log import AuditLogger
from .data_encryption import DataEncryption
from .security_baseline import SecurityBaseline
from .compliance_report import ComplianceReportGenerator
from .enterprise_dashboard import EnterpriseDashboard

__all__ = [
    "RBACManager",
    "ROLES",
    "PERMISSIONS",
    "ROLE_PERMISSIONS",
    "AuditLogger",
    "DataEncryption",
    "SecurityBaseline",
    "ComplianceReportGenerator",
    "EnterpriseDashboard",
]
