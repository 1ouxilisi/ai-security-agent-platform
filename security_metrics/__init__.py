#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_metrics — 安全度量与KPI体系（第 15 轮升级，面向 CISO / 管理层）。

提供专业级安全度量视角的一体化能力：
    - maturity_model           CMMI 式 5 级安全成熟度模型（治理/技术/运营/人员/合规 5 维度）
    - kpi_library               200+ 安全 KPI 指标库（风险/运营/技术/合规/财务 5 大类）
    - risk_scoring              风险度量与综合评分、趋势、热力图、归因与处置跟踪
    - operational_efficiency    运营效率度量（MTTD/MTTR/MTRS、误报率、自动化率、SLA）
    - compliance_audit          合规与审计度量（覆盖率/通过率/整改率/框架对比）
    - executive_dashboard       高管报告与 CISO 仪表盘、安全 ROI、一页纸
    - metrics_workflow          安全度量综合工作流（采集→计算→评估→报告→改进）

设计定位：
    - 全部为度量/评估/管理视角，面向 CISO 与管理层，不提供攻击/入侵工具。
    - 全部数据为内存字典模拟，不落库、不连接外部系统。
    - 第三方库（matplotlib/plotly 等）一律 try-import，不可用时回退内嵌模拟数据。
    - Python 3.14 兼容。
"""

from __future__ import annotations

__version__ = "15.0.0"
__round__ = 15

try:
    from security_metrics.maturity_model import (
        SecurityMaturityModel, MATURITY_LEVELS, MATURITY_DIMENSIONS,
    )
except Exception:  # pragma: no cover
    SecurityMaturityModel = None  # type: ignore
    MATURITY_LEVELS = {}
    MATURITY_DIMENSIONS = {}

try:
    from security_metrics.kpi_library import KPILibrary, KPI_CATEGORIES, KPI_LIBRARY_SIZE
except Exception:  # pragma: no cover
    KPILibrary = None  # type: ignore
    KPI_CATEGORIES = {}
    KPI_LIBRARY_SIZE = 0

try:
    from security_metrics.risk_scoring import RiskScoringEngine, RISK_LEVELS
except Exception:  # pragma: no cover
    RiskScoringEngine = None  # type: ignore
    RISK_LEVELS = {}

try:
    from security_metrics.operational_efficiency import OperationalEfficiencyMetrics
except Exception:  # pragma: no cover
    OperationalEfficiencyMetrics = None  # type: ignore

try:
    from security_metrics.compliance_audit import ComplianceAuditMetrics, COMPLIANCE_FRAMEWORKS
except Exception:  # pragma: no cover
    ComplianceAuditMetrics = None  # type: ignore
    COMPLIANCE_FRAMEWORKS = {}

try:
    from security_metrics.executive_dashboard import ExecutiveDashboard
except Exception:  # pragma: no cover
    ExecutiveDashboard = None  # type: ignore

try:
    from security_metrics.metrics_workflow import MetricsWorkflow, get_metrics_workflow, METRICS_WORKFLOW_STEPS
except Exception:  # pragma: no cover
    MetricsWorkflow = None  # type: ignore
    get_metrics_workflow = None  # type: ignore
    METRICS_WORKFLOW_STEPS = []

__all__ = [
    "__version__",
    "__round__",
    "SecurityMaturityModel",
    "MATURITY_LEVELS",
    "MATURITY_DIMENSIONS",
    "KPILibrary",
    "KPI_CATEGORIES",
    "KPI_LIBRARY_SIZE",
    "RiskScoringEngine",
    "RISK_LEVELS",
    "OperationalEfficiencyMetrics",
    "ComplianceAuditMetrics",
    "COMPLIANCE_FRAMEWORKS",
    "ExecutiveDashboard",
    "MetricsWorkflow",
    "get_metrics_workflow",
    "METRICS_WORKFLOW_STEPS",
]
