# -*- coding: utf-8 -*-
"""
supply_chain_pro — 方向2：供应链安全做深（5.5 → 9.0）。

六阶段:
    1. sbom              SBOM 生成（syft/cyclonedx + 内置解析器兜底）
    2. analysis          组件漏洞分析（OSV/Snyk + 内置 CVE 库）
    3. license           许可证合规（GPL/MIT/Apache/BSD/MPL/LGPL）
    4. dependency        依赖分析（直接/传递/冲突/过期/深度）
    5. risk              风险评级（0-100，critical/high/medium/low）
    6. remediation       整改建议（升级/替代/路线图）
    + AI 分析 / WebSocket 实时推送 / MD+HTML 报告
"""

from __future__ import annotations

from .sbom_phase import SBOMPhase, SBOMResult, Component, get_sbom_phase
from .component_analysis_phase import (
    ComponentAnalysisPhase, AnalysisResult, ComponentVuln,
    get_component_analysis_phase,
)
from .license_compliance_phase import (
    LicenseCompliancePhase, LicenseReport, LicenseIssue,
    LICENSE_DB, COMPAT_MATRIX, get_license_phase,
)
from .dependency_analysis_phase import (
    DependencyAnalysisPhase, DependencyReport, DepNode,
    get_dependency_phase,
)
from .risk_rating_phase import (
    RiskRatingPhase, RiskReport, ComponentRisk, get_risk_phase,
)
from .remediation_phase import (
    RemediationPhase, RemediationPlan, RemediationItem, RoadmapItem,
    get_remediation_phase,
)
from .ai_analysis import (
    SupplyChainAIAnalysis, AIAnalysis, AttackPath, get_ai_analysis,
)
from .report_generator import (
    ReportGenerator, ReportData, get_report_generator,
)
from .realtime_push import (
    manager, push_event, push_event_sync, snapshot, ws_chain,
    LEVEL_COLORS,
)
from .supply_chain_orchestrator import (
    SupplyChainOrchestrator, SCTask, get_orchestrator,
    REPORTS_DIR, STAGES,
)
from .supply_chain_dashboard import (
    SupplyChainDashboard, get_dashboard,
)

__all__ = [
    "SBOMPhase", "SBOMResult", "Component", "get_sbom_phase",
    "ComponentAnalysisPhase", "AnalysisResult", "ComponentVuln",
    "get_component_analysis_phase",
    "LicenseCompliancePhase", "LicenseReport", "LicenseIssue",
    "LICENSE_DB", "COMPAT_MATRIX", "get_license_phase",
    "DependencyAnalysisPhase", "DependencyReport", "DepNode",
    "get_dependency_phase",
    "RiskRatingPhase", "RiskReport", "ComponentRisk",
    "get_risk_phase",
    "RemediationPhase", "RemediationPlan", "RemediationItem",
    "RoadmapItem", "get_remediation_phase",
    "SupplyChainAIAnalysis", "AIAnalysis", "AttackPath",
    "get_ai_analysis",
    "ReportGenerator", "ReportData", "get_report_generator",
    "manager", "push_event", "push_event_sync", "snapshot",
    "ws_chain", "LEVEL_COLORS",
    "SupplyChainOrchestrator", "SCTask", "get_orchestrator",
    "REPORTS_DIR", "STAGES",
    "SupplyChainDashboard", "get_dashboard",
]
