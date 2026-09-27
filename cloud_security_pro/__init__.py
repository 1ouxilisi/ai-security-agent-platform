# -*- coding: utf-8 -*-
"""
cloud_security_pro — 方向3：云安全做深（5.5 → 9.0）。

五阶段:
    1. asset_discovery  资产发现（AWS boto3 / 阿里云 SDK 真实调用）
    2. config_check     配置检查（18 条规则）
    3. risk_rating      风险评级（0-100 / 四级）
    4. vuln_detect      漏洞检测（CVE 匹配）
    5. compliance_audit 合规审计（等保2.0 / ISO27001 / CIS）

另含:
    - AI 分析（整改建议 / 攻击路径 / 成本优化）
    - 实时推送（WebSocket）
    - 报告生成（MD / HTML）
    - 仪表盘聚合
"""

from __future__ import annotations

from .asset_discovery_phase import (
    AssetDiscoveryPhase, InventoryResult, ResourceItem,
    get_asset_discovery_phase, detect_credential_status,
)
from .config_check_phase import (
    ConfigCheckPhase, ConfigFinding, ConfigCheckResult,
    get_config_check_phase,
)
from .risk_rating_phase import (
    RiskRatingPhase, RiskRatingResult, get_risk_rating_phase,
)
from .vuln_detect_phase import (
    CloudVulnDetectPhase, CloudVuln, CLOUD_VULN_DB,
    get_vuln_detect_phase,
)
from .compliance_audit_phase import (
    ComplianceAuditPhase, ComplianceResult, ComplianceItem,
    get_compliance_audit_phase,
)
from .ai_analysis import CloudAIAnalysis, CloudAttackPath, get_ai_analysis
from .realtime_push import (
    RealtimePushManager, get_push_manager, LOG_LEVEL_COLORS,
)
from .report_generator import (
    CloudReportGenerator, CloudReportData, get_report_generator, REPORTS_DIR,
)
from .cloud_orchestrator import (
    CloudSecurityOrchestrator, CloudTask, get_orchestrator, STAGES,
)
from .cloud_dashboard import CloudSecurityDashboard, get_dashboard

__all__ = [
    "AssetDiscoveryPhase", "InventoryResult", "ResourceItem",
    "get_asset_discovery_phase", "detect_credential_status",
    "ConfigCheckPhase", "ConfigFinding", "ConfigCheckResult",
    "get_config_check_phase",
    "RiskRatingPhase", "RiskRatingResult", "get_risk_rating_phase",
    "CloudVulnDetectPhase", "CloudVuln", "CLOUD_VULN_DB",
    "get_vuln_detect_phase",
    "ComplianceAuditPhase", "ComplianceResult", "ComplianceItem",
    "get_compliance_audit_phase",
    "CloudAIAnalysis", "CloudAttackPath", "get_ai_analysis",
    "RealtimePushManager", "get_push_manager", "LOG_LEVEL_COLORS",
    "CloudReportGenerator", "CloudReportData", "get_report_generator",
    "REPORTS_DIR",
    "CloudSecurityOrchestrator", "CloudTask", "get_orchestrator", "STAGES",
    "CloudSecurityDashboard", "get_dashboard",
]
