# -*- coding: utf-8 -*-
"""
data_security_pro — 方向3：数据安全做深（5.5 -> 9.0）。

八阶段:
    1. discovery       数据发现
    2. classification  数据分类分级
    3. asset           数据资产盘点
    4. dlp             DLP 防泄漏（50+ 策略）
    5. privacy         隐私合规（GDPR / PIPL）
    6. encryption      加密与密钥
    7. access          数据访问审计
    8. risk            风险评级

另含:
    - DataSecurityAIAnalysis    AI 分析
    - realtime_push             WebSocket 实时推送
    - DataSecurityDashboard     数据安全大屏
    - DataSecurityReportGenerator  报告生成
"""

from __future__ import annotations

from .data_discovery_phase import (
    DataDiscoveryPhase, DataSource, get_data_discovery_phase,
    scan_text_for_sensitive, guess_type_by_field,
)
from .data_classification_phase import (
    DataClassificationPhase, ClassificationRule,
    get_data_classification_phase, LEVEL_ORDER, LEVEL_LABELS,
)
from .data_asset_phase import (
    DataAssetPhase, DataAsset, get_data_asset_phase,
)
from .dlp_phase import (
    DLPPhase, DLPPolicy, DLPAlert, get_dlp_phase,
    DLP_ACTIONS, DLP_LEVELS,
)
from .privacy_compliance_phase import (
    PrivacyCompliancePhase, ComplianceItem,
    get_privacy_compliance_phase,
)
from .encryption_key_phase import (
    EncryptionKeyPhase, EncryptionFinding, KeyRecord,
    get_encryption_key_phase, ALGO_STRENGTH, WEAK_ALGOS,
)
from .access_audit_phase import (
    AccessAuditPhase, AccessLog, AccessAnomaly,
    get_access_audit_phase,
)
from .risk_rating_phase import (
    RiskRatingPhase, RiskItem, get_risk_rating_phase,
    LEVELS, LEVEL_COLOR, MATURITY_LEVELS,
)
from .ai_analysis import DataSecurityAIAnalysis, get_ai_analysis
from .realtime_push import (
    manager, push_event, push_event_sync, snapshot,
    ws_chain, LEVEL_COLORS,
)
from .data_security_dashboard import (
    DataSecurityDashboard, get_dashboard,
)
from .report_generator import (
    DataSecurityReportGenerator, get_report_generator, REPORTS_DIR,
)
from .data_security_orchestrator import (
    DataSecurityOrchestrator, DSTask, get_orchestrator, STAGES,
)

__all__ = [
    "DataDiscoveryPhase", "DataSource", "get_data_discovery_phase",
    "scan_text_for_sensitive", "guess_type_by_field",
    "DataClassificationPhase", "ClassificationRule",
    "get_data_classification_phase", "LEVEL_ORDER", "LEVEL_LABELS",
    "DataAssetPhase", "DataAsset", "get_data_asset_phase",
    "DLPPhase", "DLPPolicy", "DLPAlert", "get_dlp_phase",
    "DLP_ACTIONS", "DLP_LEVELS",
    "PrivacyCompliancePhase", "ComplianceItem",
    "get_privacy_compliance_phase",
    "EncryptionKeyPhase", "EncryptionFinding", "KeyRecord",
    "get_encryption_key_phase", "ALGO_STRENGTH", "WEAK_ALGOS",
    "AccessAuditPhase", "AccessLog", "AccessAnomaly",
    "get_access_audit_phase",
    "RiskRatingPhase", "RiskItem", "get_risk_rating_phase",
    "LEVELS", "LEVEL_COLOR", "MATURITY_LEVELS",
    "DataSecurityAIAnalysis", "get_ai_analysis",
    "manager", "push_event", "push_event_sync", "snapshot",
    "ws_chain", "LEVEL_COLORS",
    "DataSecurityDashboard", "get_dashboard",
    "DataSecurityReportGenerator", "get_report_generator", "REPORTS_DIR",
    "DataSecurityOrchestrator", "DSTask", "get_orchestrator", "STAGES",
]
