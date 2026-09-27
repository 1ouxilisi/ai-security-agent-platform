# -*- coding: utf-8 -*-
"""
threat_intel_pro — 方向2：威胁情报做深（5.5 → 9.0）。

八阶段:
    1. collection   IOC 收集（OTX/AbuseIPDB/VT/ThreatFox/URLhaus/MalwareBazaar）
    2. management   IOC 管理（分类/去重/富化/标签/生命周期）
    3. matching     IOC 匹配（日志/流量/资产/邮件 + 告警）
    4. actors       威胁 Actor 画像（20+ 组织，MITRE ATT&CK）
    5. surface      攻击面管理（子域名/端口/服务/技术栈/评分）
    6. darkweb      暗网监控（凭证/数据/品牌，模拟兜底）
    7. analysis     情报分析（预警/趋势/等级/关联/优先级）
    8. sharing      情报共享（STIX 2.1 / TAXII 2.1）

另含:
    - AI 分析引擎（规则启发式，可替换 LLM）
    - WebSocket 实时推送
    - 威胁情报大屏仪表盘
    - MD/HTML 报告生成
"""

from __future__ import annotations

from .ioc_collection_phase import (
    IOCollectionPhase, CollectedIOC, IntelSource,
    get_collection_phase, BUILTIN_IOC_LIBRARY,
)
from .ioc_management_phase import (
    IOManagementPhase, ManagedIOC, classify_ioc,
    get_management_phase, IOC_TYPES, THREAT_TAGS, LIFECYCLE_STATES,
)
from .ioc_matching_phase import (
    IOMatchingPhase, MatchHit, MatchAlert,
    get_matching_phase,
)
from .threat_actor_phase import (
    ThreatActorPhase, ThreatActor, ACTOR_PROFILES, get_actor_phase,
)
from .attack_surface_phase import (
    AttackSurfacePhase, SurfaceAsset, get_attack_surface_phase,
)
from .darkweb_monitor_phase import (
    DarkwebMonitorPhase, DarkwebHit, get_darkweb_phase,
)
from .intel_analysis_phase import (
    IntelAnalysisPhase, ThreatWarning, get_analysis_phase,
)
from .intel_sharing_phase import (
    IntelSharingPhase, SharingGroup, get_sharing_phase,
)
from .ai_analysis import ThreatIntelAIAnalyzer, get_ai_analyzer
from .realtime_push import manager, LEVEL_COLORS
from .threat_intel_dashboard import (
    ThreatIntelDashboard, get_dashboard,
)
from .report_generator import (
    ThreatIntelReportGenerator, ReportData, get_report_generator,
)
from .threat_intel_orchestrator import (
    ThreatIntelOrchestrator, IntelTask, get_orchestrator,
    REPORTS_DIR, STAGES,
)

__all__ = [
    "IOCollectionPhase", "CollectedIOC", "IntelSource",
    "get_collection_phase", "BUILTIN_IOC_LIBRARY",
    "IOManagementPhase", "ManagedIOC", "classify_ioc",
    "get_management_phase", "IOC_TYPES", "THREAT_TAGS", "LIFECYCLE_STATES",
    "IOMatchingPhase", "MatchHit", "MatchAlert", "get_matching_phase",
    "ThreatActorPhase", "ThreatActor", "ACTOR_PROFILES", "get_actor_phase",
    "AttackSurfacePhase", "SurfaceAsset", "get_attack_surface_phase",
    "DarkwebMonitorPhase", "DarkwebHit", "get_darkweb_phase",
    "IntelAnalysisPhase", "ThreatWarning", "get_analysis_phase",
    "IntelSharingPhase", "SharingGroup", "get_sharing_phase",
    "ThreatIntelAIAnalyzer", "get_ai_analyzer",
    "manager", "LEVEL_COLORS",
    "ThreatIntelDashboard", "get_dashboard",
    "ThreatIntelReportGenerator", "ReportData", "get_report_generator",
    "ThreatIntelOrchestrator", "IntelTask", "get_orchestrator",
    "REPORTS_DIR", "STAGES",
]
