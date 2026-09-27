# -*- coding: utf-8 -*-
"""
src_platform_pro 包 — 方向2：SRC 漏洞平台做深（5.5→9.0）。

八阶段流程:
    1. platform_management 平台管理（平台/白帽/企业/规则/公告/模板）
    2. submission          漏洞提交（表单/附件/分类/标签/频率/重复检测）
    3. review               漏洞审核（流程/定级/误报/重复/争议/SLA）
    4. bounty               赏金管理（计算/发放/税务/排行/统计）
    5. community            白帽社区（主页/等级/荣誉/讨论/私信）
    6. enterprise           企业门户（资产/看板/修复/态势/报告）
    7. knowledge            漏洞知识库（案例/PoC/修复/最佳实践）
    8. analysis              数据分析（趋势/类型/ROI/风险/可视化）

另含:
    - AIAnalysis       AI 分析（自动审核/定级/修复建议/重复/预测）
    - RealtimePush     WebSocket 实时推送
    - SRCDashboard     SRC 大屏仪表盘
    - ReportGenerator  报告生成（MD/HTML）
    - SRCOrchestrator  八阶段编排器
"""

from __future__ import annotations

from .platform_management_phase import (
    PlatformManagementPhase, get_platform_management_phase,
)
from .vulnerability_submission_phase import (
    VulnerabilitySubmissionPhase, get_submission_phase,
    OWASP_TOP10, VULN_STATUSES,
)
from .vulnerability_review_phase import (
    VulnerabilityReviewPhase, get_review_phase, REVIEW_FLOW,
)
from .bounty_management_phase import (
    BountyManagementPhase, get_bounty_phase, BASE_BOUNTY,
)
from .hacker_community_phase import (
    HackerCommunityPhase, get_community_phase, LEVELS,
)
from .enterprise_portal_phase import (
    EnterprisePortalPhase, get_enterprise_phase,
)
from .vulnerability_knowledge_base_phase import (
    VulnerabilityKnowledgeBasePhase, get_knowledge_phase,
)
from .data_analysis_phase import (
    DataAnalysisPhase, get_analysis_phase,
)
from .ai_analysis import AIAnalysis, get_ai_analysis
from .realtime_push import (
    RealtimePush, get_realtime_push, LOG_LEVEL_COLORS,
)
from .src_dashboard import SRCDashboard, get_dashboard
from .report_generator import ReportGenerator, get_report_generator, \
    REPORTS_DIR
from .src_orchestrator import (
    SRCOrchestrator, SRCTask, get_orchestrator, STAGES,
)

__all__ = [
    "PlatformManagementPhase", "get_platform_management_phase",
    "VulnerabilitySubmissionPhase", "get_submission_phase",
    "OWASP_TOP10", "VULN_STATUSES",
    "VulnerabilityReviewPhase", "get_review_phase", "REVIEW_FLOW",
    "BountyManagementPhase", "get_bounty_phase", "BASE_BOUNTY",
    "HackerCommunityPhase", "get_community_phase", "LEVELS",
    "EnterprisePortalPhase", "get_enterprise_phase",
    "VulnerabilityKnowledgeBasePhase", "get_knowledge_phase",
    "DataAnalysisPhase", "get_analysis_phase",
    "AIAnalysis", "get_ai_analysis",
    "RealtimePush", "get_realtime_push", "LOG_LEVEL_COLORS",
    "SRCDashboard", "get_dashboard",
    "ReportGenerator", "get_report_generator", "REPORTS_DIR",
    "SRCOrchestrator", "SRCTask", "get_orchestrator", "STAGES",
]
