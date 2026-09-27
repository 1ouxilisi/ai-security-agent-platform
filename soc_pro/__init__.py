# -*- coding: utf-8 -*-
"""
soc_pro 包 — 方向1：SOC 安全运营做深（5.5→9.0）。

七阶段流程:
    1. log_collection    日志收集（syslog/filebeat/logstash 框架 + 多源接入）
    2. log_parsing       日志解析（标准化/字段提取/富化）
    3. correlation       关联分析（50+ 条 SIEM 检测规则）
    4. alert_generation  告警生成（分级/去重/聚合/生命周期）
    5. incident_response 事件响应（SOAR 剧本/工单/证据）
    6. threat_hunting    威胁狩猎（IOC/ATT&CK/异常检测）
    7. postmortem        事件复盘（时间线/根因/改进/知识库）

另含:
    - AIAnalysis         AI 分析（降噪/攻击路径/响应建议）
    - RealtimePush       WebSocket 实时推送
    - SOCDashboard       SOC 大屏仪表盘
    - ReportGenerator    报告生成（MD/HTML）
    - SOCOrchestrator    七阶段编排器
"""

from __future__ import annotations

from .log_collection_phase import (
    LogCollectionPhase, LogSource, CollectedLog, get_log_collection_phase,
)
from .log_parsing_phase import (
    LogParsingPhase, ParsedLog, ParseRule, get_log_parsing_phase,
)
from .correlation_phase import (
    CorrelationPhase, DetectionRule, CorrelationHit, get_correlation_phase,
    DETECTION_RULES,
)
from .alert_generation_phase import (
    AlertGenerationPhase, Alert, get_alert_generation_phase,
)
from .incident_response_phase import (
    IncidentResponsePhase, SOARPlaybook, Ticket, get_incident_response_phase,
)
from .threat_hunting_phase import (
    ThreatHuntingPhase, HuntingQuery, HuntingFind, get_threat_hunting_phase,
)
from .postmortem_phase import (
    PostmortemPhase, PostmortemReport, get_postmortem_phase,
)
from .ai_analysis import AIAnalysis, get_ai_analysis
from .realtime_push import RealtimePush, get_realtime_push, LOG_LEVEL_COLORS
from .soc_dashboard import SOCDashboard, get_dashboard
from .report_generator import ReportGenerator, get_report_generator
from .soc_orchestrator import (
    SOCOrchestrator, SOCTask, get_orchestrator, REPORTS_DIR, STAGES,
)

__all__ = [
    "LogCollectionPhase", "LogSource", "CollectedLog", "get_log_collection_phase",
    "LogParsingPhase", "ParsedLog", "ParseRule", "get_log_parsing_phase",
    "CorrelationPhase", "DetectionRule", "CorrelationHit",
    "get_correlation_phase", "DETECTION_RULES",
    "AlertGenerationPhase", "Alert", "get_alert_generation_phase",
    "IncidentResponsePhase", "SOARPlaybook", "Ticket",
    "get_incident_response_phase",
    "ThreatHuntingPhase", "HuntingQuery", "HuntingFind",
    "get_threat_hunting_phase",
    "PostmortemPhase", "PostmortemReport", "get_postmortem_phase",
    "AIAnalysis", "get_ai_analysis",
    "RealtimePush", "get_realtime_push", "LOG_LEVEL_COLORS",
    "SOCDashboard", "get_dashboard",
    "ReportGenerator", "get_report_generator",
    "SOCOrchestrator", "SOCTask", "get_orchestrator",
    "REPORTS_DIR", "STAGES",
]
