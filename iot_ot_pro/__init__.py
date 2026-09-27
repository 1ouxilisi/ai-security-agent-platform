# -*- coding: utf-8 -*-
"""
iot_ot_pro 包 — 方向3：工控 IoT 安全做深（5.5→9.0）。

八阶段流程:
    1. device_discovery    设备发现（多协议扫描 + 指纹识别）
    2. protocol_analysis   协议分析（工控协议 + IoT 协议）
    3. firmware_analysis    固件分析（binwalk + 硬编码凭据 + 漏洞检测）
    4. vuln_detection      漏洞检测（工控 + IoT）
    5. config_audit        配置审计（工控设备 + IoT 设备）
    6. traffic_monitor      流量监控（工控 + IoT 异常检测）
    7. risk_rating         风险评级（多维度打分 + 成熟度）
    8. compliance_audit    合规审计（IEC 62443 + NIST IoT）

另含:
    - IotOtAIAnalysis   AI 风险分析 / 攻击路径 / 整改建议
    - RealtimePush      WebSocket 实时推送
    - IotOtDashboard    工控 IoT 大屏
    - ReportGenerator   报告生成（MD/HTML）
    - IotOtOrchestrator 八阶段编排器
"""

from __future__ import annotations

from .device_discovery_phase import (
    DeviceDiscoveryPhase, ICSDevice, DiscoveryTask,
    get_device_discovery_phase,
)
from .protocol_analysis_phase import (
    ProtocolAnalysisPhase, ProtocolFinding, get_protocol_analysis_phase,
)
from .firmware_analysis_phase import (
    FirmwareAnalysisPhase, FirmwareFinding, get_firmware_analysis_phase,
)
from .vuln_detection_phase import (
    VulnDetectionPhase, Vulnerability, get_vuln_detection_phase,
)
from .config_audit_phase import (
    ConfigAuditPhase, AuditFinding, get_config_audit_phase,
)
from .traffic_monitor_phase import (
    TrafficMonitorPhase, TrafficAlert, get_traffic_monitor_phase,
)
from .risk_rating_phase import (
    RiskRatingPhase, RiskScore, get_risk_rating_phase,
)
from .compliance_audit_phase import (
    ComplianceAuditPhase, ComplianceItem, get_compliance_audit_phase,
)
from .ai_analysis import IotOtAIAnalysis, get_ai_analysis
from .realtime_push import RealtimePush, get_realtime_push, LOG_LEVEL_COLORS
from .iot_ot_dashboard import IotOtDashboard, get_dashboard
from .report_generator import ReportGenerator, get_report_generator
from .iot_ot_orchestrator import (
    IotOtOrchestrator, IotOtTask, get_orchestrator, REPORTS_DIR, STAGES,
)

__all__ = [
    "DeviceDiscoveryPhase", "ICSDevice", "DiscoveryTask",
    "get_device_discovery_phase",
    "ProtocolAnalysisPhase", "ProtocolFinding",
    "get_protocol_analysis_phase",
    "FirmwareAnalysisPhase", "FirmwareFinding",
    "get_firmware_analysis_phase",
    "VulnDetectionPhase", "Vulnerability", "get_vuln_detection_phase",
    "ConfigAuditPhase", "AuditFinding", "get_config_audit_phase",
    "TrafficMonitorPhase", "TrafficAlert", "get_traffic_monitor_phase",
    "RiskRatingPhase", "RiskScore", "get_risk_rating_phase",
    "ComplianceAuditPhase", "ComplianceItem", "get_compliance_audit_phase",
    "IotOtAIAnalysis", "get_ai_analysis",
    "RealtimePush", "get_realtime_push", "LOG_LEVEL_COLORS",
    "IotOtDashboard", "get_dashboard",
    "ReportGenerator", "get_report_generator",
    "IotOtOrchestrator", "IotOtTask", "get_orchestrator",
    "REPORTS_DIR", "STAGES",
]
