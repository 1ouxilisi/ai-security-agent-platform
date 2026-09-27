# -*- coding: utf-8 -*-
"""
forensics_pro 包 — 方向2：取证分析做深（5.5→9.0）。

八阶段流程:
    1. evidence_acquisition    证据获取（磁盘/内存/网络/系统/日志）
    2. evidence_preservation    证据保全（哈希/证据链/写保护/NTP）
    3. disk_forensics           磁盘取证（MFT/注册表/浏览器/邮件）
    4. memory_forensics         内存取证（Volatility3 插件）
    5. network_forensics        网络取证（tshark/异常/IOC）
    6. log_forensics            日志取证（多源关联/攻击路径）
    7. malware_analysis          恶意软件分析（静态+动态）
    8. forensics_report         取证报告（MD/HTML/PDF）

另含:
    - ForensicsAIAnalysis    AI 分析
    - RealtimePush           WebSocket 实时推送
    - ForensicsDashboard     取证大屏仪表盘
    - ReportGenerator        报告生成
    - ForensicsOrchestrator 八阶段编排器
"""

from __future__ import annotations

from .evidence_acquisition_phase import (
    EvidenceAcquisitionPhase, Evidence, AcquisitionTask,
    get_evidence_acquisition_phase,
)
from .evidence_preservation_phase import (
    EvidencePreservationPhase, ChainOfCustody,
    get_evidence_preservation_phase,
)
from .disk_forensics_phase import (
    DiskForensicsPhase, FileEntry, RegRecord,
    get_disk_forensics_phase,
)
from .memory_forensics_phase import (
    MemoryForensicsPhase, get_memory_forensics_phase, VOL_PLUGINS,
)
from .network_forensics_phase import (
    NetworkForensicsPhase, get_network_forensics_phase,
)
from .log_forensics_phase import (
    LogForensicsPhase, get_log_forensics_phase,
)
from .malware_analysis_phase import (
    MalwareAnalysisPhase, get_malware_analysis_phase,
)
from .forensics_report_phase import (
    ForensicsReportPhase, get_forensics_report_phase,
)
from .ai_analysis import ForensicsAIAnalysis, get_ai_analysis
from .realtime_push import (
    RealtimePush, get_realtime_push, LOG_LEVEL_COLORS,
)
from .forensics_dashboard import ForensicsDashboard, get_dashboard
from .report_generator import ReportGenerator, get_report_generator
from .forensics_orchestrator import (
    ForensicsOrchestrator, ForensicsTask, get_orchestrator,
    REPORTS_DIR, STAGES,
)

__all__ = [
    "EvidenceAcquisitionPhase", "Evidence", "AcquisitionTask",
    "get_evidence_acquisition_phase",
    "EvidencePreservationPhase", "ChainOfCustody",
    "get_evidence_preservation_phase",
    "DiskForensicsPhase", "FileEntry", "RegRecord",
    "get_disk_forensics_phase",
    "MemoryForensicsPhase", "get_memory_forensics_phase", "VOL_PLUGINS",
    "NetworkForensicsPhase", "get_network_forensics_phase",
    "LogForensicsPhase", "get_log_forensics_phase",
    "MalwareAnalysisPhase", "get_malware_analysis_phase",
    "ForensicsReportPhase", "get_forensics_report_phase",
    "ForensicsAIAnalysis", "get_ai_analysis",
    "RealtimePush", "get_realtime_push", "LOG_LEVEL_COLORS",
    "ForensicsDashboard", "get_dashboard",
    "ReportGenerator", "get_report_generator",
    "ForensicsOrchestrator", "ForensicsTask", "get_orchestrator",
    "REPORTS_DIR", "STAGES",
]
