# -*- coding: utf-8 -*-
"""
red_blue_pro — 方向1：红蓝对抗做深（5.5 → 9.0）。

红队六阶段:
    1. recon          侦察（subfinder/crt.sh/theHarvester/HIBP）
    2. initial_access 初始访问（钓鱼/Exploit/凭据攻击）
    3. execution      执行（命令/代码/持久化）
    4. privesc        提权（CVE 指纹/配置审计/Win·Linux）
    5. lateral        横向（SMB/WMI/WinRM/PtH/PtT）
    6. objective      目标（数据窃取/维持/清理）

蓝队三阶段:
    1. detection    检测（Suricata/日志分析/异常/IOC）
    2. response     响应（IR 六步/隔离/清除/恢复）
    3. attribution  溯源（时间线/画像/影响）

紫队复盘: 红 vs 蓝对比 / 差距分析 / 改进建议 / 成熟度
另含: AI 分析 / WebSocket 实时推送 / 报告生成 / 编排器 / 仪表盘
"""

from __future__ import annotations

from .red_recon_phase import (
    RedReconPhase, ReconResult, get_red_recon_phase,
)
from .red_initial_access_phase import (
    RedInitialAccessPhase, IAResult, PHISH_TEMPLATES,
    get_red_initial_access_phase,
)
from .red_execution_phase import (
    RedExecutionPhase, ExecResult, SHELL_TEMPLATES,
    get_red_execution_phase,
)
from .red_privesc_phase import (
    RedPrivescPhase, PrivescResult, PrivescFinding,
    get_red_privesc_phase, WIN_PRIVESC_CVES, LINUX_PRIVESC_CVES,
)
from .red_lateral_phase import (
    RedLateralPhase, LateralResult, get_red_lateral_phase,
)
from .red_objective_phase import (
    RedObjectivePhase, ObjectiveResult, get_red_objective_phase,
)
from .blue_detection_phase import (
    BlueDetectionPhase, DetectionResult, SURICATA_RULES,
    get_blue_detection_phase,
)
from .blue_response_phase import (
    BlueResponsePhase, ResponseResult, IR_LIFECYCLE,
    get_blue_response_phase,
)
from .blue_attribution_phase import (
    BlueAttributionPhase, AttributionResult, TimelineEvent,
    get_blue_attribution_phase,
)
from .purple_debrief import (
    PurpleDebrief, PurpleDebriefResult, GapItem, get_purple_debrief,
)
from .ai_analysis import AIAnalysis, get_ai_analysis
from .realtime_push import RealtimePush, get_realtime_push, LOG_LEVELS
from .report_generator import ReportGenerator, ReportData, get_report_generator
from .red_blue_orchestrator import (
    RedBlueOrchestrator, RBTask, get_orchestrator, REPORTS_DIR, STAGES,
)
from .red_blue_dashboard import (
    RedBlueDashboard, get_dashboard,
)

__all__ = [
    "RedReconPhase", "ReconResult", "get_red_recon_phase",
    "RedInitialAccessPhase", "IAResult", "PHISH_TEMPLATES",
    "get_red_initial_access_phase",
    "RedExecutionPhase", "ExecResult", "SHELL_TEMPLATES",
    "get_red_execution_phase",
    "RedPrivescPhase", "PrivescResult", "PrivescFinding",
    "get_red_privesc_phase", "WIN_PRIVESC_CVES", "LINUX_PRIVESC_CVES",
    "RedLateralPhase", "LateralResult", "get_red_lateral_phase",
    "RedObjectivePhase", "ObjectiveResult", "get_red_objective_phase",
    "BlueDetectionPhase", "DetectionResult", "SURICATA_RULES",
    "get_blue_detection_phase",
    "BlueResponsePhase", "ResponseResult", "IR_LIFECYCLE",
    "get_blue_response_phase",
    "BlueAttributionPhase", "AttributionResult", "TimelineEvent",
    "get_blue_attribution_phase",
    "PurpleDebrief", "PurpleDebriefResult", "GapItem",
    "get_purple_debrief",
    "AIAnalysis", "get_ai_analysis",
    "RealtimePush", "get_realtime_push", "LOG_LEVELS",
    "ReportGenerator", "ReportData", "get_report_generator",
    "RedBlueOrchestrator", "RBTask", "get_orchestrator",
    "REPORTS_DIR", "STAGES",
    "RedBlueDashboard", "get_dashboard",
]
