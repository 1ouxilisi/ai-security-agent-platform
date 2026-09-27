# -*- coding: utf-8 -*-
"""
red_blue_real — 方向4：红蓝对抗真实化（6.5 → 8.5）。

与 red_blue_pro（模拟数据）对应，本包把红蓝对抗做实：
    - 真实工具检测（shutil.which / 端口 / 服务）
    - 真实 subprocess 调用（300s 超时）与真实输出解析
    - 未安装/未配置工具给出安装配置步骤，绝不 mock
    - 真实红队八战术 / 真实蓝队五能力 / 真实紫队复盘
    - C2 工具集成（CS/MSF/Empire）、蓝队工具集成（Suricata/Snort/ES/Wazuh/TheHive）
    - ATT&CK Navigator 层、真实报告落盘、编排器、仪表盘
"""

from __future__ import annotations

from .red_attack_chain import (
    RedAttackChain, RedInitialAccess, RedExecution, RedPersistence,
    RedPrivEsc, RedDefenseEvasion, RedCredentialAccess, RedLateral,
    RedExfiltration, get_red_attack_chain,
)
from .blue_detection import (
    BlueDetection, LogCollection, IntrusionDetect, EDBDetect,
    ThreatHunt, IncidentResponse, get_blue_detection,
)
from .purple_debrief_real import (
    PurpleDebriefReal, PurpleStep, get_purple_debrief_real,
)
from .red_tools_integration import (
    RedToolsIntegration, MetasploitTool, EmpireTool, CobaltStrikeTool,
    get_red_tools,
)
from .blue_tools_integration import (
    BlueToolsIntegration, SuricataTool, SnortTool, ElasticsearchTool,
    WazuhTool, TheHiveTool, get_blue_tools,
)
from .attack_navigator import (
    AttackNavigator, RED_TECHNIQUES, get_attack_navigator,
)
from .real_report_generator import (
    RealReportGenerator, RealReportData, REPORTS_DIR,
    get_real_report_generator,
)
from .real_orchestrator import (
    RealOrchestrator, RealTask, get_real_orchestrator, STAGES,
)
from .real_dashboard import RealDashboard, get_real_dashboard

__all__ = [
    "RedAttackChain", "RedInitialAccess", "RedExecution", "RedPersistence",
    "RedPrivEsc", "RedDefenseEvasion", "RedCredentialAccess", "RedLateral",
    "RedExfiltration", "get_red_attack_chain",
    "BlueDetection", "LogCollection", "IntrusionDetect", "EDBDetect",
    "ThreatHunt", "IncidentResponse", "get_blue_detection",
    "PurpleDebriefReal", "PurpleStep", "get_purple_debrief_real",
    "RedToolsIntegration", "MetasploitTool", "EmpireTool",
    "CobaltStrikeTool", "get_red_tools",
    "BlueToolsIntegration", "SuricataTool", "SnortTool",
    "ElasticsearchTool", "WazuhTool", "TheHiveTool", "get_blue_tools",
    "AttackNavigator", "RED_TECHNIQUES", "get_attack_navigator",
    "RealReportGenerator", "RealReportData", "REPORTS_DIR",
    "get_real_report_generator",
    "RealOrchestrator", "RealTask", "get_real_orchestrator", "STAGES",
    "RealDashboard", "get_real_dashboard",
]
