# -*- coding: utf-8 -*-
"""
workflow_linkage 包 — 领域联动工作流。

八大预设联动:
    渗透→合规 / 威胁情报→SOC / DevSecOps→供应链 / 红蓝对抗→取证
    数据安全→合规 / 工控IoT→威胁情报 / CTF→安全培训 / SRC→漏洞库

模块:
    linkage_rules      联动规则管理（8 预设 + 自定义）
    preset_linkages    8 条预设联动规则实现
    linkage_engine     联动执行引擎（监听/匹配/去重/重试/动作执行）
    linkage_monitor    联动监控仪表盘
    linkage_logger     联动日志
"""

from __future__ import annotations

from .linkage_engine import LinkageEngine, get_linkage_engine
from .linkage_logger import LinkageLogger, get_linkage_logger
from .linkage_monitor import LinkageMonitor, get_linkage_monitor
from .linkage_rules import (
    ACTIONS, EVENT_TYPES, LinkageRuleManager, get_rule_manager,
)
from .preset_linkages import PRESET_DEFS, install_presets

__all__ = [
    "LinkageRuleManager", "get_rule_manager", "ACTIONS", "EVENT_TYPES",
    "LinkageEngine", "get_linkage_engine",
    "LinkageLogger", "get_linkage_logger",
    "LinkageMonitor", "get_linkage_monitor",
    "PRESET_DEFS", "install_presets",
]
