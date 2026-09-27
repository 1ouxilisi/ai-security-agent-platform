# -*- coding: utf-8 -*-
"""
ai_upgrade 包 — 方向2：AI 能力大升级

LLM 真实接入、漏洞智能分析、报告自动生成、智能问答、AI 辅助挖 SRC、
智能攻击链规划与聚合仪表盘。无 LLM Key 时自动降级规则模式，不崩溃。
"""
from __future__ import annotations

from .llm_integration import (
    AIEnhancedLLM, get_enhanced_llm, get_decision_log, clear_decision_log,
)
from .vuln_analyzer import VulnAnalyzer, get_vuln_analyzer
from .report_writer import ReportWriter, get_report_writer, REPORTS
from .smart_qa import SmartQA, get_smart_qa, set_context, QA_HISTORY
from .src_assistant import SRCAssistant, get_src_assistant, TARGETS, SUBMISSIONS
from .ai_upgrade_dashboard import (
    AIUpgradeDashboard, get_ai_dashboard, CHAINS, CHAIN_STAGES,
)

__all__ = [
    "AIEnhancedLLM", "get_enhanced_llm", "get_decision_log", "clear_decision_log",
    "VulnAnalyzer", "get_vuln_analyzer",
    "ReportWriter", "get_report_writer", "REPORTS",
    "SmartQA", "get_smart_qa", "set_context", "QA_HISTORY",
    "SRCAssistant", "get_src_assistant", "TARGETS", "SUBMISSIONS",
    "AIUpgradeDashboard", "get_ai_dashboard", "CHAINS", "CHAIN_STAGES",
]
