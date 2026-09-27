# -*- coding: utf-8 -*-
"""llm_ultra — LLM能力极致优化包（方向3）。

目标：LLM配置后分析质量做到极致。

模块：
- prompt_master:       Prompt大师 — 所有AI Prompt专业优化
- context_memory:      上下文记忆 — 记住历史扫描结果，持续分析
- multi_turn_chat:     多轮对话 — 深入讨论漏洞细节
- vuln_knowledge_base: 漏洞知识库 — 自动查CVE/Exploit-DB
- report_polisher:     报告润色 — 让报告更专业
- llm_ultra_dashboard: 仪表盘聚合
"""
from __future__ import annotations

from .prompt_master import PromptMaster, get_prompt_master
from .context_memory import ContextMemory, get_context_memory
from .multi_turn_chat import MultiTurnChat, get_multi_turn_chat
from .vuln_knowledge_base import VulnKnowledgeBase, get_vuln_knowledge_base
from .report_polisher import ReportPolisher, get_report_polisher
from .llm_ultra_dashboard import LLmUltraDashboard, get_llm_ultra_dashboard

__all__ = [
    "PromptMaster",
    "get_prompt_master",
    "ContextMemory",
    "get_context_memory",
    "MultiTurnChat",
    "get_multi_turn_chat",
    "VulnKnowledgeBase",
    "get_vuln_knowledge_base",
    "ReportPolisher",
    "get_report_polisher",
    "LLmUltraDashboard",
    "get_llm_ultra_dashboard",
]
