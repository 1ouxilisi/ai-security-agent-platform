# -*- coding: utf-8 -*-
"""llm_ultra_dashboard.py — LLM极致优化仪表盘聚合。

聚合所有llm_ultra模块数据，提供统一仪表盘视图。
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .prompt_master import get_prompt_master
from .context_memory import get_context_memory
from .multi_turn_chat import get_multi_turn_chat
from .vuln_knowledge_base import get_vuln_knowledge_base
from .report_polisher import get_report_polisher


class LLmUltraDashboard:
    """LLM极致优化仪表盘。"""

    def __init__(self) -> None:
        self._prompts = get_prompt_master()
        self._memory = get_context_memory()
        self._chat = get_multi_turn_chat()
        self._kb = get_vuln_knowledge_base()
        self._polisher = get_report_polisher()

    def overview(self) -> Dict[str, Any]:
        """仪表盘总览。"""
        return {
            "title": "LLM能力极致优化仪表盘",
            "modules": {
                "prompt_master": {
                    "status": "loaded",
                    "prompts": self._prompts.get_stats(),
                },
                "context_memory": {
                    "status": "loaded",
                    **self._memory.get_stats(),
                },
                "multi_turn_chat": {
                    "status": "loaded",
                    **self._chat.get_stats(),
                },
                "vuln_knowledge_base": {
                    "status": "loaded",
                    **self._kb.get_stats(),
                },
                "report_polisher": {
                    "status": "loaded",
                    **self._polisher.get_stats(),
                },
            },
            "features": {
                "optimized_prompts": "4套专业Prompt模板（漏洞分析/报告生成/智能问答/攻击链规划）",
                "context_memory": "会话记忆 + 扫描历史持久化",
                "multi_turn_chat": "多轮对话 + 追问建议",
                "knowledge_base": f"{self._kb.get_stats()['total_entries']}条CVE知识库",
                "report_polishing": "术语规范化 + 质量评分 + 格式建议",
                "graceful_degradation": "无Key时自动降级，标注降级模式",
            },
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def prompt_showcase(self) -> Dict[str, Any]:
        """展示优化后的Prompt效果对比。"""
        keys = ["vuln_analysis", "report_generation", "smart_qa", "attack_chain_planning"]
        comparisons = {}
        for k in keys:
            comparisons[k] = self._prompts.compare_prompts(k)
        return comparisons

    def chat_demo(self, question: str,
                  session_id: str = "demo") -> Dict[str, Any]:
        """演示多轮对话功能。"""
        return self._chat.chat(session_id, question)

    def kb_demo(self, vuln_type: str = "rce") -> Dict[str, Any]:
        """演示知识库关联功能。"""
        correlations = self._kb.auto_correlate(vuln_type)
        return {
            "vuln_type": vuln_type,
            "correlated_cves": correlations,
            "total_kb_entries": self._kb.get_stats()["total_entries"],
        }

    def polisher_demo(self, report_sample: str = "") -> Dict[str, Any]:
        """演示报告润色功能。"""
        if not report_sample:
            report_sample = (
                "## 扫描结果\n\n"
                "网站被黑了，发现好几个漏洞。\n\n"
                "1. SQL注入 - 太严重了\n"
                "2. XSS - 必须马上修\n\n"
                "赶紧处理吧！"
            )
        return self._polisher.polish(report_sample)

    def health(self) -> Dict[str, Any]:
        return {
            "package": "llm_ultra",
            "modules_loaded": 5,
            "prompts_available": self._prompts.get_stats()["total_prompts"],
            "kb_entries": self._kb.get_stats()["total_entries"],
            "active_sessions": self._memory.get_stats()["sessions"],
            "degradation_mode": True,
            "note": "配置LLM Key后自动切换为真实AI分析",
        }

    def feature_list(self) -> Dict[str, Any]:
        """列出所有LLM极致优化功能。"""
        return {
            "direction_3_features": [
                {
                    "id": "optimized_prompts",
                    "name": "所有AI Prompt优化",
                    "details": [
                        "漏洞分析Prompt：专业安全分析师视角，结构化输出",
                        "报告生成Prompt：客户友好+技术准确，专业报告格式",
                        "智能问答Prompt：简洁明了+actionable建议",
                        "攻击链规划Prompt：资深红队视角，完整攻击路径",
                    ],
                },
                {
                    "id": "context_memory",
                    "name": "上下文记忆",
                    "details": [
                        "AI能记住之前的扫描结果",
                        "持续分析，基于历史数据",
                        "会话上下文管理（LRU淘汰）",
                    ],
                },
                {
                    "id": "multi_turn_chat",
                    "name": "多轮对话",
                    "details": [
                        "用户可以和AI持续对话",
                        "深入讨论漏洞细节",
                        "智能追问建议机制",
                    ],
                },
                {
                    "id": "vuln_knowledge_base",
                    "name": "漏洞知识库",
                    "details": [
                        "AI分析时自动查CVE",
                        "自动关联Exploit-DB",
                        "自动关联已知漏洞",
                    ],
                },
                {
                    "id": "report_polisher",
                    "name": "报告润色",
                    "details": [
                        "AI自动润色报告",
                        "术语规范化+语气专业化",
                        "质量评分+格式改进建议",
                    ],
                },
                {
                    "id": "graceful_degradation",
                    "name": "优雅降级",
                    "details": [
                        "无Key时优雅降级不崩溃",
                        "降级结果明确标注",
                        "模板化分析保证可用性",
                    ],
                },
            ],
        }


_singleton: Optional[LLmUltraDashboard] = None


def get_llm_ultra_dashboard() -> LLmUltraDashboard:
    global _singleton
    if _singleton is None:
        _singleton = LLmUltraDashboard()
    return _singleton
