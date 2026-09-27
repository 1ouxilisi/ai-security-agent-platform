# -*- coding: utf-8 -*-
"""
llm_optimization/llm_dashboard.py — LLM 状态仪表盘

聚合仪表盘所需的所有数据：
    - 当前 LLM 配置状态（脱敏）
    - 三大 AI 功能可用性
    - Prompt 模板清单
    - 调用历史 / 降级统计
    - 最近一次 e2e 测试结果
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from .prompt_optimizer import get_prompt_optimizer
from .ai_function_tester import get_history, get_ai_tester
from .llm_e2e_test import get_e2e_runner


class LLMDashboard:
    """LLM 状态仪表盘数据聚合。"""

    def __init__(self) -> None:
        self.optimizer = get_prompt_optimizer()
        self.tester = get_ai_tester()
        self.runner = get_e2e_runner()

    # ------------------------------------------------------------------
    # 当前配置状态
    # ------------------------------------------------------------------
    def config_status(self) -> Dict[str, Any]:
        try:
            from llm_integration import get_config_manager, get_llm_client
            cm = get_config_manager()
            status = cm.status()
            client = get_llm_client()
            status["client_available"] = bool(client.llm_available)
            status["provider"] = getattr(client, "provider", "unknown")
            return status
        except Exception as e:  # noqa: BLE001
            return {"configured": False, "error": str(e),
                    "message": "读取 LLM 配置状态失败"}

    # ------------------------------------------------------------------
    # 三大功能可用性（轻量探测，不发真实 LLM 请求）
    # ------------------------------------------------------------------
    def function_readiness(self) -> List[Dict[str, Any]]:
        cfg = self.config_status()
        configured = bool(cfg.get("configured"))
        funcs = [
            {"key": "vuln_analysis", "name": "漏洞智能分析",
             "desc": "输入扫描结果，AI 自动分析漏洞严重程度",
             "llm_ready": configured,
             "fallback_ready": True,
             "status": "llm" if configured else "rule"},
            {"key": "report_generation", "name": "报告自动生成",
             "desc": "输入扫描数据，AI 自动生成自然语言报告",
             "llm_ready": configured,
             "fallback_ready": True,
             "status": "llm" if configured else "rule"},
            {"key": "smart_qa", "name": "智能问答",
             "desc": "用户问「这个网站有什么风险」，AI 自动分析回答",
             "llm_ready": configured,
             "fallback_ready": True,
             "status": "llm" if configured else "rule"},
        ]
        return funcs

    # ------------------------------------------------------------------
    # 调用历史与降级统计
    # ------------------------------------------------------------------
    def call_stats(self) -> Dict[str, Any]:
        hist = get_history()
        total = len(hist)
        llm_calls = sum(1 for h in hist if h.get("mode") == "llm")
        rule_calls = sum(1 for h in hist if h.get("mode") == "rule")
        fallback_calls = sum(1 for h in hist if h.get("fallback"))
        by_scene: Dict[str, int] = {}
        for h in hist:
            s = h.get("scene", "unknown")
            by_scene[s] = by_scene.get(s, 0) + 1
        latencies = [h.get("latency_ms", 0) for h in hist if h.get("latency_ms")]
        avg_latency = int(sum(latencies) / len(latencies)) if latencies else 0
        return {
            "total_calls": total,
            "llm_calls": llm_calls,
            "rule_calls": rule_calls,
            "fallback_calls": fallback_calls,
            "by_scene": by_scene,
            "avg_latency_ms": avg_latency,
        }

    # ------------------------------------------------------------------
    # 仪表盘聚合
    # ------------------------------------------------------------------
    def overview(self) -> Dict[str, Any]:
        cfg = self.config_status()
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "config": cfg,
            "functions": self.function_readiness(),
            "stats": self.call_stats(),
            "prompts": self.optimizer.list_prompts(),
            "last_e2e": self.runner.get_last_run(),
        }

    # ------------------------------------------------------------------
    # 手动触发一次健康检查（轻量：只测一个 ping）
    # ------------------------------------------------------------------
    def health_check(self) -> Dict[str, Any]:
        cfg = self.config_status()
        if not cfg.get("configured"):
            return {"success": False,
                    "message": "未配置 LLM Key，所有功能走规则模式（未配置LLM）",
                    "config": cfg}
        try:
            from llm_integration import get_llm_client, reset_llm_client, reload_config
            reload_config()
            reset_llm_client()
            client = get_llm_client()
            r = client.test_connection()
            return {
                "success": r.get("success", False),
                "message": (f"LLM 连接正常，延迟 {r.get('data', {}).get('latency_ms')} ms"
                            if r.get("success") else
                            f"LLM 连接失败: {r.get('error')}"),
                "data": r.get("data"),
                "config": cfg,
            }
        except Exception as e:  # noqa: BLE001
            return {"success": False, "message": f"健康检查异常: {e}",
                    "config": cfg}


# 模块级单例
_dash: LLMDashboard | None = None


def get_dashboard() -> LLMDashboard:
    global _dash
    if _dash is None:
        _dash = LLMDashboard()
    return _dash
