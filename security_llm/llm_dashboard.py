#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_dashboard.py — 安全大模型控制台数据聚合层（第26轮升级方向1）。

聚合 llm_manager / agent_engine / code_generator / qa_system / smart_report
五大模块的运行时指标，为前端控制台提供一站式数据视图。
全部内存字典模拟，仅用于授权安全场景。
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List

from .llm_manager import llm_manager
from .agent_engine import agent_engine
from .code_generator import code_generator
from .qa_system import qa_system
from .smart_report import smart_report


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class LLMDashboard:
    """安全大模型控制台数据聚合。"""

    def overview(self) -> Dict[str, Any]:
        """总览卡片数据。"""
        models = llm_manager.list_models()
        agents = agent_engine.list_agents()
        tasks = agent_engine.list_tasks()
        qa_stats = qa_system.stats()
        reports = smart_report.list_reports()
        return {
            "platform": "安全大模型与AI Agent深度平台",
            "version": "26.1.0",
            "uptime_hours": 720,
            "kpi": {
                "models_loaded": len(models),
                "active_model": llm_manager.current_model,
                "agents_registered": len(agents),
                "tasks_completed": len(tasks),
                "qa_sessions": qa_stats["total_sessions"],
                "qa_questions": qa_stats["total_questions"],
                "reports_generated": len(reports),
                "kb_docs": len(llm_manager.kb_docs),
            },
            "health": {
                "llm_latency_ms": 320,
                "agent_success_rate": 0.92,
                "qa_avg_confidence": qa_stats.get("avg_confidence", 0.8),
                "rag_recall": 0.87,
            },
            "ts": _now(),
        }

    def trend(self, metric: str = "tasks", days: int = 7) -> Dict[str, Any]:
        """近7天趋势数据（模拟）。"""
        base = {"tasks": 12, "queries": 45, "generations": 8, "reports": 3}
        labels = []
        values = []
        now = datetime.now()
        for i in range(days - 1, -1, -1):
            d = now.replace(day=max(1, now.day - i))
            labels.append(d.strftime("%m-%d"))
            # 确定性伪随机
            v = base.get(metric, 10) + ((hash(f"{metric}{d.isoformat()}") % 7) - 3)
            values.append(max(0, v))
        return {"metric": metric, "labels": labels, "values": values, "ts": _now()}

    def agent_status(self) -> Dict[str, Any]:
        """Agent 运行状态聚合。"""
        agents = agent_engine.list_agents()
        status_count: Dict[str, int] = {}
        for a in agents:
            status_count[a["status"]] = status_count.get(a["status"], 0) + 1
        return {
            "total": len(agents),
            "by_status": status_count,
            "recent_tasks": agent_engine.list_tasks()[-5:],
            "collab_sessions": len(agent_engine.list_collabs()),
        }

    def usage_stats(self) -> Dict[str, Any]:
        """使用量与成本统计。"""
        return {
            "tokens_today": 1285000,
            "tokens_total": 38420000,
            "api_calls_today": 320,
            "api_calls_total": 9640,
            "cost_estimate_usd": 42.8,
            "cost_cny": 305.6,
            "per_model": [
                {"model": "sec-llm-7b", "calls": 240, "tokens": 980000},
                {"model": "sec-llm-13b", "calls": 80, "tokens": 305000},
            ],
            "ts": _now(),
        }

    def alerts(self) -> List[Dict[str, Any]]:
        """平台告警列表。"""
        return [
            {"level": "warning", "title": "知识库文档低于阈值",
             "desc": "当前仅15条，建议扩充至100+以提升RAG召回率", "ts": _now()},
            {"level": "info", "title": "模型 sec-llm-7b 延迟升高",
             "desc": "近1小时P95延迟从280ms升至420ms", "ts": _now()},
            {"level": "success", "title": "Agent 流水线运行正常",
             "desc": "最近10个任务全部完成，成功率100%", "ts": _now()},
        ]

    def module_health(self) -> List[Dict[str, Any]]:
        return [
            {"module": "llm_manager", "status": "healthy", "latency_ms": 120},
            {"module": "agent_engine", "status": "healthy", "latency_ms": 85},
            {"module": "code_generator", "status": "healthy", "latency_ms": 60},
            {"module": "qa_system", "status": "healthy", "latency_ms": 45},
            {"module": "smart_report", "status": "healthy", "latency_ms": 95},
        ]


llm_dashboard = LLMDashboard()
