# -*- coding: utf-8 -*-
"""
simple_dashboard.py —— 极简仪表盘聚合

一次性聚合：布局配置 + 核心功能 + 任务统计 + 新手引导状态。
供 /api/v1/simple/dashboard 调用，前端首屏渲染只发一个请求。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .simple_layout import get_layout
from .task_manager_simple import get_task_manager, STAGES
from .onboarding_guide import get_onboarding_guide


class SimpleDashboard:
    """极简仪表盘聚合器。"""

    def overview(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        layout = get_layout()
        tm = get_task_manager()
        guide = get_onboarding_guide()

        stat = tm.stats().get("data", {})
        guide_state = (guide.get_state(session_id)
                       if session_id else {"finished": True})
        show_guide = bool(session_id and guide.should_start(session_id))

        return {
            "success": True,
            "data": {
                "mode": "simple",
                "layout": layout.get_layout(),
                "features": layout.get_core_features(),
                "hidden": layout.get_hidden_count(),
                "stages": STAGES,
                "stats": stat,
                "onboarding": {
                    "show": show_guide,
                    "state": guide_state,
                },
            },
        }

    def task_detail(self, task_id: str) -> Dict[str, Any]:
        """聚合：任务详情 + 最近日志 + 报告预览。"""
        tm = get_task_manager()
        t = tm.get_task(task_id)
        if not t.get("success"):
            return t
        logs = tm.get_logs(task_id, limit=50)
        report = tm.get_report(task_id)
        return {
            "success": True,
            "data": {
                "task": t["data"],
                "logs": logs.get("data", {}).get("logs", []),
                "report": report.get("data"),
            },
        }


_singleton: SimpleDashboard | None = None


def get_dashboard() -> SimpleDashboard:
    global _singleton
    if _singleton is None:
        _singleton = SimpleDashboard()
    return _singleton
