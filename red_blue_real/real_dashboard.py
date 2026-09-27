# -*- coding: utf-8 -*-
"""
real_dashboard.py — 方向4：真实仪表盘聚合。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .real_orchestrator import get_real_orchestrator, STAGES
from .red_tools_integration import get_red_tools
from .blue_tools_integration import get_blue_tools
from .red_attack_chain import get_red_attack_chain
from .blue_detection import get_blue_detection


class RealDashboard:
    """真实仪表盘聚合器。"""

    def __init__(self) -> None:
        self.orch = get_real_orchestrator()

    def overview(self) -> Dict[str, Any]:
        tasks = self.orch.list_tasks()
        running = [t for t in tasks if t["status"] == "running"]
        done = [t for t in tasks if t["status"] == "done"]
        errors = [t for t in tasks if t["status"] == "error"]
        return {
            "task_total": len(tasks), "task_running": len(running),
            "task_done": len(done), "task_error": len(errors),
            "stages": [{"key": k, "label": n, "progress": p}
                       for k, n, p in STAGES],
        }

    def tool_matrix(self) -> Dict[str, Any]:
        return {
            "red_tools_c2": get_red_tools().health(),
            "blue_tools": get_blue_tools().health(),
            "red_attack_chain": get_red_attack_chain().full_tool_matrix(),
            "blue_detection": get_blue_detection().full_tool_matrix(),
        }

    def recent_tasks(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.orch.list_tasks()[:limit]


_default_dash: Optional[RealDashboard] = None


def get_real_dashboard() -> RealDashboard:
    global _default_dash
    if _default_dash is None:
        _default_dash = RealDashboard()
    return _default_dash
