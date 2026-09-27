# -*- coding: utf-8 -*-
"""
red_blue_dashboard.py — 红蓝对抗 Pro 仪表盘聚合。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .red_blue_orchestrator import get_orchestrator, STAGES
from .red_recon_phase import get_red_recon_phase
from .red_initial_access_phase import get_red_initial_access_phase
from .red_execution_phase import get_red_execution_phase
from .red_privesc_phase import get_red_privesc_phase
from .red_lateral_phase import get_red_lateral_phase
from .red_objective_phase import get_red_objective_phase
from .blue_detection_phase import get_blue_detection_phase
from .blue_response_phase import get_blue_response_phase
from .blue_attribution_phase import get_blue_attribution_phase


class RedBlueDashboard:
    """仪表盘聚合器。"""

    def __init__(self) -> None:
        self.orch = get_orchestrator()

    def overview(self) -> Dict[str, Any]:
        tasks = self.orch.list_tasks()
        running = [t for t in tasks if t["status"] == "running"]
        done = [t for t in tasks if t["status"] == "done"]
        errors = [t for t in tasks if t["status"] == "error"]
        return {
            "task_total": len(tasks),
            "task_running": len(running),
            "task_done": len(done),
            "task_error": len(errors),
            "stages": [{"key": k, "label": n, "progress": p}
                       for k, n, p in STAGES],
        }

    def tool_matrix(self) -> Dict[str, Any]:
        return {
            "red_recon": get_red_recon_phase().tool_status(),
            "red_initial_access": get_red_initial_access_phase().tool_status(),
            "red_execution": get_red_execution_phase().tool_status(),
            "red_privesc": get_red_privesc_phase().tool_status(),
            "red_lateral": get_red_lateral_phase().tool_status(),
            "red_objective": get_red_objective_phase().tool_status(),
            "blue_detection": get_blue_detection_phase().tool_status(),
            "blue_response": get_blue_response_phase().tool_status(),
            "blue_attribution": get_blue_attribution_phase().tool_status(),
        }

    def recent_tasks(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.orch.list_tasks()[:limit]

    def stage_status(self) -> List[Dict[str, Any]]:
        return [{"key": k, "label": n, "progress": p}
                for k, n, p in STAGES]


_default_dash: Optional[RedBlueDashboard] = None


def get_dashboard() -> RedBlueDashboard:
    global _default_dash
    if _default_dash is None:
        _default_dash = RedBlueDashboard()
    return _default_dash
