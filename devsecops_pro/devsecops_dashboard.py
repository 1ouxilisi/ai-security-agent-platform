# -*- coding: utf-8 -*-
"""
devsecops_dashboard.py — DevSecOps Pro 仪表盘聚合。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .devsecops_orchestrator import get_orchestrator, STAGES
from .realtime_push import get_realtime_push


class DevSecOpsDashboard:
    """仪表盘聚合器。"""

    def __init__(self) -> None:
        self.orch = get_orchestrator()
        self.rt = get_realtime_push()

    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        tasks = self.orch.list_tasks()
        running = [t for t in tasks if t["status"] == "running"]
        done = [t for t in tasks if t["status"] == "done"]
        errors = [t for t in tasks if t["status"] == "error"]

        # 汇总最近一次完成任务的风险
        latest_risk: Dict[str, Any] = {}
        for t in tasks:
            if t["status"] == "done" and t.get("risk"):
                latest_risk = t["risk"]
                break

        return {
            "task_total": len(tasks),
            "task_running": len(running),
            "task_done": len(done),
            "task_error": len(errors),
            "latest_risk": latest_risk,
            "stages": [
                {"key": k, "label": n, "progress": p}
                for k, n, p in STAGES
            ],
        }

    # ------------------------------------------------------------------ #
    def recent_tasks(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.orch.list_tasks()[:limit]

    # ------------------------------------------------------------------ #
    def task_detail(self, task_id: str) -> Dict[str, Any]:
        t = self.orch.get_task(task_id)
        if t is None:
            return {"error": "task not found"}
        return t.to_dict()

    # ------------------------------------------------------------------ #
    def stage_status(self) -> List[Dict[str, Any]]:
        return [{"key": k, "label": n, "progress": p}
                for k, n, p in STAGES]

    # ------------------------------------------------------------------ #
    def tools_status(self) -> Dict[str, Any]:
        return {
            "cicd": self.orch.cicd.tool_status(),
            "sast": self.orch.sast.tool_status(),
            "sca": self.orch.sca.tool_status(),
            "secrets": self.orch.secrets.tool_status(),
            "iac": self.orch.iac.tool_status(),
            "container": self.orch.container.tool_status(),
        }

    # ------------------------------------------------------------------ #
    def event_stream(self, task_id: str) -> List[Dict[str, Any]]:
        return self.rt.history(task_id)


_default: Optional[DevSecOpsDashboard] = None


def get_dashboard() -> DevSecOpsDashboard:
    global _default
    if _default is None:
        _default = DevSecOpsDashboard()
    return _default
