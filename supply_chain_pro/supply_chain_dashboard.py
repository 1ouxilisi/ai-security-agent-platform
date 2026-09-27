# -*- coding: utf-8 -*-
"""
supply_chain_dashboard.py — 方向2 供应链安全 Pro：仪表盘聚合。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .supply_chain_orchestrator import get_orchestrator, STAGES


class SupplyChainDashboard:
    """仪表盘聚合器。"""

    def __init__(self) -> None:
        self.orch = get_orchestrator()

    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        tasks = self.orch.list_tasks()
        running = [t for t in tasks if t["status"] == "running"]
        done = [t for t in tasks if t["status"] == "done"]
        errors = [t for t in tasks if t["status"] == "error"]
        total_vulns = 0
        sev_counts = {"critical": 0, "high": 0, "medium": 0,
                      "low": 0}
        for t in tasks:
            ca = t.get("component_analysis", {}) or {}
            for v in ca.get("vulns", []):
                total_vulns += 1
                s = v.get("severity", "low")
                sev_counts[s] = sev_counts.get(s, 0) + 1
        return {
            "task_total": len(tasks),
            "task_running": len(running),
            "task_done": len(done),
            "task_error": len(errors),
            "vuln_total": total_vulns,
            "vuln_by_severity": sev_counts,
            "stages": [{"key": k, "label": n, "progress": p}
                       for k, n, p in STAGES],
        }

    # ------------------------------------------------------------------ #
    def recent_tasks(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.orch.list_tasks()[:limit]

    # ------------------------------------------------------------------ #
    def stage_status(self) -> List[Dict[str, Any]]:
        return [{"key": k, "label": n, "progress": p}
                for k, n, p in STAGES]

    # ------------------------------------------------------------------ #
    def tools_status(self) -> Dict[str, Any]:
        return {
            "sbom": self.orch.sbom.tools_status(),
            "analysis": self.orch.analysis.tools_status(),
            "dependency": self.orch.dep.tools_status(),
            "risk": self.orch.risk.tools_status(),
            "remediation": self.orch.remediation.tools_status(),
            "license_matrix_available": True,
        }


_default_dash: Optional[SupplyChainDashboard] = None


def get_dashboard() -> SupplyChainDashboard:
    global _default_dash
    if _default_dash is None:
        _default_dash = SupplyChainDashboard()
    return _default_dash
