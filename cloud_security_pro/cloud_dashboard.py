# -*- coding: utf-8 -*-
"""
cloud_dashboard.py — 云安全 Pro 仪表盘聚合。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .cloud_orchestrator import get_orchestrator, STAGES
from .vuln_detect_phase import get_vuln_detect_phase
from .asset_discovery_phase import detect_credential_status


class CloudSecurityDashboard:
    """仪表盘聚合。"""

    def __init__(self) -> None:
        self.orch = get_orchestrator()
        self.vuln_db = get_vuln_detect_phase()

    def overview(self) -> Dict[str, Any]:
        tasks = self.orch.list_tasks()
        running = [t for t in tasks if t["status"] == "running"]
        done = [t for t in tasks if t["status"] == "done"]
        errors = [t for t in tasks if t["status"] == "error"]
        # 最近一次完成任务的风险聚合
        latest = done[0] if done else {}
        return {
            "task_total": len(tasks),
            "task_running": len(running),
            "task_done": len(done),
            "task_error": len(errors),
            "latest_risk_score": (latest.get("risk") or {}).get("score"),
            "latest_risk_level": (latest.get("risk") or {}).get("level"),
            "compliance_pass_rate": (latest.get("compliance") or {}).get("pass_rate"),
            "vuln_db": self.vuln_db.db_overview(),
            "credential": {
                "aws": detect_credential_status("aws"),
                "aliyun": detect_credential_status("aliyun"),
            },
            "stages": [
                {"key": k, "label": n, "progress": p} for k, n, p in STAGES
            ],
        }

    def recent_tasks(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.orch.list_tasks()[:limit]

    def stage_status(self) -> List[Dict[str, Any]]:
        return [{"key": k, "label": n, "progress": p}
                for k, n, p in STAGES]


_default_dash: Optional[CloudSecurityDashboard] = None


def get_dashboard() -> CloudSecurityDashboard:
    global _default_dash
    if _default_dash is None:
        _default_dash = CloudSecurityDashboard()
    return _default_dash
