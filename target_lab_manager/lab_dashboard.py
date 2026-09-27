# -*- coding: utf-8 -*-
"""
lab_dashboard.py —— 靶场仪表盘聚合

一次性返回：Docker 可用性 + 全部靶场状态 + 运行统计。
"""

from __future__ import annotations

from typing import Any, Dict

from .lab_manager import get_lab_manager, detect_docker, NOTICE


class LabDashboard:
    """靶场仪表盘聚合器。"""

    def overview(self) -> Dict[str, Any]:
        mgr = get_lab_manager()
        all_status = mgr.status_all()
        instances = all_status.get("instances", [])
        running = [i for i in instances if i.get("status") == "running"]
        return {
            "success": True,
            "data": {
                "docker": all_status.get("docker"),
                "instances": instances,
                "supported": mgr.list_supported(),
                "stats": {
                    "total": len(instances),
                    "running": len(running),
                    "stopped": len(instances) - len(running),
                },
                "notice": NOTICE,
            },
        }

    def quick_pick(self) -> Dict[str, Any]:
        """给出"推荐先启动哪个靶场"的建议。"""
        return {
            "success": True,
            "data": {
                "recommended": "dvwa",
                "reason": "DVWA 最轻量，适合第一次跑通流程",
                "order": ["dvwa", "juice-shop", "webgoat"],
            },
        }


_singleton: LabDashboard | None = None


def get_lab_dashboard() -> LabDashboard:
    global _singleton
    if _singleton is None:
        _singleton = LabDashboard()
    return _singleton
