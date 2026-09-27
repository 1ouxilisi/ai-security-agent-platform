# -*- coding: utf-8 -*-
"""
soc_center_dashboard.py — SOC Center 仪表盘聚合（顶层门面，整合各子模块）。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .configuration_center import get_configuration_center
from .data_aggregator import DOMAINS, get_aggregator
from .global_search import get_global_search
from .notification_center import get_notification_center
from .unified_alert_center import get_alert_center
from .unified_dashboard import get_dashboard
from .unified_operation_log import get_operation_log
from .unified_task_list import get_task_list


class SOCCenterDashboard:
    """SOC Center 顶层聚合门面。"""

    def __init__(self) -> None:
        self.agg = get_aggregator()
        self.dash = get_dashboard()
        self.tasks = get_task_list()
        self.alerts = get_alert_center()
        self.logs = get_operation_log()
        self.search = get_global_search()
        self.notify = get_notification_center()
        self.config = get_configuration_center()

    def home(self) -> Dict[str, Any]:
        return self.dash.full_screen()

    def domains_nav(self) -> Dict[str, Any]:
        return {"domains": DOMAINS}

    def modules_status(self) -> Dict[str, Any]:
        return {
            "aggregator": "ok",
            "dashboard": "ok",
            "tasks": "ok",
            "alerts": "ok",
            "logs": "ok",
            "search": "ok",
            "notification_center": "ok",
            "config_center": "ok",
            "ws_subscribers": self.notify.subscriber_count(),
        }


_default: Optional[SOCCenterDashboard] = None


def get_soc_center() -> SOCCenterDashboard:
    global _default
    if _default is None:
        _default = SOCCenterDashboard()
    return _default
