# -*- coding: utf-8 -*-
"""
unified_dashboard.py — 统一仪表盘（安全态势总览，整合十六大领域数据）。
"""

from __future__ import annotations

from typing import Any, Dict

from .data_aggregator import DOMAINS, get_aggregator


class UnifiedDashboard:
    """统一安全态势仪表盘。"""

    def __init__(self) -> None:
        self.agg = get_aggregator()

    def overview(self) -> Dict[str, Any]:
        return {
            "score": self.agg.security_score(),
            "summary": self.agg.stats_summary(),
            "domains": self.agg.domain_health(),
        }

    def full_screen(self) -> Dict[str, Any]:
        return {
            "domains_meta": DOMAINS,
            "score": self.agg.security_score(),
            "summary": self.agg.stats_summary(),
            "domain_health": self.agg.domain_health(),
            "trend_7d": self.agg.trend(7),
            "trend_30d": self.agg.trend(30),
            "recent_alerts": self.agg.list_alerts(limit=15),
            "recent_events": self.agg.list_events(limit=20),
            "recent_tasks": self.agg.list_tasks(limit=15),
        }

    def trend(self, days: int = 7) -> Dict[str, Any]:
        return self.agg.trend(days)

    def realtime_events(self, limit: int = 50) -> Dict[str, Any]:
        return {"events": self.agg.list_events(limit=limit)}


_default = None


def get_dashboard() -> "UnifiedDashboard":
    global _default
    if _default is None:
        _default = UnifiedDashboard()
    return _default
