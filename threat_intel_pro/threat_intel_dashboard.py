# -*- coding: utf-8 -*-
"""
threat_intel_dashboard.py — 方向2 威胁情报 Pro：大屏仪表盘聚合。

聚合各阶段数据，供 /dashboard/* 与大屏消费。
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .ioc_collection_phase import get_collection_phase
from .ioc_management_phase import get_management_phase
from .ioc_matching_phase import get_matching_phase
from .threat_actor_phase import get_actor_phase
from .attack_surface_phase import get_attack_surface_phase
from .darkweb_monitor_phase import get_darkweb_phase
from .intel_analysis_phase import get_analysis_phase
from .intel_sharing_phase import get_sharing_phase
from .realtime_push import manager


class ThreatIntelDashboard:
    """威胁情报大屏聚合器。"""

    def __init__(self) -> None:
        self.collection = get_collection_phase()
        self.management = get_management_phase()
        self.matching = get_matching_phase()
        self.actors = get_actor_phase()
        self.surface = get_attack_surface_phase()
        self.darkweb = get_darkweb_phase()
        self.analysis = get_analysis_phase()
        self.sharing = get_sharing_phase()

    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        im = self.management.stats()
        mm = self.matching.stats()
        am = self.actors.stats()
        sm = self.surface.stats()
        dm = self.darkweb.stats()
        return {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ioc_total": im.get("total", 0),
            "ioc_by_type": im.get("by_type", {}),
            "ioc_by_confidence": im.get("by_confidence", {}),
            "match_hits": mm.get("total_hits", 0),
            "open_alerts": mm.get("open_alerts", 0),
            "actor_total": am.get("total", 0),
            "surface_assets": sm.get("total_assets", 0),
            "surface_score": sm.get("avg_score", 0),
            "darkweb_hits": dm.get("total_hits", 0),
            "warnings": self.analysis.stats().get("total_warnings", 0),
            "sources": [s.to_dict() for s in
                        self.collection._sources.values()],  # noqa: SLF001
            "ws": manager.stats(),
        }

    # ------------------------------------------------------------------ #
    # 图表数据
    # ------------------------------------------------------------------ #
    def ioc_trend(self, days: int = 7) -> Dict[str, Any]:
        """模拟近 N 天 IOC 趋势（确定性曲线）。"""
        series = [max(0, 10 + (i * 3) + ((i * 7) % 5)) for i in range(days)]
        return {"days": days, "series": series,
                "labels": [f"D-{days-i}" for i in range(days)]}

    def geo_distribution(self) -> Dict[str, Any]:
        """攻击源地理分布（基于入库 IOC 的 country 字段）。"""
        counter: Dict[str, int] = {}
        for ioc in self.management._iocs.values():  # noqa: SLF001
            if ioc.country:
                counter[ioc.country] = counter.get(ioc.country, 0) + 1
        top = sorted(counter.items(), key=lambda x: x[1],
                     reverse=True)[:15]
        return {"points": [{"country": c, "count": n} for c, n in top]}

    def top_actors(self, limit: int = 10) -> Dict[str, Any]:
        res = self.actors.list_actors(limit=limit)
        return {"actors": res["items"][:limit]}

    def industry_distribution(self) -> Dict[str, Any]:
        return self.analysis.industry_distribution(self.actors.stats())

    def ioc_type_distribution(self) -> Dict[str, Any]:
        return self.management.stats().get("by_type", {})

    def threat_level_distribution(self) -> Dict[str, Any]:
        return self.management.stats().get("by_confidence", {})

    def alert_stats(self) -> Dict[str, Any]:
        return self.matching.stats()

    # ------------------------------------------------------------------ #
    # 实时滚动流（最新 N 条 IOC）
    # ------------------------------------------------------------------ #
    def live_ioc_feed(self, limit: int = 20) -> Dict[str, Any]:
        items = list(self.management._iocs.values())  # noqa: SLF001
        items.sort(key=lambda x: x.last_seen, reverse=True)
        return {"feed": [i.to_dict() for i in items[:limit]]}


_dash: Optional[ThreatIntelDashboard] = None


def get_dashboard() -> ThreatIntelDashboard:
    global _dash
    if _dash is None:
        _dash = ThreatIntelDashboard()
    return _dash
