# -*- coding: utf-8 -*-
"""
soc_dashboard.py — SOC 大屏仪表盘。

聚合:
    - 告警趋势（24h/7d/30d）
    - 攻击源地图（粗粒度国家/省份分布）
    - Top 攻击类型
    - 事件状态分布
    - 严重程度分布
    - 响应时间统计
    - 规则命中 Top10
    - 实时告警滚动
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from .alert_generation_phase import get_alert_generation_phase
from .correlation_phase import get_correlation_phase
from .incident_response_phase import get_incident_response_phase
from .postmortem_phase import get_postmortem_phase
from .realtime_push import get_realtime_push
from .threat_hunting_phase import get_threat_hunting_phase


_REGION_LATLNG = {
    "美国/境外": (37.09, -95.71),
    "欧洲/境外": (48.85, 2.35),
    "亚太": (35.68, 139.69),
    "内网/RFC1918": (39.90, 116.40),
    "未知": (0, 0),
}


class SOCDashboard:
    """SOC 大屏聚合器。"""

    def __init__(self) -> None:
        self.agg = get_alert_generation_phase()
        self.cor = get_correlation_phase()
        self.ir = get_incident_response_phase()
        self.hunt = get_threat_hunting_phase()
        self.pm = get_postmortem_phase()
        self.rt = get_realtime_push()

    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        agg = self.agg.aggregate()
        stats = self.cor.stats()
        ir = self.ir.stats()
        return {
            "alerts_total": agg["total"],
            "alerts_open": sum(v for k, v in agg["by_status"].items()
                               if k in ("new", "confirmed",
                                        "in_progress")),
            "alerts_critical": agg["by_severity"].get("critical", 0),
            "alerts_high": agg["by_severity"].get("high", 0),
            "tickets_open": ir["open"],
            "tickets_resolved": ir["resolved"],
            "playbook_runs": ir["playbook_runs"],
            "rules_enabled": stats["rule_enabled"],
            "rules_total": stats["rule_total"],
            "hits_total": stats["total_hits"],
        }

    # ------------------------------------------------------------------ #
    def alert_trend(self, window: str = "24h") -> Dict[str, Any]:
        """生成告警趋势（演示数据，基于现有聚合做抖动）。"""
        points = {"24h": 24, "7d": 7, "30d": 30}.get(window, 24)
        rng = random.Random(42)
        base = self.agg.aggregate()["total"] or 10
        series = []
        for i in range(points):
            v = max(0, int(base * (0.3 + rng.random())))
            series.append({"label": f"T-{points-i}", "value": v})
        return {"window": window, "series": series[::-1]}

    # ------------------------------------------------------------------ #
    def attack_map(self) -> List[Dict[str, Any]]:
        """攻击源地图（按 IP 归属聚合）。"""
        from .log_parsing_phase import get_log_parsing_phase
        logs = get_log_parsing_phase().recent_parsed(500)
        counts: Dict[str, int] = {}
        for p in logs:
            region = (p.get("geo") or {}).get("country", "未知")
            counts[region] = counts.get(region, 0) + 1
        out = []
        for region, cnt in counts.items():
            lat, lng = _REGION_LATLNG.get(region, (0, 0))
            out.append({"region": region, "count": cnt,
                        "lat": lat, "lng": lng})
        out.sort(key=lambda x: x["count"], reverse=True)
        return out

    # ------------------------------------------------------------------ #
    def top_attack_types(self, n: int = 8) -> List[Dict[str, Any]]:
        agg = self.agg.aggregate()
        items = sorted(agg["by_category"].items(),
                      key=lambda x: x[1], reverse=True)[:n]
        return [{"category": k, "count": v} for k, v in items]

    def severity_distribution(self) -> Dict[str, int]:
        return self.agg.aggregate()["by_severity"]

    def status_distribution(self) -> Dict[str, int]:
        return self.agg.aggregate()["by_status"]

    def rule_hit_top(self, n: int = 10) -> List[Dict[str, Any]]:
        return self.cor.rule_hit_top(n)

    # ------------------------------------------------------------------ #
    def response_stats(self) -> Dict[str, Any]:
        s = self.ir.stats()
        return {
            "avg_response_sec": s["avg_response_sec"],
            "sla_breach": s["sla_breach"],
            "playbook_runs": s["playbook_runs"],
            "ticket_open": s["open"],
            "ticket_resolved": s["resolved"],
        }

    # ------------------------------------------------------------------ #
    def recent_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self.agg.list_alerts(limit=limit)

    # ------------------------------------------------------------------ #
    def full_screen(self) -> Dict[str, Any]:
        return {
            "overview": self.overview(),
            "trend_24h": self.alert_trend("24h"),
            "trend_7d": self.alert_trend("7d"),
            "map": self.attack_map(),
            "top_types": self.top_attack_types(),
            "severity": self.severity_distribution(),
            "status": self.status_distribution(),
            "top_rules": self.rule_hit_top(10),
            "response": self.response_stats(),
            "recent_alerts": self.recent_alerts(15),
            "hunting": self.hunt.hunting_report(),
            "improvements": self.pm.improvement_track(),
        }


_default: Optional[SOCDashboard] = None


def get_dashboard() -> SOCDashboard:
    global _default
    if _default is None:
        _default = SOCDashboard()
    return _default
