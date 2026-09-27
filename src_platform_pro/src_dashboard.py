# -*- coding: utf-8 -*-
"""
src_dashboard.py — SRC 大屏仪表盘。

聚合:
    - KPI（总漏洞/待审核/修复中/已修复/白帽数/企业数/总赏金）
    - 漏洞趋势 / 类型分布 / 严重程度分布
    - 白帽排名 / 企业安全态势 / 修复时效 / 赏金统计 / 实时漏洞流
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional


class SRCDashboard:
    """SRC 大屏聚合器。"""

    def __init__(self) -> None:
        from .platform_management_phase import \
            get_platform_management_phase
        from .vulnerability_submission_phase import get_submission_phase
        from .vulnerability_review_phase import get_review_phase
        from .bounty_management_phase import get_bounty_phase
        from .enterprise_portal_phase import get_enterprise_phase
        from .data_analysis_phase import get_analysis_phase
        self.pm = get_platform_management_phase()
        self.sub = get_submission_phase()
        self.rev = get_review_phase()
        self.bm = get_bounty_phase()
        self.ent = get_enterprise_phase()
        self.ana = get_analysis_phase()

    # ------------------------------------------------------------------ #
    def kpi(self) -> Dict[str, Any]:
        vs = self.sub.list(limit=1000)
        s = self.sub.stats()
        pm = self.pm.stats()
        bounty = self.bm.stats()
        return {
            "total_vulns": s["total"],
            "pending_review": s["by_status"].get("reviewing", 0) +
            s["by_status"].get("submitted", 0),
            "fixing": s["by_status"].get("fixing", 0),
            "fixed": s["by_status"].get("fixed", 0),
            "hackers": pm["hackers_total"],
            "enterprises": pm["enterprises_total"],
            "total_bounty": bounty["total_gross"],
            "critical": s["by_severity"].get("critical", 0),
            "high": s["by_severity"].get("high", 0),
        }

    def trend(self, window: str = "24h") -> Dict[str, Any]:
        return self.ana.trend(window)

    def type_distribution(self) -> Dict[str, int]:
        return self.ana.type_distribution()

    def severity_distribution(self) -> Dict[str, int]:
        return self.ana.severity_distribution()

    def hacker_ranking(self) -> List[Dict[str, Any]]:
        return self.bm.leaderboard("bounty", limit=10)

    def fix_efficiency(self) -> Dict[str, Any]:
        return self.ana.fix_efficiency()

    def bounty_stats(self) -> Dict[str, Any]:
        return self.bm.stats()

    def enterprise_posture(self) -> Dict[str, Any]:
        ents = self.pm.list_enterprises()
        if not ents:
            return {"enterprises": 0}
        eid = ents[0]["enterprise_id"]
        d = self.ent.dashboard(eid)
        return {"enterprise_id": eid, "count": len(ents),
                "avg_score": d["security_score"],
                "fix_rate": d["fix_rate"]}

    def recent_vulns(self, limit: int = 15) -> List[Dict[str, Any]]:
        return self.sub.list(limit=limit)

    # ------------------------------------------------------------------ #
    def full_screen(self) -> Dict[str, Any]:
        return {
            "kpi": self.kpi(),
            "trend_24h": self.trend("24h"),
            "trend_7d": self.trend("7d"),
            "trend_30d": self.trend("30d"),
            "type_distribution": self.type_distribution(),
            "severity_distribution": self.severity_distribution(),
            "hacker_ranking": self.hacker_ranking(),
            "fix_efficiency": self.fix_efficiency(),
            "bounty_stats": {
                "total_gross": self.bounty_stats()["total_gross"],
                "by_month": self.bounty_stats()["by_month"],
            },
            "enterprise_posture": self.enterprise_posture(),
            "recent_vulns": self.recent_vulns(15),
            "risk": self.ana.risk_assessment(),
        }


_default: Optional[SRCDashboard] = None


def get_dashboard() -> SRCDashboard:
    global _default
    if _default is None:
        _default = SRCDashboard()
    return _default
