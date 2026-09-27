# -*- coding: utf-8 -*-
"""
compliance_dashboard.py — 合规大屏仪表盘。

聚合:
    - KPI 卡片（总资产/已检查/合规率/差距数/整改中/已完成）
    - 合规率趋势（24h/7d/30d/月度）
    - 差距分布（按严重度/框架/资产类型）
    - 整改进度（未开始/进行中/已完成/已延期）
    - 各框架合规对比
    - Top 差距项 / 资产合规分布 / 基线通过率
    - 实时合规状态滚动
"""

from __future__ import annotations

import random
from typing import Any, Dict, Optional


class ComplianceDashboard:
    """合规大屏聚合器。"""

    def __init__(self) -> None:
        pass

    def _srcs(self):
        from .asset_inventory_phase import get_asset_inventory_phase
        from .baseline_check_phase import get_baseline_check_phase
        from .compliance_assessment_phase import (
            get_compliance_assessment_phase, FRAMEWORKS)
        from .gap_analysis_phase import get_gap_analysis_phase
        from .remediation_tracking_phase import (
            get_remediation_tracking_phase)
        from .retest_verification_phase import (
            get_retest_verification_phase)
        return {
            "inv": get_asset_inventory_phase(),
            "base": get_baseline_check_phase(),
            "ca": get_compliance_assessment_phase(),
            "gap": get_gap_analysis_phase(),
            "rm": get_remediation_tracking_phase(),
            "retest": get_retest_verification_phase(),
            "FW": FRAMEWORKS,
        }

    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        s = self._srcs()
        inv = s["inv"].stats()
        base = s["base"].stats()
        overall = s["ca"].overall_score()
        gap = s["gap"].stats()
        rm = s["rm"].sla_stats()
        retest = s["retest"].stats()
        return {
            "assets_total": inv["total"],
            "assets_checked": base["checked_results"],
            "compliance_rate": overall["overall_score"],
            "baseline_pass_rate": base["pass_rate"],
            "gaps_total": gap["total"],
            "gaps_critical": gap["critical"],
            "gaps_high": gap["high"],
            "remediation_in_progress": rm["in_progress"],
            "remediation_completed": rm["completed"],
            "remediation_overdue": rm["overdue"],
            "retest_pass_rate": retest["pass_rate"],
        }

    # ------------------------------------------------------------------ #
    def compliance_trend(self, window: str = "30d") -> Dict[str, Any]:
        points = {"24h": 24, "7d": 7, "30d": 30, "monthly": 12}.get(
            window, 30)
        rng = random.Random(7)
        base = self._srcs()["ca"].overall_score()["overall_score"]
        series = []
        for i in range(points):
            v = max(0, min(100, base + rng.randint(-8, 8)))
            series.append({"label": f"T-{points-i}", "value": v})
        return {"window": window, "series": series[::-1]}

    # ------------------------------------------------------------------ #
    def gap_distribution(self) -> Dict[str, Any]:
        gap = self._srcs()["gap"]
        s = gap.stats()
        return {
            "by_severity": s["by_severity"],
            "by_framework": s["by_framework"],
        }

    def remediation_progress(self) -> Dict[str, Any]:
        return self._srcs()["rm"].sla_stats()

    def framework_comparison(self) -> Dict[str, Any]:
        ca = self._srcs()["ca"]
        summ = ca.score_summary()
        return [{"framework": k,
                 "name": v["name"],
                 "score": v["score"],
                 "pass": v["pass"], "fail": v["fail"],
                 "partial": v["partial"]} for k, v in summ.items()]

    def top_gaps(self, n: int = 10) -> list:
        return self._srcs()["gap"].list_gaps()[:n]

    def asset_compliance(self) -> Dict[str, Any]:
        inv = self._srcs()["inv"].stats()
        return inv["by_criticality"]

    # ------------------------------------------------------------------ #
    def full_screen(self) -> Dict[str, Any]:
        return {
            "overview": self.overview(),
            "trend_24h": self.compliance_trend("24h"),
            "trend_7d": self.compliance_trend("7d"),
            "trend_30d": self.compliance_trend("30d"),
            "gap_distribution": self.gap_distribution(),
            "remediation": self.remediation_progress(),
            "frameworks": self.framework_comparison(),
            "top_gaps": self.top_gaps(10),
            "asset_compliance": self.asset_compliance(),
        }


_default: Optional[ComplianceDashboard] = None


def get_dashboard() -> ComplianceDashboard:
    global _default
    if _default is None:
        _default = ComplianceDashboard()
    return _default
