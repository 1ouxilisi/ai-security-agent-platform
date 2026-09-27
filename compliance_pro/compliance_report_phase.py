# -*- coding: utf-8 -*-
"""
compliance_report_phase.py — 阶段7：合规报告（结构化内容组装）。

组装:
    执行摘要 / 合规状态总览 / 各框架详情 / 差距清单 /
    整改建议 / 整改进度 / 证据附件 / 附录
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class ComplianceReportPhase:
    """阶段7：合规审计报告内容组装。"""

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------ #
    def build(self) -> Dict[str, Any]:
        from .asset_inventory_phase import get_asset_inventory_phase
        from .baseline_check_phase import get_baseline_check_phase
        from .compliance_assessment_phase import (
            get_compliance_assessment_phase, FRAMEWORKS)
        from .gap_analysis_phase import get_gap_analysis_phase
        from .remediation_tracking_phase import (
            get_remediation_tracking_phase)
        from .retest_verification_phase import (
            get_retest_verification_phase)

        inv = get_asset_inventory_phase()
        base = get_baseline_check_phase()
        ca = get_compliance_assessment_phase()
        gap = get_gap_analysis_phase()
        rm = get_remediation_tracking_phase()
        retest = get_retest_verification_phase()

        overall = ca.overall_score()
        gap_stats = gap.stats()
        rm_stats = rm.sla_stats()
        retest_stats = retest.stats()

        return {
            "executive_summary": {
                "overall_score": overall["overall_score"],
                "asset_total": inv.stats()["total"],
                "baseline_pass_rate": base.stats()["pass_rate"],
                "gap_total": gap_stats["total"],
                "critical": gap_stats["critical"],
                "high": gap_stats["high"],
                "remediation_done": rm_stats["completed"],
                "remediation_overdue": rm_stats["overdue"],
                "retest_pass_rate": retest_stats["pass_rate"],
            },
            "frameworks": overall["frameworks"],
            "gap_top": gap.list_gaps()[:20],
            "remediation": rm.progress_report(),
            "retest": retest_stats,
            "asset_summary": inv.stats(),
            "baseline_stats": base.stats(),
            "framework_names": {k: v["name"] for k, v in FRAMEWORKS.items()},
        }


_default: Optional[ComplianceReportPhase] = None


def get_compliance_report_phase() -> ComplianceReportPhase:
    global _default
    if _default is None:
        _default = ComplianceReportPhase()
    return _default
