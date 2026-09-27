#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_metrics_deep/security_efficiency.py — 安全效能度量。

能力：
    1. 安全团队效能：人均漏洞修复/事件处理/扫描/报告/培训数，团队产出与效率。
    2. 安全流程效能：修复时间/响应时间/扫描周期/报告周期/审批周期/培训周期/瓶颈。
    3. 安全技术效能：扫描覆盖率/检测准确率/误报率/漏报率/自动化率/工具利用率。
    4. 安全质量度量：漏洞/事件/报告/修复/培训/合规质量与趋势。
    5. 安全效率度量：自动化程度/人工干预率/重复工作率/工具集成度/标准化/知识复用。
    6. 安全效能改进：瓶颈识别/改进机会/计划/效果/最佳实践/基准对比。
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional


def _h(seed: str, mod: int = 100) -> int:
    return int(hashlib.md5(seed.encode("utf-8")).hexdigest()[:8], 16) % mod


def _v(seed: str, lo: float, hi: float) -> float:
    return round(lo + (hi - lo) * _h(seed) / 100.0, 1)


class EfficiencyManager:
    def __init__(self) -> None:
        self.team_size = 12

    # -- 团队效能 -- #
    def team_efficiency(self) -> Dict[str, Any]:
        size = self.team_size
        total = {
            "修复漏洞数": 240, "处理事件数": 86, "完成扫描数": 320,
            "产出报告数": 48, "组织培训场次": 18,
        }
        per_capita = {k: round(v / size, 1) for k, v in total.items()}
        return {
            "team_size": size,
            "total_output": total,
            "per_capita_output": per_capita,
            "team_productivity_index": _v("prod", 65, 95),
            "team_efficiency_score": _v("eff", 60, 92),
        }

    # -- 流程效能 -- #
    def process_efficiency(self) -> Dict[str, Any]:
        rows = [
            {"process": "漏洞修复", "cycle_hours": _v("p1", 24, 240), "target_hours": 168},
            {"process": "事件响应", "cycle_hours": _v("p2", 0.5, 8), "target_hours": 4},
            {"process": "漏洞扫描", "cycle_hours": _v("p3", 6, 48), "target_hours": 24},
            {"process": "报告生成", "cycle_hours": _v("p4", 4, 72), "target_hours": 48},
            {"process": "变更审批", "cycle_hours": _v("p5", 2, 24), "target_hours": 12},
            {"process": "安全培训", "cycle_hours": _v("p6", 8, 40), "target_hours": 24},
        ]
        for r in rows:
            r["on_time"] = r["cycle_hours"] <= r["target_hours"]
        bottlenecks = [r["process"] for r in rows if not r["on_time"]]
        return {"processes": rows, "bottlenecks": bottlenecks,
                "on_time_rate": round(
                    sum(1 for r in rows if r["on_time"]) / len(rows) * 100, 1)}

    # -- 技术效能 -- #
    def tech_efficiency(self) -> Dict[str, Any]:
        return {
            "scan_coverage": _v("t1", 70, 100),
            "detection_accuracy": _v("t2", 60, 95),
            "false_positive_rate": _v("t3", 5, 35),
            "false_negative_rate": _v("t4", 2, 20),
            "automation_rate": _v("t5", 40, 90),
            "tool_utilization": _v("t6", 50, 95),
            "tech_roi": _v("t7", 30, 110),
            "bottlenecks": ["误报率偏高，需优化检测规则", "部分工具未打通，人工搬运数据"],
        }

    # -- 质量度量 -- #
    def quality(self) -> Dict[str, Any]:
        dims = ["漏洞质量", "事件质量", "报告质量", "修复质量", "培训质量", "合规质量"]
        rows = [{"dimension": d, "score": _v("q" + d, 60, 96),
                 "trend": "上升" if _h("qtr" + d) > 40 else "平稳"} for d in dims]
        overall = round(sum(r["score"] for r in rows) / len(rows), 1)
        return {"dimensions": rows, "overall_quality": overall}

    # -- 效率度量 -- #
    def efficiency(self) -> Dict[str, Any]:
        return {
            "automation_level": _v("e1", 40, 90),
            "manual_intervention_rate": _v("e2", 10, 50),
            "repeated_work_rate": _v("e3", 5, 35),
            "tool_integration_degree": _v("e4", 50, 95),
            "process_standardization": _v("e5", 55, 95),
            "knowledge_reuse_rate": _v("e6", 40, 90),
            "improvement_rate": _v("e7", 5, 30),
            "bottlenecks": ["跨工具数据未自动同步", "应急预案知识沉淀不足"],
        }

    # -- 效能改进 -- #
    def improvement(self) -> Dict[str, Any]:
        pe = self.process_efficiency()
        te = self.tech_efficiency()
        opps = []
        for b in pe["bottlenecks"]:
            opps.append({"area": b, "type": "流程瓶颈",
                         "action": f"优化{b}流程，缩短周期并SLA达标",
                         "expected_gain": "周期缩短 20-30%"})
        for b in te["bottlenecks"]:
            opps.append({"area": "技术", "type": "技术瓶颈",
                         "action": b, "expected_gain": "误报下降、自动化率提升"})
        return {
            "identified_bottlenecks": pe["bottlenecks"] + te["bottlenecks"],
            "opportunities": opps,
            "plan": [
                {"phase": "0-3月", "focus": "清理高误报规则，打通SIEM-工单链路"},
                {"phase": "3-6月", "focus": "沉淀应急预案与知识库，提升复用"},
                {"phase": "6-12月", "focus": "全面自动化编排，目标自动化率>70%"},
            ],
            "best_practices": ["自动化优先", "数据一处录入多处复用", "季度效能复盘"],
            "benchmark": {
                "your_score": self.team_efficiency()["team_efficiency_score"],
                "industry_median": 70.0,
                "industry_top": 90.0,
            },
        }

    # -- 综合总览 -- #
    def overview(self) -> Dict[str, Any]:
        return {
            "team": self.team_efficiency(),
            "process": self.process_efficiency(),
            "tech": self.tech_efficiency(),
            "quality": self.quality(),
            "efficiency": self.efficiency(),
        }


_eff: Optional[EfficiencyManager] = None


def get_efficiency_manager() -> EfficiencyManager:
    global _eff
    if _eff is None:
        _eff = EfficiencyManager()
    return _eff
