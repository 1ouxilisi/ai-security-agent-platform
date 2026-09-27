#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
operational_efficiency.py — 安全运营效率度量。

覆盖：
    - MTTD / MTTR / MTRS（平均检测/响应/解决时间）
    - 告警量趋势、误报率、自动化率、分析师工作量
    - 工单 SLA 达成、资源利用率
"""

from __future__ import annotations

import math
import time
from typing import Any, Dict, List, Optional


class OperationalEfficiencyMetrics:
    """安全运营效率度量器（全内存模拟）。"""

    def __init__(self) -> None:
        self._analysts = 12
        self._tickets: List[Dict[str, Any]] = self._seed_tickets()

    # ------------------------------------------------------------------ #
    # 时效指标
    # ------------------------------------------------------------------ #
    def mt_metrics(self, period_months: int = 12) -> Dict[str, Any]:
        now = time.time()
        labels, mttd, mttr, mtrs = [], [], [], []
        for i in range(period_months):
            t = now - (period_months - i) * 30 * 86400
            labels.append(time.strftime("%Y-%m", time.localtime(t)))
            # 模拟：随时间下降（运营成熟度提升）
            decay = i * 0.35
            mttd.append(round(max(0.8, 8.0 - decay + math.sin(i) * 0.8), 2))
            mttr.append(round(max(0.5, 4.5 - decay * 0.5 + math.cos(i) * 0.6), 2))
            mtrs.append(round(max(4.0, 48.0 - decay * 2.0 + math.sin(i / 2) * 4), 2))
        return {
            "unit": "小时(h)", "periods": labels,
            "MTTD": {"series": mttd, "latest": mttd[-1], "target": 4.0},
            "MTTR": {"series": mttr, "latest": mttr[-1], "target": 2.0},
            "MTRS": {"series": mtrs, "latest": mtrs[-1], "target": 24.0},
            "interpretation": "MTTD<MTTR<MTRS 为健康阶梯；MTTD 越低说明检测越灵敏。",
        }

    # ------------------------------------------------------------------ #
    # 告警运营
    # ------------------------------------------------------------------ #
    def alert_metrics(self, period_months: int = 12) -> Dict[str, Any]:
        now = time.time()
        labels, total, fp, auto = [], [], [], []
        for i in range(period_months):
            t = now - (period_months - i) * 30 * 86400
            labels.append(time.strftime("%Y-%m", time.localtime(t)))
            base = 12000 - i * 180 + math.sin(i / 1.5) * 600
            total.append(max(3000, round(base)))
            fp.append(round(max(12.0, 48.0 - i * 2.5 + math.cos(i) * 2), 1))
            auto.append(round(min(92.0, 22.0 + i * 5.5), 1))
        return {
            "periods": labels,
            "alert_volume": {"series": total, "latest": total[-1], "unit": "条/月"},
            "false_positive_rate": {"series": fp, "latest": fp[-1], "target_max": 20.0, "unit": "%"},
            "automation_rate": {"series": auto, "latest": auto[-1], "target_min": 60.0, "unit": "%"},
            "noise_reduction": round((total[0] - total[-1]) / total[0] * 100, 1),
        }

    # ------------------------------------------------------------------ #
    # 分析师工作量
    # ------------------------------------------------------------------ #
    def analyst_workload(self) -> Dict[str, Any]:
        per_analyst = [round(22 + (a % 5) * 2 + math.sin(a) * 3, 1)
                       for a in range(self._analysts)]
        avg = round(sum(per_analyst) / len(per_analyst), 1)
        return {
            "analyst_count": self._analysts,
            "per_analyst_daily_tickets": per_analyst,
            "average_daily_per_analyst": avg,
            "overload_threshold": 30,
            "overloaded_count": sum(1 for v in per_analyst if v > 30),
            "utilization_pct": round(min(98.0, avg / 30 * 100), 1),
            "capacity_note": "人均日研判 >30 单视为过载，需扩编或提升自动化率。",
        }

    # ------------------------------------------------------------------ #
    # 工单 SLA
    # ------------------------------------------------------------------ #
    def _seed_tickets(self) -> List[Dict[str, Any]]:
        levels = ["P1", "P2", "P3", "P4"]
        sla = {"P1": 4, "P2": 24, "P3": 72, "P4": 168}
        out: List[Dict[str, Any]] = []
        now = time.time()
        for i in range(120):
            lv = levels[i % 4]
            took = round(sla[lv] * (0.4 + ((i * 37) % 130) / 100.0), 1)
            out.append({
                "ticket_id": f"INC-{1000 + i}", "level": lv,
                "sla_hours": sla[lv], "actual_hours": took,
                "met": took <= sla[lv],
                "created_at": time.strftime("%Y-%m-%d",
                    time.localtime(now - i * 3600 * 7)),
            })
        return out

    def ticket_sla(self) -> Dict[str, Any]:
        by_level: Dict[str, Dict[str, float]] = {}
        for t in self._tickets:
            d = by_level.setdefault(t["level"], {"total": 0, "met": 0, "sum_hours": 0.0})
            d["total"] += 1
            d["met"] += 1 if t["met"] else 0
            d["sum_hours"] += t["actual_hours"]
        rows = []
        total_met = total_all = 0
        for lv, d in by_level.items():
            rate = round(d["met"] / d["total"] * 100, 1)
            rows.append({"level": lv, "total": d["total"], "met": d["met"],
                         "sla_rate": rate,
                         "avg_actual_hours": round(d["sum_hours"] / d["total"], 1)})
            total_met += d["met"]
            total_all += d["total"]
        return {
            "total_tickets": total_all, "total_met": total_met,
            "overall_sla_rate": round(total_met / total_all * 100, 1),
            "by_level": rows,
            "target_sla_rate": 95.0,
        }

    # ------------------------------------------------------------------ #
    # 资源利用率
    # ------------------------------------------------------------------ #
    def resource_utilization(self) -> Dict[str, Any]:
        tools = ["SIEM", "SOAR", "EDR", "NDR", "TA(威胁情报)", "漏洞管理"]
        return {
            "tools": [
                {"tool": t, "usage_pct": round(55 + (i * 13) % 42 + math.sin(i) * 5, 1),
                 "licensed_seats": 50 + i * 20}
                for i, t in enumerate(tools)
            ],
            "human_fte": self._analysts,
            "shift_coverage_pct": 92.0,
            "notes": "工具使用率 <60% 建议整合下线；值班覆盖率应保持 100%。",
        }

    def summary(self) -> Dict[str, Any]:
        mt = self.mt_metrics(12)
        al = self.alert_metrics(12)
        sla = self.ticket_sla()
        return {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "MTTD_latest_h": mt["MTTD"]["latest"],
            "MTTR_latest_h": mt["MTTR"]["latest"],
            "MTRS_latest_h": mt["MTRS"]["latest"],
            "false_positive_rate_pct": al["false_positive_rate"]["latest"],
            "automation_rate_pct": al["automation_rate"]["latest"],
            "sla_achievement_pct": sla["overall_sla_rate"],
            "overloaded_analysts": self.analyst_workload()["overloaded_count"],
            "health_score": round(
                max(0, min(100,
                    100 - (al["false_positive_rate"]["latest"] - 20) * 1.5
                    - max(0, 60 - al["automation_rate"]["latest"]) * 0.5
                    - max(0, 95 - sla["overall_sla_rate"]) * 1.2)), 1),
        }
