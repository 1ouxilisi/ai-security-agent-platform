#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar/soar_metrics.py — SOAR 运营度量。

覆盖指标：
    - MTTR 平均修复时间
    - 平均分诊时间 (MTTriage)
    - 自动化率 (automation rate)
    - 剧本执行成功率
    - 告警减少率（抑制/聚合）
    - 分析师效率（每分析师处理量）
    - SLA 达成率
    - 7/30 天趋势
    - 运营仪表盘
"""

from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional


class SOARMetrics:
    """SOAR 运营度量（内置确定性模拟序列，避免每次抖动）。"""

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)
        self.records: List[Dict[str, Any]] = []
        self._seed_history()

    # ---- 历史数据（7 天）----
    def _seed_history(self) -> None:
        base = int(time.time()) - 7 * 86400
        for i in range(7):
            day = time.strftime("%Y-%m-%d", time.localtime(base + i * 86400))
            alerts = self._rng.randint(380, 620)
            auto = int(alerts * self._rng.uniform(0.45, 0.7))
            triage = round(self._rng.uniform(4.5, 12.0), 1)
            mttr = round(self._rng.uniform(28.0, 95.0), 1)
            sla_hit = round(self._rng.uniform(0.82, 0.97) * 100, 1)
            self.records.append({
                "day": day, "alerts": alerts,
                "auto_remediated": auto,
                "automation_rate": round(auto / alerts * 100, 1),
                "avg_triage_min": triage,
                "mttr_min": mttr,
                "sla_achievement": sla_hit,
                "playbooks_run": self._rng.randint(60, 140),
                "playbook_success": round(self._rng.uniform(0.85, 0.98) * 100, 1),
                "fp_marked": self._rng.randint(20, 80),
                "cases_created": self._rng.randint(12, 40),
                "cases_closed": self._rng.randint(10, 35),
            })

    # ---- 当前汇总 ----
    def summary(self) -> Dict[str, Any]:
        rec = self.records[-1] if self.records else {}
        return {
            "as_of": time.strftime("%Y-%m-%d %H:%M:%S"),
            "today": rec,
            "kpis": {
                "mttr_min": rec.get("mttr_min", 0),
                "avg_triage_min": rec.get("avg_triage_min", 0),
                "automation_rate_pct": rec.get("automation_rate", 0),
                "playbook_success_pct": rec.get("playbook_success", 0),
                "sla_achievement_pct": rec.get("sla_achievement", 0),
                "alert_reduction_pct": round(100 - rec.get("automation_rate", 0) * 0.6, 1),
                "alerts_today": rec.get("alerts", 0),
                "cases_open": rec.get("cases_created", 0) - rec.get("cases_closed", 0),
            },
        }

    # ---- 趋势 ----
    def trend(self, days: int = 7) -> List[Dict[str, Any]]:
        return self.records[-days:]

    # ---- 分析师效率 ----
    def analyst_efficiency(self) -> List[Dict[str, Any]]:
        analysts = ["alice", "bob", "carol", "dave"]
        out = []
        for name in analysts:
            handled = self._rng.randint(40, 120)
            closed = int(handled * self._rng.uniform(0.75, 0.95))
            out.append({
                "analyst": name,
                "handled": handled,
                "closed": closed,
                "avg_handle_min": round(self._rng.uniform(18, 55), 1),
                "escalations": self._rng.randint(0, 5),
                "fp_marked": self._rng.randint(5, 30),
            })
        return sorted(out, key=lambda x: x["handled"], reverse=True)

    # ---- 剧本执行分布 ----
    def playbook_distribution(self) -> List[Dict[str, Any]]:
        rows = [
            ("rb.quick_isolate", "勒索软件快速隔离", 18),
            ("phish.quarantine_mail", "钓鱼邮件处置", 32),
            ("auth.bruteforce", "暴力破解响应", 27),
            ("malware.triage", "恶意软件分诊", 21),
            ("web.rce", "Web RCE 事件", 6),
            ("cloud.rogue_key", "云 AK 泄露", 4),
            ("general.triage", "通用分诊", 45),
        ]
        return [{"playbook_id": p, "name": n, "runs": r,
                 "success_rate": round(self._rng.uniform(0.8, 0.99) * 100, 1)}
                for p, n, r in rows]

    # ---- 仪表盘 ----
    def dashboard(self) -> Dict[str, Any]:
        s = self.summary()
        t = self.trend(7)
        return {
            "summary": s,
            "trend_7d": t,
            "analyst_efficiency": self.analyst_efficiency(),
            "playbook_distribution": self.playbook_distribution(),
            "targets": {
                "mttr_target_min": 60,
                "automation_rate_target_pct": 70,
                "sla_target_pct": 95,
                "playbook_success_target_pct": 95,
            },
        }


_SINGLETON: Optional[SOARMetrics] = None


def get_soar_metrics() -> SOARMetrics:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = SOARMetrics()
    return _SINGLETON


if __name__ == "__main__":  # pragma: no cover
    m = get_soar_metrics()
    print(m.summary()["kpis"])
