# -*- coding: utf-8 -*-
"""
risk_rating_phase.py — 云安全 Pro 阶段3：风险评级。

功能:
    - 根据配置错误打分（CVSS 风格加权）
    - critical/high/medium/low 四级
    - 风险评分 0-100
    - Top 风险项排序
    - 风险趋势分析（基于历史任务序列）
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SEVERITY_WEIGHT = {"critical": 40, "high": 15, "medium": 5, "low": 1}
SEVERITY_LABEL = {"critical": "严重", "high": "高危",
                  "medium": "中危", "low": "低危"}


@dataclass
class RiskRatingResult:
    score: int = 0                       # 0-100
    grade: str = "A"                     # A+ / A / B / C / D
    level: str = "low"                   # critical/high/medium/low
    by_severity: Dict[str, int] = field(default_factory=dict)
    top_risks: List[Dict[str, Any]] = field(default_factory=list)
    category_breakdown: Dict[str, int] = field(default_factory=dict)
    trend: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score, "grade": self.grade,
            "level": self.level,
            "by_severity": self.by_severity,
            "top_risks": self.top_risks,
            "category_breakdown": self.category_breakdown,
            "trend": self.trend,
            "notes": self.notes,
        }


class RiskRatingPhase:
    """风险评级。"""

    # 历史评分序列（内存），用于趋势分析
    _history: List[Dict[str, Any]] = []

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------ #
    def rate(self, findings: List[Dict[str, Any]],
             resource_count: int = 0,
             record_trend: bool = True) -> RiskRatingResult:
        res = RiskRatingResult()
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        cat: Dict[str, int] = {}

        for f in findings:
            s = f.get("severity", "low")
            sev[s] = sev.get(s, 0) + 1
            c = f.get("category", "其他")
            cat[c] = cat.get(c, 0) + 1

        res.by_severity = sev
        res.category_breakdown = cat

        # 加权分
        raw = sum(SEVERITY_WEIGHT.get(s, 0) * n
                  for s, n in sev.items())
        # 资源基数归一：资源越多基线越宽容，但有上限
        norm = raw
        score = max(0, min(100, int(round(100 - norm * 1.2))))
        # 至少严重项会把分拉低
        if sev["critical"] > 0:
            score = min(score, 40)
        res.score = score

        if score >= 90:
            res.grade, res.level = "A+", "low"
        elif score >= 75:
            res.grade, res.level = "A", "low"
        elif score >= 60:
            res.grade, res.level = "B", "medium"
        elif score >= 40:
            res.grade, res.level = "C", "high"
        else:
            res.grade, res.level = "D", "critical"

        if sev["critical"] > 0:
            res.level = "critical"
        elif sev["high"] > 0 and res.level != "critical":
            res.level = "high"

        # Top 风险排序
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ranked = sorted(
            findings,
            key=lambda f: (order.get(f.get("severity", "low"), 9),
                          -SEVERITY_WEIGHT.get(f.get("severity", "low"), 0)))
        res.top_risks = [
            {
                "rule_id": f.get("rule_id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "resource_id": f.get("resource_id"),
                "resource_type": f.get("resource_type"),
                "remediation": f.get("remediation"),
            }
            for f in ranked[:15]
        ]

        if not findings:
            res.notes.append("无配置风险项，评级基于空清单。")

        if record_trend:
            self._push_history(res.score, sev)
        res.trend = self._trend()
        return res

    # ------------------------------------------------------------------ #
    def _push_history(self, score: int, sev: Dict[str, int]) -> None:
        self._history.append({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "score": score,
            "critical": sev.get("critical", 0),
            "high": sev.get("high", 0),
        })
        if len(self._history) > 50:
            self._history = self._history[-50:]

    def _trend(self) -> Dict[str, Any]:
        if len(self._history) < 2:
            return {"direction": "flat", "samples": self._history[-5:],
                    "message": "样本不足，至少需两次评估才能给出趋势。"}
        recent = self._history[-5:]
        delta = recent[-1]["score"] - recent[0]["score"]
        direction = "improving" if delta > 2 else (
            "worsening" if delta < -2 else "flat")
        label = {"improving": "风险下降",
                 "worsening": "风险上升",
                 "flat": "持平"}[direction]
        return {"direction": direction, "delta": delta,
                "label": label, "samples": recent,
                "message": f"近 {len(recent)} 次评估评分变化 {delta:+d}（{label}）"}

    # ------------------------------------------------------------------ #
    def history(self) -> List[Dict[str, Any]]:
        return list(self._history)


_default_risk: Optional[RiskRatingPhase] = None


def get_risk_rating_phase() -> RiskRatingPhase:
    global _default_risk
    if _default_risk is None:
        _default_risk = RiskRatingPhase()
    return _default_risk
