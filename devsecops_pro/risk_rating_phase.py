# -*- coding: utf-8 -*-
"""
risk_rating_phase.py — 阶段8：风险评级。

功能:
    - 根据代码漏洞 + 密钥泄露 + 配置错误打分
    - critical/high/medium/low 四级
    - 风险评分（0-100）
    - Top 风险项排序
    - 风险趋势分析
    - 安全成熟度评估
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RiskRating:
    score: int = 0
    level: str = "low"  # critical / high / medium / low
    maturity: str = ""
    summary: str = ""
    top_risks: List[Dict[str, Any]] = field(default_factory=list)
    breakdown: Dict[str, Any] = field(default_factory=dict)
    trend: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score, "level": self.level,
            "maturity": self.maturity, "summary": self.summary,
            "top_risks": self.top_risks,
            "breakdown": self.breakdown,
            "trend": self.trend,
        }


SEVERITY_WEIGHT = {
    "critical": 25, "high": 10, "medium": 3, "low": 1,
}


class RiskRatingPhase:
    """阶段8：风险评级。"""

    def __init__(self) -> None:
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    def rate(self,
             sast: Dict[str, Any],
             sca: Dict[str, Any],
             secrets: Dict[str, Any],
             iac: Dict[str, Any],
             container: Dict[str, Any]) -> RiskRating:
        r = RiskRating()

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        all_findings: List[Dict[str, Any]] = []

        def _collect(findings: List[Dict[str, Any]],
                     source: str) -> None:
            for f in findings:
                sev = str(f.get("severity", "low")).lower()
                if sev in counts:
                    counts[sev] += 1
                item = dict(f)
                item["_source"] = source
                all_findings.append(item)

        _collect(sast.get("findings", []), "SAST")
        _collect(sca.get("findings", []), "SCA")
        _collect(secrets.get("findings", []), "Secrets")
        _collect(iac.get("findings", []), "IaC")
        _collect(container.get("findings", []), "Container")

        # 评分：从 100 扣分
        score = 100
        for sev, w in SEVERITY_WEIGHT.items():
            score -= counts[sev] * w
        score = max(0, min(100, score))
        r.score = score

        # 等级
        if score >= 85:
            r.level = "low"
        elif score >= 65:
            r.level = "medium"
        elif score >= 40:
            r.level = "high"
        else:
            r.level = "critical"

        # 成熟度
        if score >= 85:
            r.maturity = "优秀（Leader）"
        elif score >= 70:
            r.maturity = "良好（Managed）"
        elif score >= 50:
            r.maturity = "合规（Defined）"
        elif score >= 30:
            r.maturity = "起步（Initial）"
        else:
            r.maturity = "危险（Chaotic）"

        # Top 风险排序
        def _weight(item: Dict[str, Any]) -> int:
            sev = str(item.get("severity", "low")).lower()
            return SEVERITY_WEIGHT.get(sev, 0)

        sorted_items = sorted(all_findings, key=_weight, reverse=True)
        r.top_risks = [
            {
                "source": it.get("_source"),
                "severity": it.get("severity"),
                "title": (it.get("message") or it.get("description")
                          or it.get("title") or it.get("cve")
                          or it.get("rule_id") or it.get("kind") or "-")[:120],
                "path": it.get("path") or it.get("file") or it.get("artifact", ""),
                "line": it.get("line", 0),
            }
            for it in sorted_items[:10]
        ]

        r.breakdown = {
            "counts": counts,
            "sast_count": len(sast.get("findings", [])),
            "sca_count": len(sca.get("findings", [])),
            "secrets_count": len(secrets.get("findings", [])),
            "iac_count": len(iac.get("findings", [])),
            "container_count": len(container.get("findings", [])),
        }

        r.summary = (
            f"综合风险评分 {score}/100，等级 {r.level}，"
            f"成熟度 {r.maturity}。"
            f"Critical {counts['critical']} / High {counts['high']} / "
            f"Medium {counts['medium']} / Low {counts['low']}。")

        # 历史趋势
        self._history.append({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "score": score, "level": r.level,
            **counts,
        })
        r.trend = self._history[-20:]
        return r

    # ------------------------------------------------------------------ #
    def trend_history(self) -> List[Dict[str, Any]]:
        return list(self._history)


_default: Optional[RiskRatingPhase] = None


def get_risk_phase() -> RiskRatingPhase:
    global _default
    if _default is None:
        _default = RiskRatingPhase()
    return _default
