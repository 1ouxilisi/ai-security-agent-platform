# -*- coding: utf-8 -*-
"""
risk_rating_phase.py — 阶段8：风险评级。

综合数据敏感度 + 访问风险 + 合规风险 + 加密风险打分（0-100），
critical/high/medium/low 四级；Top 风险排序 / 趋势 / 成熟度 / 风险矩阵。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


LEVELS = ["critical", "high", "medium", "low"]
LEVEL_COLOR = {
    "critical": "#e74c3c", "high": "#e67e22",
    "medium": "#f1c40f", "low": "#2ecc71",
}

MATURITY_LEVELS = [
    (1, "初始级", "无系统化数据安全治理"),
    (2, "重复级", "零散控制点，依赖个人"),
    (3, "已定义级", "有制度与流程，部分落地"),
    (4, "量化管理级", "指标量化、持续度量"),
    (5, "优化级", "自动化闭环、持续优化"),
]


@dataclass
class RiskItem:
    risk_id: str
    title: str
    category: str
    score: int
    level: str
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_id": self.risk_id, "title": self.title,
            "category": self.category, "score": self.score,
            "level": self.level, "detail": self.detail,
        }


class RiskRatingPhase:
    """阶段8：风险评级。"""

    def __init__(self) -> None:
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    @staticmethod
    def _level_of(score: int) -> str:
        if score >= 85:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 50:
            return "medium"
        return "low"

    # ------------------------------------------------------------------ #
    def compute(self,
                discovery: Optional[Dict[str, Any]] = None,
                classification: Optional[Dict[str, Any]] = None,
                dlp: Optional[Dict[str, Any]] = None,
                compliance: Optional[Dict[str, Any]] = None,
                encryption: Optional[Dict[str, Any]] = None,
                access: Optional[Dict[str, Any]] = None,
                ) -> Dict[str, Any]:
        """综合打分。各子项都是 dict；缺省给中性分。"""
        # 子项分（0-100，越高越危险）
        sens = (classification or {}).get("by_level", {})
        sens_score = min(
            100,
            sens.get("top_secret", 0) * 8
            + sens.get("confidential", 0) * 4
            + sens.get("internal", 0) * 2)

        dlp_s = dlp or {}
        dlp_score = min(100,
                        dlp_s.get("alerts_by_level", {}).get("critical", 0) * 20
                        + dlp_s.get("alerts_by_level", {}).get("high", 0) * 8)

        comp_s = compliance or {}
        comp_score = 100 - comp_s.get("overall_score", 60)

        enc_s = encryption or {}
        enc_score = enc_s.get("coverage", {}).get("avg_risk", 40)

        acc_s = access or {}
        acc_score = acc_s.get("risk_score", 0)

        overall = round(
            sens_score * 0.25 + dlp_score * 0.25 + comp_score * 0.2
            + enc_score * 0.15 + acc_score * 0.15, 1)
        overall_level = self._level_of(int(overall))

        # Top 风险项
        items: List[RiskItem] = [
            RiskItem("R-SENS", "敏感数据暴露面", "数据敏感度",
                     int(sens_score), self._level_of(int(sens_score)),
                     f"Top Secret {sens.get('top_secret',0)} / "
                     f"Confidential {sens.get('confidential',0)}"),
            RiskItem("R-DLP", "DLP 告警压力", "DLP",
                     int(dlp_score), self._level_of(int(dlp_score)),
                     f"critical {dlp_s.get('alerts_by_level',{}).get('critical',0)}"),
            RiskItem("R-COMP", "合规不符合", "隐私合规",
                     int(comp_score), self._level_of(int(comp_score)),
                     f"整体合规分 {comp_s.get('overall_score', '-')}"),
            RiskItem("R-ENC", "加密弱点", "加密密钥",
                     int(enc_score), self._level_of(int(enc_score)),
                     "弱算法/未加密字段统计"),
            RiskItem("R-ACC", "访问异常", "访问审计",
                     int(acc_score), self._level_of(int(acc_score)),
                     "异常访问/批量导出"),
        ]
        items.sort(key=lambda x: x.score, reverse=True)

        maturity = self._maturity(overall)
        rec = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "overall_score": overall, "overall_level": overall_level,
            "sub_scores": {
                "sensitivity": round(sens_score, 1),
                "dlp": round(dlp_score, 1),
                "compliance_gap": round(comp_score, 1),
                "encryption": round(enc_score, 1),
                "access": round(acc_score, 1),
            },
            "top_risks": [i.to_dict() for i in items],
            "maturity": maturity,
        }
        self._history.append(rec)
        return rec

    # ------------------------------------------------------------------ #
    def _maturity(self, score: float) -> Dict[str, Any]:
        if score >= 80:
            lvl = 1
        elif score >= 65:
            lvl = 2
        elif score >= 50:
            lvl = 3
        elif score >= 35:
            lvl = 4
        else:
            lvl = 5
        code, name, desc = MATURITY_LEVELS[lvl - 1]
        return {"level": code, "name": name, "description": desc}

    # ------------------------------------------------------------------ #
    def trend(self, limit: int = 10) -> List[Dict[str, Any]]:
        return list(self._history[-limit:])

    def history(self) -> List[Dict[str, Any]]:
        return list(self._history)


_default_phase: Optional[RiskRatingPhase] = None


def get_risk_rating_phase() -> RiskRatingPhase:
    global _default_phase
    if _default_phase is None:
        _default_phase = RiskRatingPhase()
    return _default_phase


__all__ = [
    "RiskRatingPhase", "RiskItem", "get_risk_rating_phase",
    "LEVELS", "LEVEL_COLOR", "MATURITY_LEVELS",
]
