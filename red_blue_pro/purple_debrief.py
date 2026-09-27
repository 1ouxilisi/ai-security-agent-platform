# -*- coding: utf-8 -*-
"""
purple_debrief.py — 紫队复盘。

功能:
    - 红队攻击 vs 蓝队检测对比
    - 差距分析（红队成功但蓝队未检测的项）
    - 改进建议（检测规则优化 / 响应流程优化 / 人员培训）
    - 成熟度评估
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GapItem:
    attack: str = ""
    detected: bool = False
    severity: str = "medium"
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"attack": self.attack, "detected": self.detected,
                "severity": self.severity,
                "recommendation": self.recommendation}


@dataclass
class PurpleDebriefResult:
    red_score: float = 0.0
    blue_score: float = 0.0
    coverage: float = 0.0
    gaps: List[GapItem] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    maturity: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "red_score": round(self.red_score, 1),
            "blue_score": round(self.blue_score, 1),
            "coverage": round(self.coverage, 1),
            "gap_count": len(self.gaps),
            "gaps": [g.to_dict() for g in self.gaps],
            "recommendations": self.recommendations,
            "maturity": self.maturity,
        }


class PurpleDebrief:
    """紫队复盘引擎。"""

    # ------------------------------------------------------------------ #
    def compare(self, red_stages: List[Dict[str, Any]],
                blue_alerts: List[Dict[str, Any]]
                ) -> PurpleDebriefResult:
        """红队每阶段成功项 vs 蓝队检测命中。"""
        r = PurpleDebriefResult()
        detected_set = {a.get("phase", "") for a in blue_alerts}
        gaps: List[GapItem] = []
        hit = 0
        for st in red_stages:
            name = st.get("name", st.get("stage", ""))
            ok = bool(st.get("success", True))
            detected = name in detected_set
            if ok and not detected:
                gaps.append(GapItem(
                    attack=name, detected=False,
                    severity=st.get("severity", "medium"),
                    recommendation=f"为「{name}」补充检测规则/日志采集"))
            elif ok and detected:
                hit += 1
        r.gaps = gaps
        total = max(1, len(red_stages))
        r.coverage = round(hit / total * 100, 1)
        r.red_score = round((len(red_stages) - len(gaps)) / total * 100, 1)
        r.blue_score = r.coverage
        # 改进建议
        recs = []
        if any(g.severity == "critical" for g in gaps):
            recs.append("优先补齐 critical 级未检测项的 Suricata/Sigma 规则")
        if r.coverage < 50:
            recs.append("覆盖率不足 50%：建议扩大日志采集范围与 SIEM 规则")
        recs.append("开展定期红蓝对抗演练，每季度一次")
        recs.append("蓝队人员培训：ATT&CK T1059/T1021/T1005 检测")
        r.recommendations = recs
        # 成熟度
        r.maturity = {
            "level": "初始级" if r.coverage < 40 else
                     "基础级" if r.coverage < 70 else
                     "进阶级" if r.coverage < 90 else "优化级",
            "detection": r.coverage,
            "response": 70,
            "training": 60,
            "metrics": r.coverage,
        }
        return r

    # ------------------------------------------------------------------ #
    def maturity_assessment(self) -> Dict[str, Any]:
        return {
            "levels": ["初始级", "基础级", "进阶级", "优化级", "引领级"],
            "current": "基础级",
            "domains": {
                "检测能力": "基础级",
                "响应能力": "进阶级",
                "溯源能力": "初始级",
                "人员培训": "基础级",
            },
        }


_default: Optional[PurpleDebrief] = None


def get_purple_debrief() -> PurpleDebrief:
    global _default
    if _default is None:
        _default = PurpleDebrief()
    return _default
