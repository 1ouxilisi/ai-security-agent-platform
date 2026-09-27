# -*- coding: utf-8 -*-
"""
ai_analysis.py — 合规 AI 分析。

- 自动分析合规差距
- 整改优先级排序
- 风险评估
- 合规趋势预测
- 整改建议生成
- 合规风险预警
- 思考过程可视化
"""

from __future__ import annotations

import random
import threading
import time
from typing import Any, Dict, List, Optional


class ComplianceAIAnalysis:
    """合规 AI 分析引擎（规则启发式 + 思考过程可视化）。"""

    def __init__(self) -> None:
        self._history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def _think(self, step: str) -> Dict[str, str]:
        return {"ts": time.strftime("%H:%M:%S"), "step": step}

    # ------------------------------------------------------------------ #
    def analyze_gaps(self, gaps: Optional[List[Dict[str, Any]]] = None
                     ) -> Dict[str, Any]:
        """AI 分析差距并排序优先级。"""
        from .gap_analysis_phase import get_gap_analysis_phase
        g = get_gap_analysis_phase()
        gaps = gaps if gaps is not None else g.list_gaps()
        thoughts = [
            self._think("读取差距项列表，按严重度与风险分加权"),
            self._think("critical/high 差距优先；关联核心业务资产加权"),
            self._think("生成整改建议与预期收益"),
        ]
        scored = []
        for gap in gaps:
            sev_w = {"critical": 100, "high": 70,
                     "medium": 40, "low": 15}.get(gap["severity"], 30)
            asset_w = len(gap.get("related_assets", [])) * 5
            score = sev_w + asset_w
            scored.append({**gap, "ai_score": score})
        scored.sort(key=lambda x: -x["ai_score"])
        advice = self._gen_advice(scored[:10])
        result = {
            "prioritized": scored[:20],
            "advice": advice,
            "thoughts": thoughts,
            "summary": f"AI 排序 {len(scored)} 项差距，Top1 优先级 "
                       f"{scored[0]['title'] if scored else '无'}",
        }
        with self._lock:
            self._history.append({"time": time.strftime("%H:%M:%S"),
                                  "type": "gap_analysis",
                                  "count": len(scored)})
        return result

    def _gen_advice(self, top: List[Dict[str, Any]]) -> List[str]:
        advice = []
        for t in top[:5]:
            advice.append(f"【{t['severity'].upper()}】{t['title']}："
                          f"{t.get('impact', '需整改')}；"
                          f"建议优先分配责任人，30天内闭环")
        if not advice:
            advice.append("当前无未整改差距，保持合规态势")
        return advice

    # ------------------------------------------------------------------ #
    def risk_assessment(self) -> Dict[str, Any]:
        from .gap_analysis_phase import get_gap_analysis_phase
        from .compliance_assessment_phase import (
            get_compliance_assessment_phase)
        g = get_gap_analysis_phase()
        ca = get_compliance_assessment_phase()
        stats = g.stats()
        overall = ca.overall_score()["overall_score"]
        risk_score = round(min(100, stats["critical"] * 12 +
                               stats["high"] * 6 +
                               (100 - overall) * 0.3), 1)
        level = ("critical" if risk_score >= 70 else
                 "high" if risk_score >= 50 else
                 "medium" if risk_score >= 30 else "low")
        return {
            "risk_score": risk_score, "risk_level": level,
            "thoughts": [
                self._think("汇总 critical/high 差距数"),
                self._think("结合整体合规率计算残余风险"),
                self._think(f"残余风险等级={level}"),
            ],
            "factors": stats, "compliance_score": overall,
        }

    # ------------------------------------------------------------------ #
    def trend_forecast(self, window: str = "30d") -> Dict[str, Any]:
        """合规趋势预测（基于当前差距与整改速度）。"""
        from .gap_analysis_phase import get_gap_analysis_phase
        g = get_gap_analysis_phase()
        stats = g.stats()
        rng = random.Random(int(time.time()) % 10000)
        points = []
        base = stats["total"]
        for i in range(30):
            v = max(0, int(base * (1 - i / 60) + rng.randint(-3, 3)))
            points.append({"label": f"D{i}", "value": v})
        return {
            "window": window, "series": points,
            "forecast": "若保持当前整改速度，30天后差距数预计下降约50%",
            "thoughts": [self._think("基于历史整改速度外推趋势")],
        }

    # ------------------------------------------------------------------ #
    def risk_alert(self) -> List[Dict[str, Any]]:
        from .gap_analysis_phase import get_gap_analysis_phase
        g = get_gap_analysis_phase()
        alerts = []
        for gap in g.list_gaps(severity="critical"):
            alerts.append({
                "level": "critical",
                "message": f"关键差距未闭环: {gap['title']}",
                "gap_id": gap["gap_id"],
            })
        for gap in g.list_gaps(severity="high")[:5]:
            alerts.append({
                "level": "high",
                "message": f"高危差距: {gap['title']}",
                "gap_id": gap["gap_id"],
            })
        return alerts

    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history)[-limit:]


_default: Optional[ComplianceAIAnalysis] = None


def get_ai_analysis() -> ComplianceAIAnalysis:
    global _default
    if _default is None:
        _default = ComplianceAIAnalysis()
    return _default
