# -*- coding: utf-8 -*-
"""
ai_analysis.py — 方向2 威胁情报 Pro：AI 分析。

不调用外部 LLM，使用规则化启发式引擎完成:
    - 威胁情报自动分析
    - 威胁预警生成
    - 攻击趋势预测
    - IOC-Actor 关联分析
    - 威胁优先级排序
    - 攻击面风险评估
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


class ThreatIntelAIAnalyzer:
    """AI 分析引擎（规则启发式，可被真实 LLM 替换）。"""

    def __init__(self) -> None:
        self._thoughts: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    def _think(self, step: str, detail: str) -> None:
        self._thoughts.append({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "step": step, "detail": detail})

    def thoughts(self) -> List[Dict[str, Any]]:
        return list(self._thoughts[-50:])

    # ------------------------------------------------------------------ #
    def analyze_intel(self, iocs: List[Dict[str, Any]],
                      matches: List[Dict[str, Any]],
                      actors: List[Dict[str, Any]],
                      surface: Dict[str, Any]) -> Dict[str, Any]:
        """综合分析，产出结论。"""
        self._think("接收数据",
                    f"IOC={len(iocs)} 匹配={len(matches)} "
                    f"Actor={len(actors)}")
        # 1. 严重度聚合
        crit = sum(1 for i in iocs if i.get("confidence", 0) >= 90)
        high = sum(1 for i in iocs if 75 <= i.get("confidence", 0) < 90)
        self._think("严重度聚合", f"critical={crit} high={high}")
        # 2. Actor 推断
        malware = [i.get("malware", "") for i in iocs if i.get("malware")]
        likely_actors: List[Dict[str, Any]] = []
        for a in actors:
            shared = [m for m in malware
                      if any(m.lower() in x.lower()
                             for x in a.get("malware", []))]
            if shared:
                likely_actors.append({
                    "name": a.get("name"), "country": a.get("country"),
                    "shared": shared,
                    "capability": a.get("capability")})
        likely_actors.sort(key=lambda x: len(x["shared"]), reverse=True)
        self._think("Actor 推断",
                    f"疑似 {[a['name'] for a in likely_actors[:3]]}")
        # 3. 攻击面风险
        exp_score = surface.get("avg_score", 0)
        risk = "高" if exp_score >= 60 else ("中" if exp_score >= 35
                                              else "低")
        # 4. 优先级
        prioritized = sorted(
            iocs,
            key=lambda x: (x.get("confidence", 0),
                           len(x.get("tags", []))),
            reverse=True)[:10]
        self._think("优先级排序", f"Top10 IOC 已排序")
        # 5. 结论
        overall = "严重" if crit >= 5 or risk == "高" \
            else ("高" if high >= 5 or risk == "中" else "中")
        return {
            "overall_risk": overall,
            "ioc_summary": {"total": len(iocs), "critical": crit,
                            "high": high},
            "likely_actors": likely_actors[:5],
            "attack_surface_risk": {"score": exp_score, "level": risk},
            "top_iocs": prioritized,
            "recommendations": self._recommend(
                crit, high, likely_actors, risk),
            "thoughts": self.thoughts(),
        }

    # ------------------------------------------------------------------ #
    def _recommend(self, crit: int, high: int,
                   actors: List[Dict[str, Any]],
                   surface_risk: str) -> List[str]:
        recs: List[str] = []
        if crit:
            recs.append(f"立即在防火墙/EDR 阻断 {crit} 条 critical IOC")
        if high:
            recs.append(f"对 {high} 条 high IOC 做 hunt 与资产排查")
        if actors:
            recs.append(
                f"对照 {actors[0]['name']} 的 TTPs 开展威胁狩猎")
        if surface_risk == "高":
            recs.append("收敛暴露面：关闭高危端口、更新证书、隐藏管理后台")
        recs.append("建立 IOC 自动下发与回环验证机制")
        recs.append("将关键 IOC 通过 STIX/TAXII 共享给合作伙伴")
        return recs

    # ------------------------------------------------------------------ #
    def trend_forecast(self, series: List[int]) -> Dict[str, Any]:
        n = len(series)
        if n < 2:
            return {"trend": "unknown", "forecast": []}
        slope = (series[-1] - series[0]) / (n - 1)
        direction = "上升" if slope > 1 else ("下降" if slope < -1
                                              else "平稳")
        forecast = [round(series[-1] + slope * (i + 1)) for i in range(7)]
        return {"trend": direction, "slope": round(slope, 2),
                "forecast_7d": forecast}


_analyzer: Optional[ThreatIntelAIAnalyzer] = None


def get_ai_analyzer() -> ThreatIntelAIAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = ThreatIntelAIAnalyzer()
    return _analyzer
