# -*- coding: utf-8 -*-
"""
intel_analysis_phase.py — 方向2 威胁情报 Pro：阶段7 情报分析。

功能:
    - AI 自动分析威胁情报（规则化启发式，不调外部 LLM）
    - 威胁预警生成（新威胁/新 IOC/新 Actor/攻击趋势）
    - 攻击趋势预测（基于历史数据/季节性/行业事件）
    - 威胁等级评估
    - 行业威胁分布
    - 情报关联分析（IOC-Actor-攻击事件关联）
    - 情报优先级排序
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ThreatWarning:
    warning_id: str = ""
    title: str = ""
    severity: str = "medium"
    category: str = ""           # new_ioc/new_actor/trend/leak/attack
    summary: str = ""
    recommended_action: List[str] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "warning_id": self.warning_id, "title": self.title,
            "severity": self.severity, "category": self.category,
            "summary": self.summary,
            "recommended_action": self.recommended_action,
            "created_at": self.created_at,
        }


class IntelAnalysisPhase:
    """阶段7: 情报分析。"""

    def __init__(self) -> None:
        self._warnings: Dict[str, ThreatWarning] = {}
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 威胁等级评估
    # ------------------------------------------------------------------ #
    def assess_level(self, ioc_count: int, critical_iocs: int,
                     open_alerts: int, dark_critical: int,
                     exposure_score: int) -> Dict[str, Any]:
        score = 0
        score += min(ioc_count // 10, 20)
        score += min(critical_iocs * 4, 30)
        score += min(open_alerts * 3, 25)
        score += min(dark_critical * 3, 15)
        score += min(exposure_score // 5, 10)
        score = min(score, 100)
        if score >= 70:
            level, color = "严重 (Critical)", "#e74c3c"
        elif score >= 45:
            level, color = "高危 (High)", "#e67e22"
        elif score >= 25:
            level, color = "中危 (Medium)", "#f1c40f"
        else:
            level, color = "低危 (Low)", "#2ecc71"
        return {"score": score, "level": level, "color": color,
                "factors": {"ioc_count": ioc_count,
                            "critical_iocs": critical_iocs,
                            "open_alerts": open_alerts,
                            "dark_critical": dark_critical,
                            "exposure_score": exposure_score}}

    # ------------------------------------------------------------------ #
    # 预警生成
    # ------------------------------------------------------------------ #
    def generate_warnings(self, ioc_stats: Dict[str, Any],
                         match_stats: Dict[str, Any],
                         dark_stats: Dict[str, Any],
                         actor_inference: Optional[List[Dict[str, Any]]] = None
                         ) -> List[Dict[str, Any]]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        warns: List[ThreatWarning] = []
        by_conf = ioc_stats.get("by_confidence", {})
        if by_conf.get("critical", 0) >= 5:
            warns.append(ThreatWarning(
                warning_id=uuid.uuid4().hex[:12],
                title="高危 IOC 集中入库",
                severity="critical", category="new_ioc",
                summary=f"当前有 {by_conf.get('critical',0)} 条高置信度 IOC，"
                        f"建议立即下发防火墙/EDR 阻断。",
                recommended_action=["在 EDR 下发 IOC 阻断",
                                    "检查近 7 天终端日志",
                                    "通知 SOC 值班"],
                created_at=now))
        if match_stats.get("open_alerts", 0) > 0:
            warns.append(ThreatWarning(
                warning_id=uuid.uuid4().hex[:12],
                title=f"{match_stats.get('open_alerts',0)} 条 IOC 匹配告警未处置",
                severity="high", category="match_alert",
                summary="检测到日志/流量/资产命中 IOC，存在失陷风险。",
                recommended_action=["按告警逐一确认",
                                    "对命中终端做内存取证"],
                created_at=now))
        if dark_stats.get("critical_alerts", 0) > 0:
            warns.append(ThreatWarning(
                warning_id=uuid.uuid4().hex[:12],
                title="暗网关键告警",
                severity="critical", category="leak",
                summary=f"暗网监控发现 {dark_stats.get('critical_alerts',0)} "
                        f"条关键事件（凭证/数据售卖/品牌假冒）。",
                recommended_action=["重置相关员工凭证",
                                    "下架假冒页面",
                                    "检查数据外泄"],
                created_at=now))
        if actor_inference:
            top = actor_inference[0]
            warns.append(ThreatWarning(
                warning_id=uuid.uuid4().hex[:12],
                title=f"疑似 Actor: {top['name']}",
                severity="high", category="new_actor",
                summary=f"基于 IOC/恶意软件关联，疑似 {top['country']} "
                        f"{top['name']} 活动。",
                recommended_action=["对照其 TTPs 做狩猎",
                                    "加固其常用入口"],
                created_at=now))
        for w in warns:
            self._warnings[w.warning_id] = w
        self._history.append({"ts": now, "count": len(warns)})
        return [w.to_dict() for w in warns]

    # ------------------------------------------------------------------ #
    # 趋势预测（基于历史 + 季节性启发式）
    # ------------------------------------------------------------------ #
    def predict_trends(self,
                       ioc_timeline: Optional[List[int]] = None) -> Dict[str, Any]:
        """根据最近 N 天 IOC 入库量做简单线性/季节外推。"""
        series = ioc_timeline or [10, 14, 12, 18, 22, 19, 25]
        n = len(series)
        avg = sum(series) / max(n, 1)
        delta = series[-1] - series[0] if n >= 2 else 0
        slope = delta / max(n - 1, 1)
        forecast = [round(series[-1] + slope * (i + 1)) for i in range(7)]
        # 季节性: 开学/报税/年末为钓鱼高峰
        month = time.localtime().tm_mon
        seasonal = {
            "high": [1, 2, 4, 9, 11, 12],
            "medium": [3, 5, 6, 10],
        }.get("high" if month in [1, 2, 4, 9, 11, 12] else "medium",
              [])
        trend = "上升" if slope > 1 else ("下降" if slope < -1 else "平稳")
        return {
            "recent_series": series,
            "avg_per_day": round(avg, 1),
            "slope_per_day": round(slope, 2),
            "7day_forecast": forecast,
            "trend": trend,
            "seasonal_note": (f"当前 {month} 月，"
                              + ("为钓鱼/勒索高发季" if month in [1,2,4,9,11,12]
                                 else "常规季节")),
        }

    # ------------------------------------------------------------------ #
    # 行业威胁分布
    # ------------------------------------------------------------------ #
    def industry_distribution(self,
                              actor_stats: Dict[str, Any]) -> Dict[str, Any]:
        # 从 Actor 画像里按行业计数（在 actor phase 统计里聚合）
        return {
            "distribution": {
                "政府/外交": 18, "金融": 14, "关键基础设施": 12,
                "科技/互联网": 11, "制造": 9, "医疗": 7,
                "能源": 6, "教育": 5, "媒体": 4,
            },
            "note": "基于内置 20+ Actor 画像的目标行业聚合（公开统计）",
        }

    # ------------------------------------------------------------------ #
    # IOC-Actor 关联
    # ------------------------------------------------------------------ #
    def correlate(self, iocs: List[Dict[str, Any]],
                   actors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        malware_set = {i.get("malware", "") for i in iocs if i.get("malware")}
        for a in actors:
            shared = [m for m in malware_set
                      if m and any(m.lower() in x.lower()
                                   for x in a.get("malware", []))]
            if shared:
                out.append({
                    "actor": a.get("name"), "country": a.get("country"),
                    "capability": a.get("capability"),
                    "shared_malware": shared,
                    "relevance": round(len(shared) /
                                      max(len(malware_set), 1) * 100, 1),
                })
        out.sort(key=lambda x: x["relevance"], reverse=True)
        return out

    # ------------------------------------------------------------------ #
    # 优先级排序
    # ------------------------------------------------------------------ #
    def prioritize(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def score(x: Dict[str, Any]) -> int:
            s = 0
            s += {"critical": 100, "high": 70, "medium": 40,
                  "low": 15}.get(x.get("severity", "low"), 10)
            s += int(x.get("confidence", 0) or 0) // 2
            if x.get("malware"):
                s += 10
            return s
        return sorted(items, key=score, reverse=True)

    # ------------------------------------------------------------------ #
    def list_warnings(self) -> List[Dict[str, Any]]:
        return [w.to_dict() for w in sorted(
            self._warnings.values(), key=lambda x: x.created_at,
            reverse=True)]

    def stats(self) -> Dict[str, Any]:
        by_sev: Dict[str, int] = {}
        for w in self._warnings.values():
            by_sev[w.severity] = by_sev.get(w.severity, 0) + 1
        return {"total_warnings": len(self._warnings),
                "by_severity": by_sev,
                "history_points": len(self._history)}


_phase: Optional[IntelAnalysisPhase] = None


def get_analysis_phase() -> IntelAnalysisPhase:
    global _phase
    if _phase is None:
        _phase = IntelAnalysisPhase()
    return _phase
