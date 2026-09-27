# -*- coding: utf-8 -*-
"""confidence_scorer.py — 置信度评分引擎。

每个漏洞都有置信度（高/中/低）：
- 高置信度(high)：工具检测 + 二次验证通过
- 中置信度(medium)：工具检测但未验证
- 低置信度(low)：仅规则匹配，默认隐藏

用户可切换显示低置信度。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


CONFIDENCE_LEVELS = {
    "high": {
        "label": "高置信度（已确认）",
        "color": "#10b981",
        "default_show": True,
        "min_score": 80,
        "criteria": "工具检测 + 二次验证通过 + 有证据payload",
    },
    "medium": {
        "label": "中置信度（待验证）",
        "color": "#f59e0b",
        "default_show": True,
        "min_score": 50,
        "criteria": "工具检测到，但未执行二次验证或验证未完成",
    },
    "low": {
        "label": "低置信度（疑似/噪声）",
        "color": "#6b7280",
        "default_show": False,
        "min_score": 0,
        "criteria": "仅规则匹配，无工具确认或二次验证未通过",
    },
}


class ConfidenceScorer:
    """置信度评分器：基于多维度证据给每个finding打分。"""

    def __init__(self) -> None:
        self._display_low = False  # 用户是否显示低置信度
        self._scored_count = 0
        self._distribution: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        self._score_history: List[Dict[str, Any]] = []

    def score(self, finding: Dict[str, Any],
              verification_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """对单个finding计算置信度评分。

        评分维度（满分100）：
        - 工具检测来源（0-30分）：nuclei=30, sqlmap=30, nikto=20, 自定义规则=10
        - 严重级别（0-20分）：critical=20, high=15, medium=10, low=5
        - 证据充分性（0-25分）：匹配证据关键词数量
        - 二次验证（0-25分）：verified=True=25, False=0, None=10
        - 历史误报率（0-10分）：该类型历史FP率越低分越高
        """
        score = 0
        breakdown: Dict[str, int] = {}

        # 1. 工具来源分（0-30）
        tool = (finding.get("detected_by") or finding.get("source") or "").lower()
        if tool in ("nuclei", "sqlmap", "nmap-vuln"):
            breakdown["tool_source"] = 30
        elif tool in ("nikto", "dirb", "dirsearch"):
            breakdown["tool_source"] = 20
        elif tool in ("custom_rule", "manual"):
            breakdown["tool_source"] = 10
        else:
            breakdown["tool_source"] = 15
        score += breakdown["tool_source"]

        # 2. 严重级别分（0-20）
        sev = (finding.get("severity") or "").lower()
        sev_scores = {"critical": 20, "high": 15, "medium": 10, "low": 5, "info": 2}
        breakdown["severity"] = sev_scores.get(sev, 5)
        score += breakdown["severity"]

        # 3. 证据充分性（0-25）
        evidence = finding.get("evidence") or finding.get("detail") or ""
        evidence_keywords = finding.get("evidence_keywords", [])
        if isinstance(evidence, str) and evidence_keywords:
            matched = sum(1 for k in evidence_keywords if k.lower() in evidence.lower())
            ev_score = min(25, matched * 8)
        elif evidence:
            ev_score = 10
        else:
            ev_score = 0
        breakdown["evidence"] = ev_score
        score += ev_score

        # 4. 二次验证分（0-25）
        if verification_result:
            if verification_result.get("verified"):
                ver_score = 25
            else:
                ver_score = 0
        else:
            ver_score = 10  # 未验证
        breakdown["verification"] = ver_score
        score += ver_score

        # 5. 历史误报率惩罚（0-10）
        # 假设当前历史FP率
        fp_rate_penalty = finding.get("_historical_fp_rate", 0.1875)
        hist_score = max(0, int(10 * (1 - fp_rate_penalty)))
        breakdown["historical"] = hist_score
        score += hist_score

        # 确定置信度等级
        if score >= 80:
            level = "high"
        elif score >= 50:
            level = "medium"
        else:
            level = "low"

        result = {
            "finding_id": finding.get("id", f"finding-{self._scored_count}"),
            "vuln_type": finding.get("type"),
            "name": finding.get("name"),
            "severity": sev,
            "total_score": score,
            "confidence_level": level,
            "confidence_label": CONFIDENCE_LEVELS[level]["label"],
            "confidence_color": CONFIDENCE_LEVELS[level]["color"],
            "breakdown": breakdown,
            "verification": verification_result,
            "should_show": self._should_show(level),
            "scored_at": datetime.utcnow().isoformat() + "Z",
        }
        self._scored_count += 1
        self._distribution[level] += 1
        self._score_history.append(result)
        return result

    def score_batch(self, findings: List[Dict[str, Any]],
                    verification_map: Optional[Dict[str, Dict[str, Any]]] = None
                    ) -> List[Dict[str, Any]]:
        """批量评分。verification_map: {finding_id: verification_result}"""
        verification_map = verification_map or {}
        results = []
        for f in findings:
            fid = f.get("id", "")
            vr = verification_map.get(fid)
            results.append(self.score(f, vr))
        return results

    def filter_by_display(self, scored_findings: List[Dict[str, Any]]
                          ) -> List[Dict[str, Any]]:
        """根据当前显示设置过滤。默认隐藏low，用户开启后显示。"""
        return [s for s in scored_findings if s["should_show"]]

    def set_display_low(self, show: bool) -> None:
        self._display_low = show

    def get_display_low(self) -> bool:
        return self._display_low

    def _should_show(self, level: str) -> bool:
        if level == "low":
            return self._display_low
        return True

    def get_distribution(self) -> Dict[str, Any]:
        total = sum(self._distribution.values()) or 1
        return {
            "levels": self._distribution,
            "total_scored": self._scored_count,
            "percentages": {
                k: round(v / total * 100, 1)
                for k, v in self._distribution.items()
            },
            "display_low_confidence": self._display_low,
        }

    def get_levels_info(self) -> Dict[str, Dict[str, Any]]:
        return {k: dict(v) for k, v in CONFIDENCE_LEVELS.items()}

    def get_stats(self) -> Dict[str, Any]:
        return {
            "scored_count": self._scored_count,
            "distribution": self.get_distribution(),
            "history_count": len(self._score_history),
        }

    def reset(self) -> None:
        self._scored_count = 0
        self._distribution = {"high": 0, "medium": 0, "low": 0}
        self._score_history.clear()


_singleton: Optional[ConfidenceScorer] = None


def get_confidence_scorer() -> ConfidenceScorer:
    global _singleton
    if _singleton is None:
        _singleton = ConfidenceScorer()
    return _singleton
