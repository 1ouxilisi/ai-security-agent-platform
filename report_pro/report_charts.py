# -*- coding: utf-8 -*-
"""
report_charts.py — 图表数据生成。

生成供前端 Chart.js 直接消费的数据：
    - 风险分布饼图
    - 漏洞严重程度柱状图
    - 资产风险热力图
    - 趋势对比图（跨报告对比）
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "#ff4d4f",
    "high":     "#ff7a45",
    "medium":   "#fadb14",
    "low":      "#52c41a",
    "info":     "#1677ff",
}
SEVERITY_LABELS = {
    "critical": "严重", "high": "高危", "medium": "中危",
    "low": "低危", "info": "信息",
}


class ReportCharts:
    """图表数据聚合器。"""

    # ------------------------------------------------------------------ #
    # 饼图：风险分布
    # ------------------------------------------------------------------ #
    @staticmethod
    def pie_distribution(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        cnt = Counter((f.get("severity") or "info").lower()
                      for f in findings)
        labels, data, colors = [], [], []
        for sev in SEVERITY_ORDER:
            if cnt.get(sev, 0) > 0:
                labels.append(SEVERITY_LABELS[sev])
                data.append(cnt[sev])
                colors.append(SEVERITY_COLORS[sev])
        return {
            "type": "doughnut",
            "data": {"labels": labels,
                     "datasets": [{"data": data,
                                   "backgroundColor": colors}]},
            "options": {"plugins": {"legend": {"position": "right"}}}
        }

    # ------------------------------------------------------------------ #
    # 柱状图：严重程度
    # ------------------------------------------------------------------ #
    @staticmethod
    def bar_severity(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        cnt = Counter((f.get("severity") or "info").lower()
                      for f in findings)
        return {
            "type": "bar",
            "data": {
                "labels": [SEVERITY_LABELS[s] for s in SEVERITY_ORDER],
                "datasets": [{
                    "label": "漏洞数量",
                    "data": [cnt.get(s, 0) for s in SEVERITY_ORDER],
                    "backgroundColor": [SEVERITY_COLORS[s]
                                        for s in SEVERITY_ORDER],
                }],
            },
            "options": {"scales": {"y": {"beginAtZero": True}}}
        }

    # ------------------------------------------------------------------ #
    # 柱状图：按漏洞类别
    # ------------------------------------------------------------------ #
    @staticmethod
    def bar_by_category(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        cnt = Counter((f.get("category") or "unknown")
                      for f in findings)
        top = cnt.most_common(10)
        return {
            "type": "bar",
            "data": {
                "labels": [k for k, _ in top],
                "datasets": [{
                    "label": "数量",
                    "data": [v for _, v in top],
                    "backgroundColor": "#58a6ff",
                }],
            },
            "options": {"indexAxis": "y"}
        }

    # ------------------------------------------------------------------ #
    # 热力图：资产风险
    # ------------------------------------------------------------------ #
    @staticmethod
    def heatmap_assets(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """返回每资产的严重程度分布。"""
        out = []
        for a in assets:
            out.append({
                "name": a.get("name", ""),
                "critical": a.get("critical", 0),
                "high": a.get("high", 0),
                "medium": a.get("medium", 0),
                "low": a.get("low", 0),
                "total": (a.get("critical", 0) + a.get("high", 0)
                          + a.get("medium", 0) + a.get("low", 0)),
            })
        return sorted(out, key=lambda x: -x["total"])

    # ------------------------------------------------------------------ #
    # 趋势对比：历史报告对比
    # ------------------------------------------------------------------ #
    @staticmethod
    def trend_compare(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        reports: [{"date": "2026-09-01", "critical": 1, "high": 3, ...}, ...]
        """
        labels = [r.get("date", "") for r in reports]
        datasets = []
        for sev in SEVERITY_ORDER:
            datasets.append({
                "label": SEVERITY_LABELS[sev],
                "data": [r.get(sev, 0) for r in reports],
                "borderColor": SEVERITY_COLORS[sev],
                "backgroundColor": SEVERITY_COLORS[sev] + "33",
                "tension": 0.3,
            })
        return {
            "type": "line",
            "data": {"labels": labels, "datasets": datasets},
            "options": {"scales": {"y": {"beginAtZero": True}}}
        }

    # ------------------------------------------------------------------ #
    # 汇总
    # ------------------------------------------------------------------ #
    @classmethod
    def all_charts(cls, findings: List[Dict[str, Any]],
                   assets: List[Dict[str, Any]] | None = None,
                   trend_reports: List[Dict[str, Any]] | None = None
                   ) -> Dict[str, Any]:
        return {
            "pie": cls.pie_distribution(findings),
            "bar_severity": cls.bar_severity(findings),
            "bar_category": cls.bar_by_category(findings),
            "heatmap": cls.heatmap_assets(assets or []),
            "trend": cls.trend_compare(trend_reports or []),
        }
