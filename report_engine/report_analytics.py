# -*- coding: utf-8 -*-
"""report_analytics.py — 报告管理与分析。

- 报告库管理 / 搜索 / 分类 / 标签
- 统计分析：数量、类型分布、行业分布、平均生成时间
- 模板使用率 / 质量评分趋势 / 客户反馈 / 综合仪表盘
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional


class ReportAnalytics:
    def __init__(self) -> None:
        self.library: Dict[str, Dict[str, Any]] = {}
        self.feedbacks: Dict[str, List[Dict[str, Any]]] = {}
        self.usage_counter: Counter = Counter()  # template_id -> 次数

    # ---------------- 入库 ---------------- #
    def ingest(self, report: Dict[str, Any]) -> Dict[str, Any]:
        rid = report["report_id"]
        self.library[rid] = {
            "report_id": rid,
            "client": report.get("client"),
            "project": report.get("project"),
            "template_id": report.get("template_id"),
            "template_name": report.get("template_name"),
            "industry": report.get("meta", {}).get("industry", "unknown"),
            "report_type": report.get("meta", {}).get("report_type", "unknown"),
            "overall_risk": report.get("overall_risk"),
            "vuln_count": len(report.get("vulnerabilities", [])),
            "created_at": report.get("created_at"),
            "tags": report.get("meta", {}).get("tags", []),
            "quality_score": None,
            "stage": "draft",
        }
        self.usage_counter[report.get("template_id", "unknown")] += 1
        return self.library[rid]

    def set_quality(self, report_id: str, score: int, grade: str) -> None:
        if report_id in self.library:
            self.library[report_id]["quality_score"] = score
            self.library[report_id]["quality_grade"] = grade

    def set_stage(self, report_id: str, stage: str) -> None:
        if report_id in self.library:
            self.library[report_id]["stage"] = stage

    # ---------------- 搜索 / 标签 ---------------- #
    def search(self, keyword: Optional[str] = None,
               industry: Optional[str] = None,
               report_type: Optional[str] = None,
               tag: Optional[str] = None,
               stage: Optional[str] = None) -> List[Dict[str, Any]]:
        out = list(self.library.values())
        if keyword:
            kw = keyword.lower()
            out = [r for r in out if kw in (r.get("client") or "").lower()
                   or kw in (r.get("project") or "").lower()]
        if industry:
            out = [r for r in out if r["industry"] == industry]
        if report_type:
            out = [r for r in out if r["report_type"] == report_type]
        if tag:
            out = [r for r in out if tag in (r.get("tags") or [])]
        if stage:
            out = [r for r in out if r["stage"] == stage]
        return out

    def add_tag(self, report_id: str, tag: str) -> bool:
        r = self.library.get(report_id)
        if not r:
            return False
        r.setdefault("tags", [])
        if tag not in r["tags"]:
            r["tags"].append(tag)
        return True

    # ---------------- 客户反馈 ---------------- #
    def add_feedback(self, report_id: str, user: str, rating: int,
                     comment: str = "") -> Dict[str, Any]:
        fb = {
            "report_id": report_id, "user": user, "rating": rating,
            "comment": comment, "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.feedbacks.setdefault(report_id, []).append(fb)
        return fb

    # ---------------- 仪表盘 ---------------- #
    def dashboard(self) -> Dict[str, Any]:
        total = len(self.library)
        by_type = Counter(r["report_type"] for r in self.library.values())
        by_industry = Counter(r["industry"] for r in self.library.values())
        by_stage = Counter(r["stage"] for r in self.library.values())
        scores = [r["quality_score"] for r in self.library.values() if r["quality_score"] is not None]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        # 客户平均分
        all_ratings = [f["rating"] for fs in self.feedbacks.values() for f in fs]
        avg_rating = round(sum(all_ratings) / len(all_ratings), 2) if all_ratings else 0
        return {
            "total_reports": total,
            "by_report_type": dict(by_type),
            "by_industry": dict(by_industry),
            "by_stage": dict(by_stage),
            "avg_quality_score": avg_score,
            "avg_customer_rating": avg_rating,
            "top_templates": self.usage_counter.most_common(10),
            "quality_trend": self._quality_trend(),
        }

    def _quality_trend(self) -> List[Dict[str, Any]]:
        rows = sorted(
            [r for r in self.library.values() if r["quality_score"] is not None],
            key=lambda x: x["created_at"] or "",
        )
        return [{"date": r["created_at"], "score": r["quality_score"],
                 "client": r["client"]} for r in rows[-20:]]


_ANALYTICS: ReportAnalytics | None = None


def get_analytics() -> ReportAnalytics:
    global _ANALYTICS
    if _ANALYTICS is None:
        _ANALYTICS = ReportAnalytics()
    return _ANALYTICS
