# -*- coding: utf-8 -*-
"""fp_dashboard.py — 误报率仪表盘聚合。

聚合靶场清单、最新一次验证、历史趋势、规则优化状态、报告列表，供前端
控制台一次性拉取。
"""
from __future__ import annotations

from typing import Any, Dict, List

from .range_repository import get_repository
from .fp_runner import get_runner
from .rule_optimizer import get_optimizer
from .fp_report import get_report_generator, REPORTS_DIR

import glob
import os


class FPDashboard:
    """仪表盘聚合服务。"""

    def __init__(self) -> None:
        self.repo = get_repository()
        self.runner = get_runner()
        self.opt = get_optimizer()
        self.rpt = get_report_generator()

    def overview(self) -> Dict[str, Any]:
        ranges = self.repo.list_ranges()
        latest = self.runner.latest()
        history = self.runner.history()
        rules = self.opt.get_rules()
        reports = self.list_reports()
        return {
            "ranges": ranges,
            "ranges_total": len(ranges),
            "negative_control": [r["id"] for r in ranges if r.get("is_negative_control")],
            "latest": latest,
            "history_count": len(history),
            "history_trend": [
                {
                    "ts": h.get("ts"),
                    "fpr": (h.get("aggregate") or {}).get("false_positive_rate"),
                    "f1": (h.get("aggregate") or {}).get("f1"),
                    "recall": (h.get("aggregate") or {}).get("recall"),
                }
                for h in history[-20:]
            ],
            "rules_current": rules["current"],
            "rules_history_count": len(rules["history"]),
            "reports": reports,
            "tools_status": self.runner.tools_status(),
        }

    def list_reports(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not os.path.isdir(REPORTS_DIR):
            return out
        for p in sorted(glob.glob(os.path.join(REPORTS_DIR, "fp_validation_report_*.md")),
                        reverse=True)[:20]:
            st = os.stat(p)
            out.append({
                "name": os.path.basename(p),
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            })
        return out

    def get_report(self, name: str) -> Dict[str, Any] | None:
        safe = os.path.basename(name)
        path = os.path.join(REPORTS_DIR, safe)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return {"name": safe, "path": path, "content": f.read()}


_singleton: FPDashboard | None = None


def get_dashboard() -> FPDashboard:
    global _singleton
    if _singleton is None:
        _singleton = FPDashboard()
    return _singleton
