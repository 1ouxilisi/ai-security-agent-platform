# -*- coding: utf-8 -*-
"""
global_search.py — 全局搜索（跨领域搜索任务/告警/漏洞/资产/日志，按领域分类展示）。
"""

from __future__ import annotations

from typing import Any, Dict

from .data_aggregator import get_aggregator


class GlobalSearch:
    def __init__(self) -> None:
        self.agg = get_aggregator()

    def search(self, keyword: str, limit_per: int = 20) -> Dict[str, Any]:
        return self.agg.global_search(keyword, limit_per=limit_per)


_default = None


def get_global_search() -> "GlobalSearch":
    global _default
    if _default is None:
        _default = GlobalSearch()
    return _default
