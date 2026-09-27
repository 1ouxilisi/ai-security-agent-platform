# -*- coding: utf-8 -*-
"""
unified_task_list.py — 统一任务列表（所有领域任务，按时间倒序，可筛选/搜索/按领域过滤）。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .data_aggregator import get_aggregator


class UnifiedTaskList:
    def __init__(self) -> None:
        self.agg = get_aggregator()

    def list(self, domain: Optional[str] = None,
             status: Optional[str] = None,
             keyword: Optional[str] = None,
             limit: int = 200) -> Dict[str, Any]:
        items = self.agg.list_tasks(domain=domain, status=status,
                                    keyword=keyword, limit=limit)
        return {"tasks": items, "total": len(items)}

    def stats(self) -> Dict[str, Any]:
        return self.agg.stats_summary()["tasks"]


_default = None


def get_task_list() -> "UnifiedTaskList":
    global _default
    if _default is None:
        _default = UnifiedTaskList()
    return _default
