# -*- coding: utf-8 -*-
"""
unified_operation_log.py — 统一操作日志（所有用户操作记录，按时间倒序）。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .data_aggregator import get_aggregator


class UnifiedOperationLog:
    def __init__(self) -> None:
        self.agg = get_aggregator()

    def list(self, keyword: Optional[str] = None,
             user: Optional[str] = None,
             limit: int = 200) -> Dict[str, Any]:
        items = self.agg.list_logs(keyword=keyword, user=user, limit=limit)
        return {"logs": items, "total": len(items)}

    def record(self, user: str, action: str, target: str = "",
               domain: str = "", detail: str = "") -> Dict[str, Any]:
        return self.agg.ingest_log({
            "user": user, "action": action, "target": target,
            "domain": domain, "detail": detail,
        })


_default = None


def get_operation_log() -> "UnifiedOperationLog":
    global _default
    if _default is None:
        _default = UnifiedOperationLog()
    return _default
