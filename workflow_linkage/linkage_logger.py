# -*- coding: utf-8 -*-
"""
linkage_logger.py — 联动日志（记录每次联动的触发/执行/结果）。
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional


class LinkageLogger:
    """联动执行日志（单例，线程安全）。"""

    MAX = 1000

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._logs: List[Dict[str, Any]] = []
        self._seq = 0

    def log(self, rule_id: str, rule_name: str, source_domain: str,
            target_domain: str, event: Dict[str, Any],
            status: str, detail: str = "",
            retry: int = 0) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            entry = {
                "id": f"llog-{self._seq}",
                "rule_id": rule_id,
                "rule_name": rule_name,
                "source_domain": source_domain,
                "target_domain": target_domain,
                "event_type": event.get("type", ""),
                "event_summary": str(event.get("data", ""))[:200],
                "status": status,  # success/failed/retried
                "detail": detail,
                "retry": retry,
                "created_at": time.time(),
            }
            self._logs.append(entry)
            if len(self._logs) > self.MAX:
                self._logs = self._logs[-self.MAX:]
            return entry

    def list(self, rule_id: Optional[str] = None,
             status: Optional[str] = None,
             limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._logs)
        if rule_id:
            items = [i for i in items if i["rule_id"] == rule_id]
        if status:
            items = [i for i in items if i["status"] == status]
        items.sort(key=lambda x: x["created_at"], reverse=True)
        return items[:limit]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._logs)
        total = len(items)
        success = sum(1 for i in items if i["status"] == "success")
        failed = sum(1 for i in items if i["status"] == "failed")
        by_rule: Dict[str, int] = {}
        by_domain: Dict[str, int] = {}
        for i in items:
            by_rule[i["rule_name"]] = by_rule.get(i["rule_name"], 0) + 1
            by_domain[i["source_domain"]] = \
                by_domain.get(i["source_domain"], 0) + 1
        return {
            "total": total,
            "success": success,
            "failed": failed,
            "success_rate": round(success / total * 100, 1) if total else 0.0,
            "by_rule": by_rule,
            "by_domain": by_domain,
        }


_default: Optional[LinkageLogger] = None


def get_linkage_logger() -> LinkageLogger:
    global _default
    if _default is None:
        _default = LinkageLogger()
    return _default
