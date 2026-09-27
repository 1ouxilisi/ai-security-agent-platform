# -*- coding: utf-8 -*-
"""
linkage_monitor.py — 联动监控仪表盘。

- 联动规则列表（状态/最近触发/触发次数/成功率）
- 联动事件流（实时显示联动触发和执行）
- 联动统计图表（按规则/按领域/按时间）
- 联动失败列表（失败记录，可手动重试）
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .linkage_engine import get_linkage_engine
from .linkage_logger import get_linkage_logger
from .linkage_rules import get_rule_manager


class LinkageMonitor:
    def __init__(self) -> None:
        self.rm = get_rule_manager()
        self.logger = get_linkage_logger()
        self.engine = get_linkage_engine()

    def rules_overview(self) -> List[Dict[str, Any]]:
        items = self.rm.list()
        out = []
        for r in items:
            hits = r.get("hit_count", 0)
            succ = r.get("success_count", 0)
            out.append({
                "id": r["id"], "name": r["name"],
                "source_domain": r["source_domain"],
                "target_domain": r["target_domain"],
                "enabled": r["enabled"],
                "priority": r["priority"],
                "hit_count": hits,
                "success_rate": round(succ / hits * 100, 1) if hits else 0.0,
                "last_fired": "",
            })
        return out

    def event_stream(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.logger.list(limit=limit)

    def failures(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.logger.list(status="failed", limit=limit)

    def stats(self) -> Dict[str, Any]:
        ls = self.logger.stats()
        rs = self.rm.stats()
        return {
            "linkage": ls,
            "rules": rs,
            "total_rules": rs["total"],
            "enabled_rules": rs["enabled"],
        }

    def retry(self, log_id: str) -> Dict[str, Any]:
        return self.engine.replay(log_id)

    def dashboard(self) -> Dict[str, Any]:
        return {
            "rules": self.rules_overview(),
            "stats": self.stats(),
            "recent_events": self.event_stream(limit=30),
            "failures": self.failures(limit=20),
        }


_default: Optional[LinkageMonitor] = None


def get_linkage_monitor() -> LinkageMonitor:
    global _default
    if _default is None:
        _default = LinkageMonitor()
    return _default
