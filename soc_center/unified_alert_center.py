# -*- coding: utf-8 -*-
"""
unified_alert_center.py — 统一告警中心（所有领域告警，按严重程度排序，可确认/处理/关闭）。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .data_aggregator import get_aggregator


class UnifiedAlertCenter:
    def __init__(self) -> None:
        self.agg = get_aggregator()

    def list(self, domain: Optional[str] = None,
             severity: Optional[str] = None,
             status: Optional[str] = None,
             limit: int = 200) -> Dict[str, Any]:
        items = self.agg.list_alerts(domain=domain, severity=severity,
                                     status=status, limit=limit)
        return {"alerts": items, "total": len(items)}

    def detail(self, alert_id: str) -> Optional[Dict[str, Any]]:
        return self.agg.get_alert(alert_id)

    def update_status(self, alert_id: str, status: str,
                      note: str = "") -> Optional[Dict[str, Any]]:
        valid = {"new", "confirmed", "processing", "closed", "false_positive"}
        if status not in valid:
            return None
        fields: Dict[str, Any] = {"status": status}
        if note:
            fields["detail"] = note
        return self.agg.update_alert(alert_id, **fields)

    def assign(self, alert_id: str, assignee: str) -> Optional[Dict[str, Any]]:
        return self.agg.update_alert(alert_id, assignee=assignee)

    def summary(self) -> Dict[str, Any]:
        return self.agg.stats_summary()["alerts"]


_default = None


def get_alert_center() -> "UnifiedAlertCenter":
    global _default
    if _default is None:
        _default = UnifiedAlertCenter()
    return _default
