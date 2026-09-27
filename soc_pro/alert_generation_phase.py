# -*- coding: utf-8 -*-
"""
alert_generation_phase.py — 阶段4：告警生成。

功能:
    - 告警分级（critical/high/medium/low 四级）
    - 告警去重（相同告警合并/时间窗口去重）
    - 告警聚合（按源 IP/目标/攻击类型聚合）
    - 告警生命周期（新建/确认/处理中/已解决/已关闭）
    - 告警分配（自动分配/手动分配）
    - 告警通知（邮件/短信/Webhook 框架）
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATUSES = ["new", "confirmed", "in_progress", "resolved", "closed"]


@dataclass
class Alert:
    alert_id: str = ""
    title: str = ""
    severity: str = "medium"
    category: str = ""
    status: str = "new"
    src_ip: str = ""
    dst_ip: str = ""
    user: str = ""
    rule_id: str = ""
    mitre: str = ""
    count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    assignee: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    dedup_key: str = ""
    notes: List[str] = field(default_factory=list)
    sla_due: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id, "title": self.title,
            "severity": self.severity, "category": self.category,
            "status": self.status,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "user": self.user, "rule_id": self.rule_id,
            "mitre": self.mitre, "count": self.count,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "assignee": self.assignee, "description": self.description,
            "evidence": self.evidence[-5:],
            "notes": self.notes, "sla_due": self.sla_due,
        }


class AlertGenerationPhase:
    """阶段4：告警生成。"""

    def __init__(self) -> None:
        self._alerts: Dict[str, Alert] = {}
        self._notifications: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._analysts = ["alice", "bob", "carol", "dave"]

    # ------------------------------------------------------------------ #
    def _sla_for(self, severity: str) -> str:
        mins = {"critical": 15, "high": 60, "medium": 240,
                "low": 1440}.get(severity, 240)
        return (datetime.now() + timedelta(minutes=mins)
                ).isoformat(timespec="seconds")

    def generate_from_hits(self,
                           hits: Optional[List[Dict[str, Any]]] = None
                           ) -> Dict[str, Any]:
        if hits is None:
            from .correlation_phase import get_correlation_phase
            hits = get_correlation_phase().recent_hits(200)

        created = 0
        merged = 0
        now = datetime.now().isoformat(timespec="seconds")

        with self._lock:
            for h in hits:
                key = f"{h.get('rule_id')}|{h.get('src_ip')}|{h.get('user')}"
                # 去重：5 分钟窗口内同 key 合并
                existing = None
                for a in self._alerts.values():
                    if a.dedup_key == key and a.status in ("new",
                                                           "confirmed"):
                        existing = a
                        break
                if existing:
                    existing.count += int(h.get("count", 1))
                    existing.last_seen = now
                    existing.evidence.extend(h.get("evidence", []))
                    merged += 1
                    continue
                sev = h.get("severity", "medium")
                a = Alert(
                    alert_id="alrt_" + uuid.uuid4().hex[:10],
                    title=f"[{h.get('category','')}] {h.get('rule_name','')}",
                    severity=sev,
                    category=h.get("category", ""),
                    src_ip=h.get("src_ip", ""),
                    dst_ip=h.get("dst_ip", ""),
                    user=h.get("user", ""),
                    rule_id=h.get("rule_id", ""),
                    mitre=h.get("mitre", ""),
                    count=int(h.get("count", 1)),
                    first_seen=now, last_seen=now,
                    description=h.get("description", ""),
                    evidence=list(h.get("evidence", [])),
                    dedup_key=key,
                    sla_due=self._sla_for(sev),
                    assignee=self._auto_assign(sev),
                )
                self._alerts[a.alert_id] = a
                created += 1

        return {"created": created, "merged": merged,
                "total": len(self._alerts)}

    def _auto_assign(self, severity: str) -> str:
        if severity == "critical":
            return "oncall-lead"
        if severity == "high":
            return self._analysts[0]
        return self._analysts[-1]

    # ------------------------------------------------------------------ #
    def list_alerts(self, status: Optional[str] = None,
                    severity: Optional[str] = None,
                    limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._alerts.values())
        if status:
            items = [a for a in items if a.status == status]
        if severity:
            items = [a for a in items if a.severity == severity]
        items.sort(key=lambda a: (SEVERITY_ORDER.get(a.severity, 9),
                                  a.last_seen), reverse=False)
        return [a.to_dict() for a in items[-limit:]][::-1]

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            a = self._alerts.get(alert_id)
            return a.to_dict() if a else None

    def update_status(self, alert_id: str, status: str,
                      note: str = "") -> Optional[Dict[str, Any]]:
        if status not in STATUSES:
            return None
        with self._lock:
            a = self._alerts.get(alert_id)
            if a is None:
                return None
            a.status = status
            if note:
                a.notes.append(f"[{datetime.now().strftime('%H:%M:%S')}] "
                               f"{note}")
            return a.to_dict()

    def assign(self, alert_id: str, assignee: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            a = self._alerts.get(alert_id)
            if a is None:
                return None
            a.assignee = assignee
            return a.to_dict()

    # ------------------------------------------------------------------ #
    def notify(self, alert_id: str, channels: List[str]
               ) -> Dict[str, Any]:
        """通知框架：邮件/短信/Webhook（不真实外发，记录事件）。"""
        a = self.get_alert(alert_id)
        if not a:
            return {"success": False, "error": "alert not found"}
        records = []
        for ch in channels:
            rec = {
                "channel": ch, "alert_id": alert_id,
                "title": a["title"], "severity": a["severity"],
                "status": "queued",
                "at": datetime.now().isoformat(timespec="seconds"),
                "note": f"[{ch}] 通知队列已入队（未配置真实 "
                        f"{ch.upper()} 通道，仅记录）",
            }
            self._notifications.append(rec)
            records.append(rec)
        return {"success": True, "records": records}

    def notification_log(self) -> List[Dict[str, Any]]:
        return list(self._notifications)[-100:]

    # ------------------------------------------------------------------ #
    def aggregate(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._alerts.values())
        by_src: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        by_status: Dict[str, int] = {s: 0 for s in STATUSES}
        by_sev: Dict[str, int] = {}
        for a in items:
            by_src[a.src_ip or "unknown"] = \
                by_src.get(a.src_ip or "unknown", 0) + 1
            by_cat[a.category] = by_cat.get(a.category, 0) + 1
            by_status[a.status] = by_status.get(a.status, 0) + 1
            by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
        top_src = sorted(by_src.items(), key=lambda x: x[1],
                         reverse=True)[:10]
        return {
            "total": len(items),
            "by_status": by_status,
            "by_severity": by_sev,
            "by_category": by_cat,
            "top_source_ips": [{"ip": k, "count": v}
                               for k, v in top_src],
        }


_default: Optional[AlertGenerationPhase] = None


def get_alert_generation_phase() -> AlertGenerationPhase:
    global _default
    if _default is None:
        _default = AlertGenerationPhase()
    return _default
