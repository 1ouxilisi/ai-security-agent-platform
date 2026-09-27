# -*- coding: utf-8 -*-
"""
access_audit_phase.py — 阶段7：数据访问审计。

- 访问日志收集
- 异常访问检测（时间/地点/IP）
- 越权访问 / 批量访问 / 敏感访问 / 特权账户监控
- 权限审计（过大/冗余/过期）
- 访问统计 + 风险评分
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AccessLog:
    log_id: str
    ts: str
    user: str
    action: str          # select/export/update/delete/login
    resource: str
    ip: str
    location: str = "内网"
    is_privileged: bool = False
    row_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id": self.log_id, "ts": self.ts, "user": self.user,
            "action": self.action, "resource": self.resource,
            "ip": self.ip, "location": self.location,
            "is_privileged": self.is_privileged,
            "row_count": self.row_count,
        }


@dataclass
class AccessAnomaly:
    anomaly_id: str
    ts: str
    user: str
    atype: str           # unusual_time/unusual_ip/unusual_location/
                          # over_privilege/bulk_export/sensitive_access/
                          # privileged_alert
    risk_score: int
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id, "ts": self.ts,
            "user": self.user, "atype": self.atype,
            "risk_score": self.risk_score, "detail": self.detail,
        }


class AccessAuditPhase:
    """阶段7：数据访问审计。"""

    def __init__(self) -> None:
        self._logs: List[AccessLog] = []
        self._anomalies: List[AccessAnomaly] = []
        self._permissions: List[Dict[str, Any]] = []
        self._seed_mock()

    def _lid(self) -> str:
        return "L" + uuid.uuid4().hex[:8]

    def _seed_mock(self) -> None:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        seeds = [
            ("alice", "select", "crm.users", "10.0.1.21", "内网",
             False, 120),
            ("bob", "export", "crm.users", "10.0.1.22", "内网",
             False, 120000),
            ("dba-zhang", "select", "crm.orders", "10.0.1.5", "内网",
             True, 50),
            ("carol", "select", "crm.users", "203.0.113.7", "境外",
             False, 3000),
            ("dba-zhang", "select", "mysql.user", "10.0.1.5", "内网",
             True, 0),
            ("eve", "update", "crm.users", "10.0.1.99", "内网",
             False, 10),
        ]
        for s in seeds:
            self._logs.append(AccessLog(
                log_id=self._lid(), ts=now, user=s[0], action=s[1],
                resource=s[2], ip=s[3], location=s[4],
                is_privileged=s[5], row_count=s[6]))
        # 权限
        self._permissions = [
            {"role": "developer", "scope": "crm.*",
             "granted_by": "admin", "days_since_grant": 800,
             "redundant": True},
            {"role": "bob", "scope": "crm.orders",
             "granted_by": "manager", "days_since_grant": 30,
             "redundant": False},
            {"role": "guest", "scope": "crm.users.select",
             "granted_by": "admin", "days_since_grant": 1500,
             "redundant": True},
        ]

    # ------------------------------------------------------------------ #
    def ingest_log(self, user: str, action: str, resource: str,
                   ip: str, location: str = "内网",
                   is_privileged: bool = False,
                   row_count: int = 0) -> Dict[str, Any]:
        log = AccessLog(
            log_id=self._lid(), ts=time.strftime("%Y-%m-%d %H:%M:%S"),
            user=user, action=action, resource=resource, ip=ip,
            location=location, is_privileged=is_privileged,
            row_count=row_count)
        self._logs.append(log)
        self._detect_anomaly(log)
        return log.to_dict()

    # ------------------------------------------------------------------ #
    def _detect_anomaly(self, log: AccessLog) -> None:
        hour = int(time.strftime("%H"))
        if hour < 6 or hour > 22:
            self._anomalies.append(AccessAnomaly(
                anomaly_id="AN" + uuid.uuid4().hex[:6], ts=log.ts,
                user=log.user, atype="unusual_time", risk_score=60,
                detail=f"{log.user} 在非常规时间访问 {log.resource}"))
        if log.location == "境外":
            self._anomalies.append(AccessAnomaly(
                anomaly_id="AN" + uuid.uuid4().hex[:6], ts=log.ts,
                user=log.user, atype="unusual_location", risk_score=80,
                detail=f"{log.user} 从境外 {log.ip} 访问 {log.resource}"))
        if log.row_count >= 100000:
            self._anomalies.append(AccessAnomaly(
                anomaly_id="AN" + uuid.uuid4().hex[:6], ts=log.ts,
                user=log.user, atype="bulk_export", risk_score=90,
                detail=f"{log.user} 一次导出 {log.row_count} 行"))
        if log.is_privileged and log.resource.endswith("mysql.user"):
            self._anomalies.append(AccessAnomaly(
                anomaly_id="AN" + uuid.uuid4().hex[:6], ts=log.ts,
                user=log.user, atype="privileged_alert", risk_score=85,
                detail=f"特权账户访问权限表 {log.resource}"))
        if "users" in log.resource and log.action in ("export",):
            self._anomalies.append(AccessAnomaly(
                anomaly_id="AN" + uuid.uuid4().hex[:6], ts=log.ts,
                user=log.user, atype="sensitive_access", risk_score=70,
                detail=f"{log.user} 导出敏感表 {log.resource}"))

    # ------------------------------------------------------------------ #
    def list_logs(self, user: Optional[str] = None,
                  limit: int = 100) -> List[Dict[str, Any]]:
        items = self._logs
        if user:
            items = [l for l in items if l.user == user]
        return [l.to_dict() for l in items[-limit:]][::-1]

    def list_anomalies(self, atype: Optional[str] = None,
                       min_risk: int = 0) -> List[Dict[str, Any]]:
        items = self._anomalies
        if atype:
            items = [a for a in items if a.atype == atype]
        items = [a for a in items if a.risk_score >= min_risk]
        return [a.to_dict() for a in
                sorted(items, key=lambda x: x.risk_score, reverse=True)]

    def list_permissions(self) -> List[Dict[str, Any]]:
        return list(self._permissions)

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        users: Dict[str, int] = {}
        actions: Dict[str, int] = {}
        for l in self._logs:
            users[l.user] = users.get(l.user, 0) + 1
            actions[l.action] = actions.get(l.action, 0) + 1
        risk = 0
        if self._anomalies:
            risk = round(sum(a.risk_score for a in self._anomalies)
                         / len(self._anomalies), 1)
        redundant = sum(1 for p in self._permissions
                        if p.get("redundant"))
        return {
            "log_total": len(self._logs),
            "anomaly_total": len(self._anomalies),
            "top_users": sorted(users.items(), key=lambda x: -x[1])[:10],
            "by_action": actions,
            "redundant_permissions": redundant,
            "risk_score": risk,
        }


_default_phase: Optional[AccessAuditPhase] = None


def get_access_audit_phase() -> AccessAuditPhase:
    global _default_phase
    if _default_phase is None:
        _default_phase = AccessAuditPhase()
    return _default_phase


__all__ = [
    "AccessAuditPhase", "AccessLog", "AccessAnomaly",
    "get_access_audit_phase",
]
