#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soc_deep/incident_response_deep.py — 事件响应深度。

覆盖：
    1. 事件管理：创建/分级/指派/跟踪/关闭
    2. 响应流程：NIST SP 800-61 / SANS PICERL 六阶段
    3. 事件调查：证据链/IOC/时间线/根因
    4. 事件遏制：网络隔离/账户冻结/进程终止（dry-run）
    5. 事件根除：IOC清除/恶意文件/后门修复
    6. 事件恢复：系统恢复/验证/监控
    7. 事件复盘：Postmortem/经验教训/改进项
"""

from __future__ import annotations

import time
import uuid
from collections import Counter
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# NIST / SANS IR 六阶段
# --------------------------------------------------------------------------- #
IR_PHASES = {
    "preparation":      {"name": "准备 Preparation",      "order": 0},
    "identification":   {"name": "识别 Identification",   "order": 1},
    "containment":      {"name": "遏制 Containment",     "order": 2},
    "eradication":      {"name": "根除 Eradication",     "order": 3},
    "recovery":         {"name": "恢复 Recovery",        "order": 4},
    "lessons_learned":  {"name": "复盘 Lessons Learned", "order": 5},
}

INCIDENT_SEVERITIES = ("low", "medium", "high", "critical")
INCIDENT_STATUSES = ("new", "investigating", "contained", "eradicated",
                     "recovering", "closed", "reopened")

CONTAINMENT_ACTIONS = (
    "isolate_network", "disable_account", "quarantine_host",
    "block_ip", "revoke_session", "stop_process", "take_snapshot",
)

ERADICATION_ACTIONS = (
    "remove_malware", "delete_backdoor", "patch_vuln",
    "rotate_credentials", "clean_ioc", "restore_config",
)


# --------------------------------------------------------------------------- #
# 事件对象
# --------------------------------------------------------------------------- #
class SecurityIncident:
    def __init__(self, title: str, severity: str = "medium",
                 category: str = "unknown") -> None:
        self.id = f"inc_{uuid.uuid4().hex[:10]}"
        self.title = title
        self.severity = severity
        self.category = category
        self.status = "new"
        self.phase = "preparation"
        self.assignee: Optional[str] = None
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.updated_at = self.created_at
        self.description = ""
        self.root_cause: str = ""
        self.timeline: List[Dict[str, Any]] = [{
            "phase": "preparation", "at": self.created_at,
            "note": "事件登记，进入准备阶段",
        }]
        self.iocs: Dict[str, List[str]] = {
            "ips": [], "domains": [], "hashes": [], "emails": [], "users": []}
        self.actions: List[Dict[str, Any]] = []
        self.lessons: List[str] = []
        self._mttd: Optional[float] = None
        self._mttr: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "category": self.category, "status": self.status,
            "phase": self.phase, "phase_name": IR_PHASES[self.phase]["name"],
            "assignee": self.assignee, "created_at": self.created_at,
            "updated_at": self.updated_at, "description": self.description,
            "root_cause": self.root_cause, "timeline": self.timeline,
            "iocs": self.iocs, "actions": self.actions, "lessons": self.lessons,
            "mttd_minutes": self._mttd, "mttr_minutes": self._mttr,
        }


# --------------------------------------------------------------------------- #
# 事件响应引擎
# --------------------------------------------------------------------------- #
class IncidentResponseDeep:
    def __init__(self) -> None:
        self.incidents: Dict[str, SecurityIncident] = {}
        self._seed_demo()

    # ---------------- 事件管理 ---------------- #
    def create(self, title: str, severity: str = "medium",
               category: str = "unknown", description: str = "",
               assignee: str = "") -> SecurityIncident:
        inc = SecurityIncident(title, severity, category)
        inc.description = description
        inc.assignee = assignee or None
        self.incidents[inc.id] = inc
        return inc

    def get(self, inc_id: str) -> Optional[SecurityIncident]:
        return self.incidents.get(inc_id)

    def list(self, status: str = "", severity: str = "",
             keyword: str = "") -> List[Dict[str, Any]]:
        out = []
        for i in self.incidents.values():
            if status and i.status != status:
                continue
            if severity and i.severity != severity:
                continue
            if keyword and keyword.lower() not in i.title.lower():
                continue
            out.append(i.to_dict())
        out.sort(key=lambda x: x["updated_at"], reverse=True)
        return out

    def assign(self, inc_id: str, assignee: str) -> Optional[SecurityIncident]:
        i = self.incidents.get(inc_id)
        if i:
            i.assignee = assignee
            i.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return i

    # ---------------- 阶段流转（NIST/SANS） ---------------- #
    def advance_phase(self, inc_id: str, note: str = "") -> Optional[SecurityIncident]:
        i = self.incidents.get(inc_id)
        if not i:
            return None
        order = IR_PHASES[i.phase]["order"]
        next_order = min(order + 1, 5)
        for ph, meta in IR_PHASES.items():
            if meta["order"] == next_order:
                i.phase = ph
                break
        phase_to_status = {
            "preparation": "new", "identification": "investigating",
            "containment": "contained", "eradication": "eradicated",
            "recovery": "recovering", "lessons_learned": "closed",
        }
        i.status = phase_to_status.get(i.phase, i.status)
        i.timeline.append({
            "phase": i.phase, "at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "note": note or f"进入 {IR_PHASES[i.phase]['name']} 阶段",
        })
        i.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return i

    # ---------------- 调查 ---------------- #
    def add_ioc(self, inc_id: str, kind: str, value: str) -> Optional[SecurityIncident]:
        i = self.incidents.get(inc_id)
        if not i:
            return None
        bucket = i.iocs.get(kind)
        if bucket is not None and value not in bucket:
            bucket.append(value)
        i.timeline.append({"phase": i.phase, "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "note": f"补充IOC [{kind}] {value}"})
        return i

    def set_root_cause(self, inc_id: str, cause: str) -> Optional[SecurityIncident]:
        i = self.incidents.get(inc_id)
        if i:
            i.root_cause = cause
            i.timeline.append({"phase": i.phase, "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                              "note": f"根因定位: {cause}"})
        return i

    # ---------------- 遏制 / 根除 / 恢复 ---------------- #
    def containment_action(self, inc_id: str, action: str,
                          target: str, operator: str = "soc-analyst",
                          dry_run: bool = True) -> Optional[Dict[str, Any]]:
        i = self.incidents.get(inc_id)
        if not i:
            return None
        record = {
            "stage": "containment", "action": action, "target": target,
            "operator": operator, "dry_run": dry_run,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "result": "simulated" if dry_run else "executed",
        }
        i.actions.append(record)
        return record

    def eradication_action(self, inc_id: str, action: str, target: str,
                          operator: str = "soc-analyst",
                          dry_run: bool = True) -> Optional[Dict[str, Any]]:
        i = self.incidents.get(inc_id)
        if not i:
            return None
        record = {
            "stage": "eradication", "action": action, "target": target,
            "operator": operator, "dry_run": dry_run,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "result": "simulated" if dry_run else "executed",
        }
        i.actions.append(record)
        return record

    def recovery_action(self, inc_id: str, action: str, target: str,
                       operator: str = "soc-analyst") -> Optional[Dict[str, Any]]:
        i = self.incidents.get(inc_id)
        if not i:
            return None
        record = {
            "stage": "recovery", "action": action, "target": target,
            "operator": operator,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "result": "simulated",
        }
        i.actions.append(record)
        return record

    # ---------------- 复盘 ---------------- #
    def add_lesson(self, inc_id: str, lesson: str) -> Optional[SecurityIncident]:
        i = self.incidents.get(inc_id)
        if i:
            i.lessons.append(lesson)
        return i

    def close(self, inc_id: str, postmortem: str = "") -> Optional[SecurityIncident]:
        i = self.incidents.get(inc_id)
        if not i:
            return None
        i.status = "closed"
        i.phase = "lessons_learned"
        i.timeline.append({"phase": i.phase, "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "note": f"事件关闭。{postmortem}"})
        i.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return i

    # ---------------- 度量 ---------------- #
    def metrics(self) -> Dict[str, Any]:
        sev = Counter(i.severity for i in self.incidents.values())
        st = Counter(i.status for i in self.incidents.values())
        ph = Counter(i.phase for i in self.incidents.values())
        return {
            "total": len(self.incidents),
            "by_severity": dict(sev), "by_status": dict(st),
            "by_phase": dict(ph),
            "open": sum(1 for i in self.incidents.values() if i.status != "closed"),
        }

    def _seed_demo(self) -> None:
        inc = self.create("web-server-01 遭 SQL 注入", "critical",
                          "web_attack", "WAF 触发 SQLi 告警，疑似数据泄露",
                          "analyst_zhang")
        inc.iocs["ips"] = ["203.0.113.8"]
        inc.iocs["users"] = ["root"]
        inc.phase = "containment"
        inc.status = "contained"
        inc.timeline.append({"phase": "identification",
                              "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                              "note": "确认攻击事件"})
        self.containment_action(inc.id, "block_ip", "203.0.113.8")


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_instance: Optional[IncidentResponseDeep] = None


def get_incident_response() -> IncidentResponseDeep:
    global _instance
    if _instance is None:
        _instance = IncidentResponseDeep()
    return _instance
