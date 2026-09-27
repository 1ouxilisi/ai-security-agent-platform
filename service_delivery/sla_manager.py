#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sla_manager.py — SLA 与服务级别。

覆盖：
    - SLA 模板：响应时间 / 解决时间 / 可用性承诺
    - SLA 监控：实时计算达成率
    - 违约告警、SLA 报告、SLA 历史、SLA 仪表盘
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


SLA_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "P1-critical": {
        "name": "P1 关键事件", "response_minutes": 15,
        "resolve_minutes": 240, "availability_pct": 99.95,
        "color": "#ff4d4f", "support": "7x24",
    },
    "P2-high": {
        "name": "P2 高优先级", "response_minutes": 60,
        "resolve_minutes": 480, "availability_pct": 99.9,
        "color": "#fa8c16", "support": "7x24",
    },
    "P3-medium": {
        "name": "P3 中优先级", "response_minutes": 240,
        "resolve_minutes": 1440, "availability_pct": 99.5,
        "color": "#faad14", "support": "5x8",
    },
    "P4-low": {
        "name": "P4 低优先级", "response_minutes": 1440,
        "resolve_minutes": 4320, "availability_pct": 99.0,
        "color": "#52c41a", "support": "工单",
    },
}

SLA_BREACH_LEVELS: Dict[str, str] = {
    "none": "未违约",
    "warning": "接近违约",
    "breach": "已违约",
    "critical_breach": "严重违约",
}


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _now() -> datetime:
    return datetime.now()


class SLAManager:
    """SLA 模板 / 实例 / 监控 / 告警 / 报告。"""

    def __init__(self) -> None:
        self.instances: Dict[str, Dict[str, Any]] = {}
        self.events: Dict[str, List[Dict[str, Any]]] = {}
        self.alerts: List[Dict[str, Any]] = []
        self._seed()

    def _seed(self) -> None:
        for i, cid in enumerate(("CUS-001", "CUS-002", "CUS-003")):
            sid = _uid("SLA")
            self.instances[sid] = {
                "sla_id": sid, "customer_id": cid,
                "template": ["P1-critical", "P2-high", "P3-medium"][i],
                "start": "2026-01-01", "end": "2026-12-31",
                "monthly_availability": [99.97, 99.85, 99.99, 99.92, 99.98, 99.95],
                "open_incidents": 2 + i,
                "breaches": i,
            }
            self.events[sid] = [
                {"time": (_now() - timedelta(hours=h)).strftime("%Y-%m-%d %H:%M:%S"),
                 "type": "incident", "status": "resolved",
                 "response_min": 12 + h, "resolve_min": 200 + h * 10}
                for h in (1, 5, 20, 50)
            ]

    # ------------------------- 模板 ------------------------- #
    def list_templates(self) -> Dict[str, Dict[str, Any]]:
        return SLA_TEMPLATES

    # ------------------------- 实例 ------------------------- #
    def create_instance(self, customer_id: str, template: str,
                        start: str, end: str) -> Dict[str, Any]:
        sid = _uid("SLA")
        inst = {"sla_id": sid, "customer_id": customer_id,
                "template": template, "start": start, "end": end,
                "monthly_availability": [], "open_incidents": 0,
                "breaches": 0}
        self.instances[sid] = inst
        self.events[sid] = []
        return inst

    def list_instances(self, customer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.instances.values())
        if customer_id:
            items = [x for x in items if x["customer_id"] == customer_id]
        return items

    # ------------------------- 实时监控 ------------------------- #
    def monitor(self, sid: str) -> Optional[Dict[str, Any]]:
        inst = self.instances.get(sid)
        if not inst:
            return None
        tpl = SLA_TEMPLATES.get(inst["template"], {})
        events = self.events.get(sid, [])
        resolved = [e for e in events if e["status"] == "resolved"]
        if not resolved:
            return {"sla_id": sid, "template": tpl, "events_evaluated": 0,
                    "response_compliance": 0, "resolve_compliance": 0,
                    "availability_pct": 0, "breach_level": "none"}
        resp_sla = tpl.get("response_minutes", 60)
        sol_sla = tpl.get("resolve_minutes", 480)
        resp_ok = sum(1 for e in resolved if e["response_min"] <= resp_sla)
        sol_ok = sum(1 for e in resolved if e["resolve_min"] <= sol_sla)
        avail = round(sum(inst.get("monthly_availability", [99.9]))
                      / max(1, len(inst.get("monthly_availability", [99.9]))), 2)
        avail_sla = tpl.get("availability_pct", 99.5)
        breach = "none"
        if avail < avail_sla - 0.2:
            breach = "critical_breach"
        elif avail < avail_sla:
            breach = "breach"
        elif (resp_ok / len(resolved)) < 0.9:
            breach = "warning"
        return {
            "sla_id": sid, "template": tpl,
            "events_evaluated": len(resolved),
            "response_compliance": round(resp_ok / len(resolved), 3),
            "resolve_compliance": round(sol_ok / len(resolved), 3),
            "availability_pct": avail,
            "availability_sla": avail_sla,
            "breach_level": breach,
            "breach_label": SLA_BREACH_LEVELS.get(breach, breach),
        }

    # ------------------------- 事件 / 告警 ------------------------- #
    def log_event(self, sid: str, response_min: int,
                  resolve_min: int, status: str = "resolved") -> Dict[str, Any]:
        ev = {"time": _now().strftime("%Y-%m-%d %H:%M:%S"),
              "type": "incident", "status": status,
              "response_min": response_min, "resolve_min": resolve_min}
        self.events.setdefault(sid, []).append(ev)
        m = self.monitor(sid)
        if m and m["breach_level"] in ("breach", "critical_breach"):
            self.alerts.append({
                "alert_id": _uid("ALT"), "sla_id": sid,
                "level": m["breach_level"], "time": ev["time"],
                "message": f"SLA 违约: 可用性 {m['availability_pct']}% "
                           f"(SLA {m['availability_sla']}%)",
            })
        return ev

    def list_alerts(self, level: Optional[str] = None) -> List[Dict[str, Any]]:
        items = self.alerts
        if level:
            items = [a for a in items if a["level"] == level]
        return items

    # ------------------------- 历史 / 报告 ------------------------- #
    def history(self, sid: str) -> List[Dict[str, Any]]:
        return self.events.get(sid, [])

    def report(self, sid: str) -> Dict[str, Any]:
        m = self.monitor(sid)
        if not m:
            return {}
        inst = self.instances[sid]
        return {
            "sla_id": sid, "customer_id": inst["customer_id"],
            "template": m["template"],
            "response_compliance": m["response_compliance"],
            "resolve_compliance": m["resolve_compliance"],
            "availability_pct": m["availability_pct"],
            "breach_level": m["breach_level"],
            "breach_count": inst.get("breaches", 0),
            "generated_at": _now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------- 仪表盘 ------------------------- #
    def dashboard(self) -> Dict[str, Any]:
        monitored = [self.monitor(sid) for sid in self.instances]
        monitored = [m for m in monitored if m]
        avg_avail = round(sum(m["availability_pct"] for m in monitored)
                          / max(1, len(monitored)), 2)
        breaches = [m for m in monitored
                    if m["breach_level"] in ("breach", "critical_breach")]
        return {
            "total_sla": len(self.instances),
            "avg_availability": avg_avail,
            "breaching": len(breaches),
            "active_alerts": len(self.alerts),
            "templates": list(SLA_TEMPLATES.keys()),
            "updated_at": _now().strftime("%Y-%m-%d %H:%M:%S"),
        }
