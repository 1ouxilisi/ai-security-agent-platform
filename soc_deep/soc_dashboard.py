#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soc_deep/soc_dashboard.py — SOC 深度控制台数据聚合层。

聚合 7 大模块数据，对外提供：
    - 总览 KPI（日志/规则/告警/事件/情报/度量）
    - 实时威胁墙
    - 攻击链视图
    - 系统设置
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


SYSTEM_SETTINGS = {
    "platform_name": "SOC Deep 深度安全运营中心",
    "version": "26.3.0",
    "timezone": "Asia/Shanghai",
    "retention_days": 30,
    "oncall_rotation": "weekly",
    "notification_channels": ["email", "webhook", "sms"],
    "auto_triage_enabled": True,
    "auto_ir_playbook": "standard-incident-response",
}


class SOCDashboard:
    """聚合层。"""

    def __init__(self) -> None:
        try:
            from .siem_logging import get_siem
            from .correlation_engine import get_correlation_engine
            from .alert_triage_deep import get_alert_triage_deep
            from .incident_response_deep import get_incident_response
            from .threat_intel_soc import get_threat_intel_soc
            from .soc_metrics import get_soc_metrics
            self.siem = get_siem()
            self.rules = get_correlation_engine()
            self.triage = get_alert_triage_deep()
            self.incident = get_incident_response()
            self.intel = get_threat_intel_soc()
            self.metrics = get_soc_metrics()
            self._ok = True
        except Exception as e:  # pragma: no cover
            self._ok = False
            self._err = str(e)

    def overview(self) -> Dict[str, Any]:
        if not self._ok:
            return {"error": self._err}
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "platform": SYSTEM_SETTINGS["platform_name"],
            "version": SYSTEM_SETTINGS["version"],
            "siem": self.siem.stats(),
            "rules": {
                "total": len(self.rules.rules),
                "alerts_today": len(self.rules.alerts),
            },
            "triage": self.triage.summary(),
            "incident": self.incident.metrics(),
            "intel": self.intel.quality_report(),
            "metrics": self.metrics.dashboard(),
        }

    def threat_wall(self) -> Dict[str, Any]:
        """实时威胁墙：高危告警+活跃事件+命中情报。"""
        if not self._ok:
            return {"error": self._err}
        alerts = self.triage.list_alerts(severity="critical")[:10]
        incidents = self.incident.list(status="investigating")[:5]
        intel_hits = self.intel.match_log[-10:]
        return {
            "critical_alerts": alerts,
            "active_incidents": incidents,
            "intel_hits": list(reversed(intel_hits)),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def kill_chain(self) -> List[Dict[str, Any]]:
        """攻击链视图：把告警按阶段聚合。"""
        stages = ["recon", "weaponize", "delivery", "exploitation",
                  "installation", "c2", "actions"]
        out: List[Dict[str, Any]] = []
        for s in stages:
            cnt = sum(1 for a in self.triage.alerts.values()
                      if s in a.category or s in " ".join(a.tags))
            out.append({"stage": s, "count": cnt})
        return out

    def health(self) -> Dict[str, Any]:
        return {
            "modules_loaded": self._ok,
            "uptime": "simulated",
            "settings": SYSTEM_SETTINGS,
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_instance: Optional[SOCDashboard] = None


def get_soc_dashboard() -> SOCDashboard:
    global _instance
    if _instance is None:
        _instance = SOCDashboard()
    return _instance
