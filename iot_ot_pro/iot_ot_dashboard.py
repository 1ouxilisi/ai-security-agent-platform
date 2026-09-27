# -*- coding: utf-8 -*-
"""
iot_ot_dashboard.py — 工控IoT 大屏仪表盘。

KPI: 设备数/已扫描/漏洞数/高危数/告警数/合规率
分布: 按类型/厂商/位置/协议
趋势: 漏洞 24h/7d/30d
热力: 按位置/业务线/设备类型
协议分布: 工控/IoT/通用
其他: 风险矩阵 / Top风险设备 / 流量异常统计 / 合规状态 / 实时告警
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from .device_discovery_phase import get_device_discovery_phase
from .vuln_detection_phase import get_vuln_detection_phase
from .traffic_monitor_phase import get_traffic_monitor_phase
from .risk_rating_phase import get_risk_rating_phase
from .compliance_audit_phase import get_compliance_audit_phase


class IotOtDashboard:
    """工控IoT 大屏聚合器。"""

    def __init__(self) -> None:
        self.disc = get_device_discovery_phase()
        self.vuln = get_vuln_detection_phase()
        self.traf = get_traffic_monitor_phase()
        self.risk = get_risk_rating_phase()
        self.comp = get_compliance_audit_phase()

    # ------------------------------------------------------------------ #
    def kpi(self) -> Dict[str, Any]:
        ds = self.disc.stats()
        vs = self.vuln.stats()
        ts = self.traf.stats()
        cs = self.comp.summary()
        return {
            "devices_total": ds["total"],
            "devices_scanned": ds["total"],
            "vulns_total": vs["total"],
            "vulns_high": vs["by_severity"].get("critical", 0)
                          + vs["by_severity"].get("high", 0),
            "alerts_total": ts["total"],
            "compliance_rate": cs["overall_score"],
        }

    # ------------------------------------------------------------------ #
    def device_distribution(self) -> Dict[str, Any]:
        ds = self.disc.stats()
        return {
            "by_type": ds["by_type"],
            "by_vendor": ds["by_vendor"],
            "by_protocol": ds["by_protocol"],
            "by_location": {"车间A": 2, "车间B": 1, "车间C": 1,
                            "办公楼": 2, "园区": 1},
        }

    def protocol_distribution(self) -> Dict[str, Any]:
        return {
            "ics": {"modbus_tcp": 3, "s7": 1, "opc_ua": 2,
                    "dnp3": 1, "bacnet": 1},
            "iot": {"mqtt": 1, "coap": 1, "rtsp": 1, "ssdp": 1},
            "general": {"http": 4, "ssh": 2, "snmp": 1, "telnet": 1},
        }

    # ------------------------------------------------------------------ #
    def vuln_trend(self, window: str = "7d") -> List[Dict[str, Any]]:
        points = {"24h": 24, "7d": 7, "30d": 30}.get(window, 7)
        rng = random.Random(21)
        base = max(5, self.vuln.stats()["total"] or 8)
        series = []
        for i in range(points):
            series.append({"label": f"T-{points-i}",
                           "new": max(1, int(base * (0.3 + rng.random())))})
        return series[::-1]

    def severity_distribution(self) -> Dict[str, int]:
        return self.vuln.stats()["by_severity"]

    # ------------------------------------------------------------------ #
    def risk_heatmap(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        locations = ["车间A", "车间B", "车间C", "办公楼", "园区"]
        bizs = ["关键生产", "重要生产", "辅助系统"]
        rng = random.Random(11)
        for loc in locations:
            for biz in bizs:
                rows.append({"location": loc, "business": biz,
                             "value": rng.randint(5, 95)})
        return rows

    def top_risks(self, n: int = 10) -> List[Dict[str, Any]]:
        return self.risk.top_risks(n)

    def risk_matrix(self) -> Dict[str, Any]:
        return self.risk.risk_matrix()

    # ------------------------------------------------------------------ #
    def traffic_stats(self) -> Dict[str, Any]:
        return self.traf.stats()

    def recent_alerts(self, limit: int = 15) -> List[Dict[str, Any]]:
        return self.traf.list_alerts()[:limit]

    def compliance_status(self) -> Dict[str, Any]:
        return self.comp.summary()

    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        kpi = self.kpi()
        return {
            "kpi": kpi,
            "severity": self.severity_distribution(),
            "device_distribution": self.device_distribution(),
            "protocol_distribution": self.protocol_distribution(),
            "top_risks": self.top_risks(5),
            "recent_alerts": self.recent_alerts(8),
            "compliance": self.compliance_status(),
        }

    def full_screen(self) -> Dict[str, Any]:
        return {
            "kpi": self.kpi(),
            "device_distribution": self.device_distribution(),
            "protocol_distribution": self.protocol_distribution(),
            "vuln_trend": self.vuln_trend("7d"),
            "severity": self.severity_distribution(),
            "risk_heatmap": self.risk_heatmap(),
            "risk_matrix": self.risk_matrix(),
            "top_risks": self.top_risks(10),
            "traffic": self.traffic_stats(),
            "recent_alerts": self.recent_alerts(15),
            "compliance": self.compliance_status(),
        }


_default: Optional[IotOtDashboard] = None


def get_dashboard() -> IotOtDashboard:
    global _default
    if _default is None:
        _default = IotOtDashboard()
    return _default
