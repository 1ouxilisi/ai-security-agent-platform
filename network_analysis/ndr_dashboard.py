#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ndr_dashboard.py — NDR运营仪表盘引擎。

覆盖：
    - 实时流量监控大屏（流量速率/连接数/协议分布/告警/Top说话者/Top端口/实时更新）
    - 告警管理（流量告警列表/分诊/确认/误报/升级/关联事件/告警聚合/告警统计）
    - 威胁地图（攻击源地理位置/攻击目标/攻击类型/攻击趋势地图可视化，SVG世界地图+攻击线）
    - 网络健康状态（带宽利用率/异常连接数/告警数/检测覆盖率/数据源状态/接口状态）
    - NDR度量（检测率/误报率/MTTD/告警量趋势/Top威胁类型/Top攻击源/规则命中率/分析师效率）

设计定位：仅做运营监控与度量展示，输出仪表盘数据，不进行任何攻击操作。
"""

from __future__ import annotations

import random
import time
import uuid
from collections import Counter
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# NDR 度量定义
# --------------------------------------------------------------------------- #
NDR_METRICS_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "detection_rate": {
        "name": "威胁检测率", "unit": "%", "target": 95.0,
        "description": "已检测威胁占全部已知威胁的比例",
        "category": "effectiveness",
    },
    "false_positive_rate": {
        "name": "误报率", "unit": "%", "target": 5.0,
        "description": "误报告警占总告警的比例（越低越好）",
        "category": "accuracy",
    },
    "mttd": {
        "name": "平均检测时间MTTD", "unit": "minutes", "target": 15.0,
        "description": "从攻击发生到检测发现的平均时间",
        "category": "efficiency",
    },
    "mttr": {
        "name": "平均响应时间MTTR", "unit": "minutes", "target": 60.0,
        "description": "从检测到处置完成的平均时间",
        "category": "efficiency",
    },
    "alert_volume": {
        "name": "告警量", "unit": "alerts/day", "target": 500,
        "description": "每日产生的告警总数",
        "category": "volume",
    },
    "rule_hit_rate": {
        "name": "规则命中率", "unit": "%", "target": 30.0,
        "description": "活跃规则中至少命中过一次的比例",
        "category": "coverage",
    },
    "analyst_efficiency": {
        "name": "分析师效率", "unit": "alerts/analyst/hour", "target": 20.0,
        "description": "每位分析师每小时分诊处理的告警数",
        "category": "efficiency",
    },
    "coverage_rate": {
        "name": "检测覆盖率", "unit": "%", "target": 90.0,
        "description": "受监控流量占总流量的比例",
        "category": "coverage",
    },
}


class NDRDashboard:
    """NDR运营仪表盘。"""

    def __init__(self) -> None:
        self.alerts: List[Dict[str, Any]] = []
        self.threat_map_data: List[Dict[str, Any]] = []
        self.health_status: Dict[str, Any] = {}
        self.metrics_history: List[Dict[str, Any]] = []
        self._init_demo_alerts()

    # ------------------------------------------------------------------ #
    # 初始化演示告警
    # ------------------------------------------------------------------ #
    def _init_demo_alerts(self) -> None:
        """生成初始演示告警数据。"""
        alert_templates = [
            ("critical", "Emotet C2 Beacon Detected", "malware_c2", "192.168.1.50", "185.220.101.45"),
            ("high", "DNS Tunnel Suspected", "tunnel_dns", "192.168.1.80", "91.219.236.10"),
            ("high", "Horizontal Port Scan", "scan", "192.168.1.100", "192.168.1.0/24"),
            ("medium", "RDP from Untrusted Network", "lateral", "203.0.113.50", "192.168.1.100"),
            ("medium", "DGA Domain Query", "dga", "192.168.1.30", "DNS Server"),
            ("low", "Anomalous TLS Certificate", "behavior", "10.0.0.50", "203.0.113.77"),
            ("critical", "Data Exfiltration Alert", "exfiltration", "192.168.1.200", "45.155.204.88"),
            ("high", "SMB Lateral Movement", "lateral", "192.168.1.10", "192.168.1.100"),
        ]
        for i, (sev, name, category, src, dst) in enumerate(alert_templates):
            self.alerts.append({
                "alert_id": f"ndr_{i:04d}",
                "severity": sev,
                "name": name,
                "category": category,
                "source_ip": src,
                "destination_ip": dst,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": random.choice(["open", "open", "confirmed", "false_positive"]),
                "assigned_analyst": random.choice(["analyst_1", "analyst_2", "analyst_3", None]),
                "related_events": random.randint(0, 5),
            })

    # ------------------------------------------------------------------ #
    # 实时流量监控大屏
    # ------------------------------------------------------------------ #
    def get_realtime_overview(self) -> Dict[str, Any]:
        """实时流量监控大屏数据。"""
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "traffic_rate_mbps": round(random.uniform(100, 800), 1),
            "packets_per_sec": random.randint(5000, 50000),
            "active_connections": random.randint(1000, 15000),
            "new_connections_per_sec": random.randint(50, 500),
            "protocol_distribution": {
                "TCP": random.randint(40, 70),
                "UDP": random.randint(15, 30),
                "HTTPS": random.randint(10, 25),
                "DNS": random.randint(3, 10),
                "ICMP": random.randint(1, 5),
            },
            "alerts_today": len(self.alerts),
            "critical_alerts": sum(1 for a in self.alerts if a["severity"] == "critical"),
            "top_talkers": [
                {"ip": f"192.168.1.{random.randint(10,200)}", "mbps": round(random.uniform(10, 100), 1)}
                for _ in range(5)
            ],
            "top_ports": [
                {"port": p, "usage_pct": round(random.uniform(5, 40), 1)}
                for p in [443, 80, 53, 445, 3389, 22, 8080]
            ],
        }

    # ------------------------------------------------------------------ #
    # 告警管理
    # ------------------------------------------------------------------ #
    def list_alerts(self, status: Optional[str] = None,
                    severity: Optional[str] = None,
                    limit: int = 50) -> Dict[str, Any]:
        """列出告警列表。"""
        alerts = self.alerts
        if status:
            alerts = [a for a in alerts if a["status"] == status]
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]

        return {
            "total_alerts": len(self.alerts),
            "filtered_count": len(alerts),
            "by_status": dict(Counter(a["status"] for a in self.alerts)),
            "by_severity": dict(Counter(a["severity"] for a in self.alerts)),
            "by_category": dict(Counter(a["category"] for a in self.alerts)),
            "alerts": alerts[:limit],
        }

    def triage_alert(self, alert_id: str, action: str,
                     analyst: str = "auto", notes: str = "") -> Dict[str, Any]:
        """分诊/确认/升级/标记误报告警。"""
        for a in self.alerts:
            if a["alert_id"] == alert_id:
                action_map = {
                    "confirm": ("confirmed", "告警已确认"),
                    "false_positive": ("false_positive", "已标记为误报"),
                    "escalate": ("escalated", "已升级处理"),
                    "close": ("closed", "已关闭"),
                }
                new_status, msg = action_map.get(action, (a["status"], "未知操作"))
                a["status"] = new_status
                a["triaged_by"] = analyst
                a["triaged_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                a["notes"] = notes
                return {"alert_id": alert_id, "action": action, "result": msg,
                         "new_status": new_status, "alert": a}
        return {"alert_id": alert_id, "error": "告警不存在"}

    def get_alert_statistics(self) -> Dict[str, Any]:
        """告警统计。"""
        return {
            "total": len(self.alerts),
            "open": sum(1 for a in self.alerts if a["status"] == "open"),
            "confirmed": sum(1 for a in self.alerts if a["status"] == "confirmed"),
            "false_positive": sum(1 for a in self.alerts if a["status"] == "false_positive"),
            "critical": sum(1 for a in self.alerts if a["severity"] == "critical"),
            "high": sum(1 for a in self.alerts if a["severity"] == "high"),
            "medium": sum(1 for a in self.alerts if a["severity"] == "medium"),
            "low": sum(1 for a in self.alerts if a["severity"] == "low"),
            "by_category": dict(Counter(a["category"] for a in self.alerts)),
            "avg_age_hours": round(random.uniform(1, 48), 1),
        }

    # ------------------------------------------------------------------ #
    # 威胁地图
    # ------------------------------------------------------------------ #
    def get_threat_map(self) -> Dict[str, Any]:
        """威胁地图数据（SVG世界地图+攻击线）。"""
        # 模拟攻击源地理位置
        sources = [
            {"country": "俄罗斯", "city": "Moscow", "lat": 55.75, "lon": 37.61, "count": random.randint(10, 100)},
            {"country": "美国", "city": "California", "lat": 36.77, "lon": -119.41, "count": random.randint(5, 50)},
            {"country": "荷兰", "city": "Amsterdam", "lat": 52.37, "lon": 4.90, "count": random.randint(3, 30)},
            {"country": "德国", "city": "Frankfurt", "lat": 50.11, "lon": 8.68, "count": random.randint(2, 20)},
            {"country": "中国", "city": "Beijing", "lat": 39.90, "lon": 116.40, "count": random.randint(1, 15)},
            {"country": "巴西", "city": "Sao Paulo", "lat": -23.55, "lon": -46.63, "count": random.randint(1, 10)},
            {"country": "印度", "city": "Mumbai", "lat": 19.07, "lon": 72.87, "count": random.randint(2, 15)},
        ]
        target = {"country": "中国", "city": "Target Network", "lat": 30.57, "lon": 104.07}

        attack_lines = []
        for s in sources:
            attack_lines.append({
                "source": s,
                "target": target,
                "attack_type": random.choice(["C2通信", "端口扫描", "数据渗出", "DGA查询", "暴力破解"]),
                "intensity": s["count"],
            })

        threat_types = [
            {"name": "恶意软件C2", "count": sum(1 for a in self.alerts if a["category"] == "malware_c2")},
            {"name": "端口扫描", "count": sum(1 for a in self.alerts if a["category"] == "scan")},
            {"name": "横向移动", "count": sum(1 for a in self.alerts if a["category"] == "lateral")},
            {"name": "数据渗出", "count": sum(1 for a in self.alerts if a["category"] == "exfiltration")},
            {"name": "隧道检测", "count": sum(1 for a in self.alerts if a["category"] == "tunnel_dns")},
        ]

        return {
            "attack_sources": sources,
            "target": target,
            "attack_lines": attack_lines,
            "threat_types": threat_types,
            "total_attacks_tracked": sum(s["count"] for s in sources),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 网络健康状态
    # ------------------------------------------------------------------ #
    def get_health_status(self) -> Dict[str, Any]:
        """网络健康状态。"""
        interfaces = [
            {"name": "eth0", "status": "up", "speed_gbps": 1.0, "utilization_pct": round(random.uniform(20, 80), 1),
             "errors": random.randint(0, 5)},
            {"name": "eth1", "status": "up", "speed_gbps": 10.0, "utilization_pct": round(random.uniform(10, 60), 1),
             "errors": random.randint(0, 2)},
            {"name": "monitor0", "status": "up", "speed_gbps": 10.0, "utilization_pct": round(random.uniform(30, 90), 1),
             "errors": 0},
        ]

        data_sources = [
            {"name": "core_switch_mirror", "status": "online", "last_seen": "2026-09-14 12:00:00",
             "packets_processed": random.randint(1000000, 50000000)},
            {"name": "edge_firewall_log", "status": "online", "last_seen": "2026-09-14 12:00:01",
             "packets_processed": random.randint(500000, 10000000)},
            {"name": "endpoint_telemetry", "status": "degraded", "last_seen": "2026-09-14 11:58:00",
             "packets_processed": random.randint(100000, 1000000)},
        ]

        return {
            "overall_health": random.choice(["good", "good", "warning"]),
            "bandwidth_utilization_pct": round(random.uniform(25, 75), 1),
            "abnormal_connections": random.randint(10, 200),
            "active_alerts": sum(1 for a in self.alerts if a["status"] in ("open", "confirmed")),
            "detection_coverage_pct": round(random.uniform(85, 99), 1),
            "interfaces": interfaces,
            "data_sources": data_sources,
            "cpu_usage_pct": round(random.uniform(20, 70), 1),
            "memory_usage_pct": round(random.uniform(30, 80), 1),
            "disk_usage_pct": round(random.uniform(40, 85), 1),
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # NDR 度量
    # ------------------------------------------------------------------ #
    def get_metrics(self) -> Dict[str, Any]:
        """NDR运营度量指标。"""
        metrics = {}
        for key, definition in NDR_METRICS_DEFINITIONS.items():
            metrics[key] = {
                **definition,
                "current_value": round(random.uniform(definition["target"] * 0.7,
                                                        definition["target"] * 1.3), 2),
                "target_value": definition["target"],
                "status": random.choice(["on_track", "on_track", "needs_attention"]),
            }

        # 告警趋势（过去7天）
        alert_trend = []
        for i in range(7):
            alert_trend.append({
                "date": time.strftime("%Y-%m-%d", time.gmtime(time.time() - (6 - i) * 86400)),
                "alert_count": random.randint(50, 500),
                "critical_count": random.randint(0, 20),
            })

        return {
            "metrics": metrics,
            "alert_trend_7d": alert_trend,
            "top_threat_types": self.get_threat_map()["threat_types"],
            "top_attack_sources": self.get_threat_map()["attack_sources"][:5],
            "rule_hit_rate": round(random.uniform(20, 50), 1),
            "analyst_efficiency": round(random.uniform(10, 30), 1),
            "metrics_generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 仪表盘总览
    # ------------------------------------------------------------------ #
    def get_dashboard_overview(self) -> Dict[str, Any]:
        """仪表盘总览数据。"""
        return {
            "realtime": self.get_realtime_overview(),
            "alerts_summary": self.get_alert_statistics(),
            "health": self.get_health_status(),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
