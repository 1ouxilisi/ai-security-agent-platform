#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
edr_dashboard.py — EDR 运营仪表盘模块。

覆盖：
    - 终端安全态势：终端总数/在线数/风险终端数/告警数/隔离终端数/漏洞数/补丁覆盖率/Agent覆盖率
    - 实时告警流：最新告警/告警级别/告警类型/受影响终端/响应状态/告警详情/告警时间线
    - 威胁地图：攻击源/攻击目标/攻击类型/横向移动路径/感染范围可视化(SVG拓扑+攻击线)
    - 终端健康状态：CPU/内存/磁盘/网络/Agent状态/最后通信/离线终端/资源告警/健康评分
    - EDR度量：检测率/误报率/MTTD/MTTR/告警量趋势/Top威胁类型/隔离次数/响应动作统计/漏洞修复率

设计定位：仅做运营度量、可视化与态势感知视角，输出KPI与趋势报告。
"""

from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional


class EDRDashboard:
    """EDR 运营仪表盘：态势、告警流、威胁地图、健康、度量。"""

    def __init__(self) -> None:
        self._alerts_stream: List[Dict[str, Any]] = []
        self._threat_map_nodes: List[Dict[str, Any]] = []
        self._seed_demo()

    def _seed_demo(self) -> None:
        severities = ["critical", "high", "medium", "low"]
        alert_types = ["恶意软件检测", "异常进程", "可疑命令行", "进程注入",
                       "勒索软件行为", "持久化检测", "横向移动", "C2通信"]
        for i in range(20):
            self._alerts_stream.append({
                "alert_id": f"STR-{i:03d}",
                "time": time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(time.time() - random.randint(10, 7200))),
                "severity": random.choices(severities, weights=[10, 30, 40, 20])[0],
                "type": random.choice(alert_types),
                "asset_id": f"EP-{random.randint(1,40):04d}",
                "hostname": f"HOST-{random.randint(1,40):04d}",
                "status": random.choice(["new", "triaged", "contained", "resolved"]),
                "detail": f"检测到{random.choice(alert_types)}行为",
            })
        self._alerts_stream.sort(key=lambda x: x["time"], reverse=True)
        # 威胁地图节点
        self._threat_map_nodes = [
            {"id": "attacker", "label": "外部攻击者", "type": "attacker",
             "x": 80, "y": 200, "ip": "185.220.101.45"},
            {"id": "ep0007", "label": "EP-0007", "type": "infected",
             "x": 300, "y": 120, "ip": "10.20.5.17"},
            {"id": "ep0012", "label": "EP-0012", "type": "infected",
             "x": 300, "y": 280, "ip": "10.20.5.22"},
            {"id": "ep0003", "label": "EP-0003", "type": "watch",
             "x": 520, "y": 100, "ip": "10.20.5.10"},
            {"id": "ep0019", "label": "EP-0019", "type": "watch",
             "x": 520, "y": 300, "ip": "10.20.5.31"},
            {"id": "server", "label": "文件服务器", "type": "server",
             "x": 740, "y": 200, "ip": "10.20.1.100"},
        ]

    # ------------------------------------------------------------------ #
    # 终端安全态势
    # ------------------------------------------------------------------ #
    def security_posture(self) -> Dict[str, Any]:
        return {
            "total_endpoints": 40,
            "online": 35,
            "offline": 5,
            "risk_endpoints": 8,
            "critical_risk_endpoints": 3,
            "total_alerts_today": 23,
            "alerts_unresolved": 12,
            "isolated_endpoints": 2,
            "total_vulnerabilities": 8,
            "critical_vulnerabilities": 3,
            "patch_compliance_pct": 68.5,
            "agent_coverage_pct": 92.5,
            "agent_missing": 3,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 实时告警流
    # ------------------------------------------------------------------ #
    def realtime_alerts(self, limit: int = 20) -> Dict[str, Any]:
        items = self._alerts_stream[:limit]
        by_severity = {}
        by_type = {}
        for a in self._alerts_stream:
            by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
            by_type[a["type"]] = by_type.get(a["type"], 0) + 1
        return {
            "alerts": items,
            "total": len(self._alerts_stream),
            "by_severity": by_severity,
            "by_type": by_type,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 威胁地图
    # ------------------------------------------------------------------ #
    def threat_map(self) -> Dict[str, Any]:
        edges = [
            {"from": "attacker", "to": "ep0007", "type": "initial_access",
             "protocol": "HTTPS", "port": 443},
            {"from": "attacker", "to": "ep0012", "type": "phishing",
             "protocol": "SMTP", "port": 25},
            {"from": "ep0007", "to": "ep0003", "type": "lateral_movement",
             "protocol": "SMB", "port": 445},
            {"from": "ep0007", "to": "ep0019", "type": "lateral_movement",
             "protocol": "RDP", "port": 3389},
            {"from": "ep0012", "to": "server", "type": "data_exfil",
             "protocol": "SMB", "port": 445},
            {"from": "ep0007", "to": "attacker", "type": "c2",
             "protocol": "HTTPS", "port": 8443},
        ]
        return {
            "nodes": self._threat_map_nodes,
            "edges": edges,
            "infected_count": 2,
            "watch_count": 2,
            "attack_sources": ["185.220.101.45", "104.244.74.15"],
            "attack_types": ["钓鱼投递", "漏洞利用", "横向移动", "C2通信"],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 终端健康状态
    # ------------------------------------------------------------------ #
    def endpoint_health(self) -> Dict[str, Any]:
        online = 35
        offline = 5
        high_cpu = random.randint(2, 5)
        high_mem = random.randint(3, 7)
        high_disk = random.randint(1, 4)
        agent_down = 3
        health_scores = [random.randint(60, 98) for _ in range(online)]
        return {
            "total": 40,
            "online": online,
            "offline": offline,
            "avg_cpu_pct": round(random.uniform(25, 45), 1),
            "avg_memory_pct": round(random.uniform(40, 65), 1),
            "avg_disk_pct": round(random.uniform(50, 75), 1),
            "high_cpu_count": high_cpu,
            "high_memory_count": high_mem,
            "high_disk_count": high_disk,
            "agent_down_count": agent_down,
            "avg_health_score": round(sum(health_scores) / max(len(health_scores), 1), 1),
            "offline_list": [
                {"asset_id": f"EP-{i:04d}", "hostname": f"HOST-{i:04d}",
                 "last_seen": f"{random.randint(1,7)}天前"}
                for i in range(30, 35)
            ],
            "resource_alerts": [
                {"asset_id": f"EP-{i:04d}", "type": random.choice(["CPU过高", "内存过高", "磁盘不足"]),
                 "value": f"{random.randint(80,99)}%"}
                for i in range(5)
            ],
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # EDR 度量
    # ------------------------------------------------------------------ #
    def edr_metrics(self) -> Dict[str, Any]:
        return {
            "detection_rate_pct": 94.2,
            "false_positive_rate_pct": 3.8,
            "mttd_minutes": 12.5,
            "mttr_minutes": 45.0,
            "alert_volume_trend": [
                {"day": "周一", "count": 18},
                {"day": "周二", "count": 25},
                {"day": "周三", "count": 15},
                {"day": "周四", "count": 30},
                {"day": "周五", "count": 22},
                {"day": "周六", "count": 8},
                {"day": "周日", "count": 5},
            ],
            "top_threat_types": [
                {"type": "恶意软件检测", "count": 45},
                {"type": "异常进程", "count": 32},
                {"type": "可疑命令行", "count": 28},
                {"type": "进程注入", "count": 12},
                {"type": "持久化检测", "count": 10},
            ],
            "isolation_count_week": 5,
            "response_action_stats": {
                "isolate_endpoint": 5,
                "terminate_process": 12,
                "delete_file": 8,
                "collect_evidence": 6,
                "start_scan": 15,
            },
            "vuln_fix_rate_pct": 72.5,
            "patch_coverage_pct": 68.5,
            "analyst_efficiency_score": 81.0,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


# --------------------------------------------------------------------------- #
# 模块级单例
# --------------------------------------------------------------------------- #
_default_dashboard: Optional[EDRDashboard] = None


def get_dashboard() -> EDRDashboard:
    global _default_dashboard
    if _default_dashboard is None:
        _default_dashboard = EDRDashboard()
    return _default_dashboard
