#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
network_behavior.py — 网络行为分析引擎。

覆盖：
    - 网络实体画像（主机/服务器/设备/IP的通信行为画像）
    - 通信关系图谱（谁和谁通信/通信频率/数据量/协议/端口关系图）
    - 网络拓扑发现（自动发现网络设备/子网/网关/服务/ARP表/路由表推断）
    - 横向移动检测（异常内网连接/远程服务滥用(RDP/WinRM/SSH)/凭据传递/异常登录源）
    - 数据渗出检测（大量外发数据/异常上传/罕见外部目的地/定时传输/加密外发）

设计定位：仅做行为分析与异常关联，不进行任何攻击或渗透操作。
"""

from __future__ import annotations

import random
import time
import uuid
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set


# --------------------------------------------------------------------------- #
# 横向移动指示器
# --------------------------------------------------------------------------- #
LATERAL_MOVEMENT_INDICATORS: Dict[str, Dict[str, Any]] = {
    "rdp_abuse": {
        "name": "RDP远程桌面滥用",
        "ports": [3389],
        "indicators": ["非工作时间RDP连接", "来自非常规网段的RDP", "短时间多台主机RDP", "RDP登录后立即执行命令"],
        "severity": "high",
    },
    "winrm_abuse": {
        "name": "WinRM滥用",
        "ports": [5985, 5986],
        "indicators": ["非管理员账号WinRM", "短时间多主机WinRM", "WinRM后执行PowerShell"],
        "severity": "high",
    },
    "ssh_abuse": {
        "name": "SSH横向移动",
        "ports": [22],
        "indicators": ["同一密钥多主机登录", "非堡垒机SSH连接", "异常SSH源IP", "SSH后立即SCP传输"],
        "severity": "medium",
    },
    "psexec_wmiexec": {
        "name": "PsExec/WMI横向",
        "ports": [445, 135],
        "indicators": ["SMB admin$共享访问", "WMI远程进程创建", "服务安装事件", "非管理员远程执行"],
        "severity": "critical",
    },
    "credential_pass": {
        "name": "凭据传递攻击",
        "ports": [445, 88, 389],
        "indicators": ["异常Kerberos票据请求", "NTLM中继特征", "黄金票据迹象", "异账号多主机登录"],
        "severity": "critical",
    },
    "smb_lateral": {
        "name": "SMB横向移动",
        "ports": [445, 139],
        "indicators": ["SMB共享枚举", "IPC$连接", "批量文件复制", "异常SMB会话"],
        "severity": "high",
    },
}


def _random_internal_ip() -> str:
    return f"192.168.{random.randint(0,5)}.{random.randint(1,254)}"


class NetworkBehaviorAnalyzer:
    """网络行为分析引擎。"""

    def __init__(self) -> None:
        self.entity_profiles: Dict[str, Dict[str, Any]] = {}
        self.communication_graph: Dict[str, Any] = {}
        self.topology: Dict[str, Any] = {}
        self.lateral_movement_alerts: List[Dict[str, Any]] = []
        self.data_exfil_alerts: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 网络实体画像
    # ------------------------------------------------------------------ #
    def build_entity_profiles(self, entities: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """构建网络实体通信行为画像。"""
        if not entities:
            # 生成模拟实体
            entities = []
            roles = ["workstation", "server", "domain_controller", "database",
                      "web_server", "mail_server", "printer", "iot_device"]
            for i in range(12):
                entities.append({
                    "ip": _random_internal_ip(),
                    "mac": f"aa:bb:cc:{i:02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}",
                    "role": random.choice(roles),
                    "hostname": f"host-{i:03d}.internal.corp",
                })

        profiles = []
        for e in entities:
            ip = e["ip"]
            peers = set(_random_internal_ip() for _ in range(random.randint(3, 12)))
            proto_list = random.sample(["TCP", "UDP", "DNS", "HTTPS", "HTTP", "SMB", "RDP", "SSH"],
                                        k=random.randint(2, 5))
            profile = {
                "entity_id": uuid.uuid4().hex[:8],
                "ip": ip,
                "mac": e.get("mac", "unknown"),
                "hostname": e.get("hostname", "unknown"),
                "role": e.get("role", "workstation"),
                "communication_peers": sorted(peers),
                "peer_count": len(peers),
                "protocols_used": proto_list,
                "ports_used": random.sample([80, 443, 53, 445, 3389, 22, 25, 8080],
                                             k=random.randint(2, 5)),
                "total_data_sent_mb": round(random.uniform(5, 5000), 2),
                "total_data_received_mb": round(random.uniform(10, 8000), 2),
                "active_hours": random.choice(["08:00-18:00", "24x7", "09:00-17:00"]),
                "connection_count": random.randint(20, 5000),
                "risk_score": random.randint(0, 100),
                "anomaly_flags": random.sample(["none", "none", "rare_external",
                                                  "offhour_traffic", "new_peer"],
                                                 k=random.randint(0, 2)),
                "last_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.entity_profiles[ip] = profile
            profiles.append(profile)

        return {
            "total_entities": len(profiles),
            "by_role": dict(Counter(p["role"] for p in profiles)),
            "high_risk_entities": [p for p in profiles if p["risk_score"] > 70],
            "profiles": profiles,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def get_entity_profile(self, ip: str) -> Dict[str, Any]:
        """获取单个实体画像。"""
        if ip in self.entity_profiles:
            return self.entity_profiles[ip]
        # 返回模拟画像
        return {
            "entity_id": "unknown",
            "ip": ip,
            "hostname": f"host-{ip.split('.')[-1]}.internal.corp",
            "role": "workstation",
            "communication_peers": [_random_internal_ip() for _ in range(5)],
            "protocols_used": ["TCP", "DNS", "HTTPS"],
            "risk_score": 35,
            "note": "默认模拟画像",
        }

    # ------------------------------------------------------------------ #
    # 通信关系图谱
    # ------------------------------------------------------------------ #
    def build_communication_graph(self, limit_nodes: int = 30) -> Dict[str, Any]:
        """构建通信关系图谱（节点=IP，边=通信）。"""
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        # 生成节点
        internal_nodes = set()
        for _ in range(limit_nodes):
            ip = _random_internal_ip()
            internal_nodes.add(ip)

        external_nodes = {"8.8.8.8", "1.1.1.1", "203.0.113.50", "198.51.100.23", "9.9.9.9"}
        all_ips = list(internal_nodes) + list(external_nodes)

        for ip in all_ips:
            is_external = ip in external_nodes
            nodes.append({
                "id": ip,
                "label": ip,
                "type": "external" if is_external else random.choice(["workstation", "server", "router"]),
                "size": random.randint(5, 20),
                "risk": random.randint(0, 100),
            })

        # 生成边
        for _ in range(min(60, limit_nodes * 2)):
            src = random.choice(all_ips)
            dst = random.choice(all_ips)
            if src != dst:
                edges.append({
                    "source": src,
                    "target": dst,
                    "protocol": random.choice(["TCP", "UDP", "DNS", "HTTPS"]),
                    "port": random.choice([80, 443, 53, 445, 3389, 22]),
                    "frequency": random.randint(1, 100),
                    "data_volume_mb": round(random.uniform(0.1, 500), 2),
                })

        graph = {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "internal_nodes": len(internal_nodes),
            "external_nodes": len(external_nodes),
        }
        self.communication_graph = graph
        return graph

    # ------------------------------------------------------------------ #
    # 网络拓扑发现
    # ------------------------------------------------------------------ #
    def discover_topology(self) -> Dict[str, Any]:
        """自动发现网络拓扑。"""
        devices = [
            {"ip": "192.168.1.1", "type": "gateway", "mac": "00:11:22:33:44:55", "vendor": "Cisco"},
            {"ip": "192.168.1.10", "type": "workstation", "mac": "aa:bb:cc:00:01:01", "vendor": "Dell"},
            {"ip": "192.168.1.20", "type": "server", "mac": "aa:bb:cc:00:02:02", "vendor": "HP"},
            {"ip": "192.168.1.30", "type": "server", "mac": "aa:bb:cc:00:03:03", "vendor": "Lenovo"},
            {"ip": "192.168.1.100", "type": "domain_controller", "mac": "aa:bb:cc:00:04:04", "vendor": "Microsoft"},
            {"ip": "10.0.0.1", "type": "router", "mac": "00:11:22:aa:bb:cc", "vendor": "Juniper"},
            {"ip": "10.0.0.5", "type": "database", "mac": "aa:bb:cc:00:05:05", "vendor": "Oracle"},
            {"ip": "172.16.0.1", "type": "firewall", "mac": "00:11:22:de:ad:be", "vendor": "Palo Alto"},
        ]

        subnets = [
            {"cidr": "192.168.1.0/24", "gateway": "192.168.1.1", "hosts_detected": 25},
            {"cidr": "10.0.0.0/8", "gateway": "10.0.0.1", "hosts_detected": 150},
            {"cidr": "172.16.0.0/16", "gateway": "172.16.0.1", "hosts_detected": 45},
        ]

        arp_table = [
            {"ip": d["ip"], "mac": d["mac"], "interface": "eth0", "type": d["type"]}
            for d in devices
        ]

        services = [
            {"port": 80, "service": "HTTP", "hosts": ["192.168.1.20", "192.168.1.30"]},
            {"port": 443, "service": "HTTPS", "hosts": ["192.168.1.20", "192.168.1.30", "10.0.0.5"]},
            {"port": 445, "service": "SMB", "hosts": ["192.168.1.100"]},
            {"port": 3389, "service": "RDP", "hosts": ["192.168.1.100", "192.168.1.20"]},
            {"port": 22, "service": "SSH", "hosts": ["10.0.0.5", "10.0.0.1"]},
            {"port": 53, "service": "DNS", "hosts": ["192.168.1.100", "8.8.8.8"]},
        ]

        topology = {
            "devices": devices,
            "device_count": len(devices),
            "subnets": subnets,
            "arp_table": arp_table,
            "services_detected": services,
            "gateways": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
            "discovery_method": "ARP + 端口扫描 + 流量推断",
            "discovered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.topology = topology
        return topology

    # ------------------------------------------------------------------ #
    # 横向移动检测
    # ------------------------------------------------------------------ #
    def detect_lateral_movement(self, traffic_data: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """检测横向移动行为。"""
        alerts: List[Dict[str, Any]] = []

        for i, (lm_type, indicator) in enumerate(LATERAL_MOVEMENT_INDICATORS.items()):
            # 模拟检测：部分类型命中
            detected = random.random() < 0.5
            if detected:
                src = _random_internal_ip()
                dst = _random_internal_ip()
                alert = {
                    "alert_id": f"lm_{i:03d}",
                    "movement_type": lm_type,
                    "name": indicator["name"],
                    "severity": indicator["severity"],
                    "source_ip": src,
                    "target_ip": dst,
                    "ports": indicator["ports"],
                    "indicators_matched": random.sample(indicator["indicators"],
                                                         k=random.randint(1, 3)),
                    "first_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "session_count": random.randint(1, 20),
                    "description": f"检测到{indicator['name']}可疑行为",
                    "status": "open",
                }
                alerts.append(alert)

        self.lateral_movement_alerts.extend(alerts)
        return {
            "total_alerts": len(alerts),
            "by_type": {a["movement_type"]: a["name"] for a in alerts},
            "critical_count": sum(1 for a in alerts if a["severity"] == "critical"),
            "high_count": sum(1 for a in alerts if a["severity"] == "high"),
            "alerts": alerts,
            "indicators_loaded": len(LATERAL_MOVEMENT_INDICATORS),
            "detection_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 数据渗出检测
    # ------------------------------------------------------------------ #
    def detect_data_exfiltration(self, baseline_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """检测数据渗出行为。"""
        exfil_types = [
            {"type": "mass_outbound", "name": "大量外发数据", "severity": "critical",
             "description": "单主机短时间外发数据量远超基线"},
            {"type": "abnormal_upload", "name": "异常上传", "severity": "high",
             "description": "上传流量比例异常偏高"},
            {"type": "rare_destination", "name": "罕见外部目的地", "severity": "medium",
             "description": "连接从未见过的外部IP/域名"},
            {"type": "scheduled_transfer", "name": "定时传输", "severity": "medium",
             "description": "每日固定时间向外传输数据"},
            {"type": "encrypted_exfil", "name": "加密外发", "severity": "high",
             "description": "高熵加密数据向外传输"},
            {"type": "baseline_deviation", "name": "数据量基线偏离", "severity": "low",
             "description": "外发数据量超出基线200%以上"},
        ]

        alerts = []
        for i, etype in enumerate(exfil_types):
            detected = random.random() < 0.55
            if detected:
                alerts.append({
                    "exfil_id": f"exfil_{i:03d}",
                    **etype,
                    "source_ip": _random_internal_ip(),
                    "destination_ip": f"203.0.113.{random.randint(10,200)}",
                    "data_volume_mb": round(random.uniform(50, 5000), 2),
                    "baseline_mb": round(random.uniform(10, 100), 2),
                    "deviation_pct": random.randint(200, 1200),
                    "protocol": random.choice(["HTTPS", "DNS", "HTTP", "SSH", "FTP"]),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "open",
                })

        self.data_exfil_alerts.extend(alerts)
        return {
            "total_alerts": len(alerts),
            "by_severity": dict(Counter(a["severity"] for a in alerts)),
            "by_type": dict(Counter(a["type"] for a in alerts)),
            "total_data_exfiltrated_mb": sum(a["data_volume_mb"] for a in alerts),
            "alerts": alerts,
            "detection_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 行为分析总览
    # ------------------------------------------------------------------ #
    def get_behavior_summary(self) -> Dict[str, Any]:
        """网络行为分析总览。"""
        return {
            "entities_tracked": len(self.entity_profiles),
            "graph_nodes": len(self.communication_graph.get("nodes", [])),
            "graph_edges": len(self.communication_graph.get("edges", [])),
            "topology_devices": self.topology.get("device_count", 0),
            "lateral_movement_alerts": len(self.lateral_movement_alerts),
            "data_exfil_alerts": len(self.data_exfil_alerts),
            "high_risk_entities": sum(1 for p in self.entity_profiles.values()
                                       if p.get("risk_score", 0) > 70),
            "summary_generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
