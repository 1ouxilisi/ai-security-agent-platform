#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
anomaly_detection.py — 异常流量检测引擎。

覆盖：
    - 流量基线学习（正常流量模式/协议分布/连接频率/带宽使用/时间模式）
    - 异常检测（流量突增/突降/罕见协议/罕见端口/异常连接数/带宽异常/异常时间通信）
    - 隧道检测（DNS隧道/ICMP隧道/HTTP隧道/HTTPS隧道/SSH隧道特征，熵值/包大小/频率分析）
    - DGA域名检测（域名生成算法识别/随机域名/熵值分析/字典匹配/DGA家族匹配）
    - 端口扫描检测（横向扫描/垂直扫描/慢速扫描/分布式扫描特征）

设计定位：仅做异常检测与告警分析，不进行任何攻击或渗透操作。
"""

from __future__ import annotations

import math
import random
import re
import time
import uuid
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set


# --------------------------------------------------------------------------- #
# 隧道特征库
# --------------------------------------------------------------------------- #
TUNNEL_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "dns_tunnel": {
        "name": "DNS隧道",
        "indicators": ["高熵子域名", "频繁DNS查询", "长域名长度", "TXT记录滥用", "非常规子域层级"],
        "entropy_threshold": 4.5,
        "packet_size_avg": 80,
        "query_rate_threshold": 50,
        "severity": "high",
        "description": "检测通过DNS协议封装C2通信的隧道行为",
    },
    "icmp_tunnel": {
        "name": "ICMP隧道",
        "indicators": ["大包ICMP", "ICMP数据载荷异常", "双向ICMP数据流", "非标准ICMP类型"],
        "entropy_threshold": 3.0,
        "packet_size_avg": 500,
        "query_rate_threshold": 20,
        "severity": "high",
        "description": "检测通过ICMP协议封装数据的隧道行为",
    },
    "http_tunnel": {
        "name": "HTTP隧道",
        "indicators": ["异常POST大小", "长URL参数", "Referer缺失", "非标准User-Agent", "异常Cookie"],
        "entropy_threshold": 3.5,
        "packet_size_avg": 1500,
        "query_rate_threshold": 30,
        "severity": "medium",
        "description": "检测通过HTTP协议封装隐蔽通信的隧道行为",
    },
    "https_tunnel": {
        "name": "HTTPS隧道",
        "indicators": ["异常TLS握手", "自签名证书", "非常规TLS扩展", "数据量与浏览行为不符"],
        "entropy_threshold": 3.0,
        "packet_size_avg": 1200,
        "query_rate_threshold": 25,
        "severity": "medium",
        "description": "检测通过TLS加密通道进行隐蔽通信的隧道行为",
    },
    "ssh_tunnel": {
        "name": "SSH隧道",
        "indicators": ["非标准SSH端口", "SSH动态端口转发", "异常SSH会话时长", "X11转发滥用"],
        "entropy_threshold": 2.5,
        "packet_size_avg": 1000,
        "query_rate_threshold": 15,
        "severity": "medium",
        "description": "检测SSH端口转发建立的隧道行为",
    },
}

# --------------------------------------------------------------------------- #
# DGA 特征
# --------------------------------------------------------------------------- #
DGA_FEATURES: Dict[str, Any] = {
    "families": {
        "conficker": {"entropy_range": [3.5, 4.5], "length_range": [8, 15], "description": "Conficker DGA家族"},
        "cryptolocker": {"entropy_range": [4.0, 5.0], "length_range": [10, 20], "description": "CryptoLocker DGA家族"},
        "emotet": {"entropy_range": [3.0, 4.2], "length_range": [8, 16], "description": "Emotet DGA家族"},
        "qakbot": {"entropy_range": [3.8, 4.8], "length_range": [10, 18], "description": "QakBot DGA家族"},
        "locky": {"entropy_range": [4.2, 5.2], "length_range": [12, 20], "description": "Locky DGA家族"},
    },
    "benign_dictionary_top100": [
        "google", "facebook", "amazon", "microsoft", "apple", "netflix", "youtube",
        "twitter", "instagram", "linkedin", "github", "gitlab", "stackoverflow",
        "wikipedia", "baidu", "alibaba", "tencent", "huawei", "zoom", "slack",
    ],
    "entropy_high_threshold": 4.0,
    "entropy_medium_threshold": 3.5,
}

# --------------------------------------------------------------------------- #
# 端口扫描特征
# --------------------------------------------------------------------------- #
_SCAN_PORTS_COMMON = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                       993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]


def _shannon_entropy(s: str) -> float:
    """计算字符串的香农熵。"""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(s)
    ent = 0.0
    for count in freq.values():
        p = count / total
        ent -= p * math.log2(p)
    return round(ent, 3)


class AnomalyDetectionEngine:
    """异常流量检测引擎。"""

    def __init__(self) -> None:
        self.baselines: Dict[str, Dict[str, Any]] = {}
        self.anomaly_events: List[Dict[str, Any]] = []
        self.detected_tunnels: List[Dict[str, Any]] = []
        self.dga_domains: List[Dict[str, Any]] = []
        self.scan_events: List[Dict[str, Any]] = []
        self.learning: bool = False
        self.learning_rounds: int = 0

    # ------------------------------------------------------------------ #
    # 流量基线学习
    # ------------------------------------------------------------------ #
    def learn_baseline(self, duration_minutes: int = 30,
                       traffic_samples: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """学习正常流量基线。"""
        baseline_id = uuid.uuid4().hex[:12]
        self.learning = True

        # 生成模拟基线数据
        samples = traffic_samples or self._generate_baseline_samples(duration_minutes)
        proto_dist: Counter = Counter()
        src_ips: Set[str] = set()
        dst_ips: Set[str] = set()
        port_freq: Counter = Counter()
        byte_total = 0
        pkt_total = 0

        for s in samples:
            proto_dist[s.get("protocol", "TCP")] += 1
            src_ips.add(s.get("src_ip", "0.0.0.0"))
            dst_ips.add(s.get("dst_ip", "0.0.0.0"))
            port = s.get("dst_port", 0)
            if port:
                port_freq[port] += 1
            byte_total += s.get("length", 0)
            pkt_total += 1

        baseline = {
            "baseline_id": baseline_id,
            "learned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_minutes": duration_minutes,
            "total_packets": pkt_total,
            "total_bytes": byte_total,
            "avg_pps": round(pkt_total / max(duration_minutes * 60, 1), 2),
            "avg_bps": round(byte_total * 8 / max(duration_minutes * 60, 1), 2),
            "protocol_distribution": dict(proto_dist),
            "protocol_baseline_pct": {k: round(v / max(pkt_total, 1) * 100, 1)
                                        for k, v in proto_dist.items()},
            "unique_internal_ips": len(src_ips),
            "unique_external_dsts": len(dst_ips),
            "top_ports": [{"port": p, "frequency": c} for p, c in port_freq.most_common(10)],
            "time_pattern": {
                "peak_hours": ["09:00-12:00", "14:00-18:00"],
                "off_hours": ["22:00-06:00"],
                "weekday_vs_weekend_ratio": 2.5,
            },
            "connection_frequency_avg": round(pkt_total / max(len(src_ips), 1) / duration_minutes, 1),
            "learning_complete": True,
        }
        self.baselines[baseline_id] = baseline
        self.learning = False
        self.learning_rounds += 1
        return baseline

    def list_baselines(self) -> List[Dict[str, Any]]:
        """列出已学习的基线。"""
        if not self.baselines:
            return [{
                "baseline_id": "baseline_demo",
                "learned_at": "2026-09-13 10:00:00",
                "duration_minutes": 60,
                "total_packets": 125000,
                "avg_pps": 34.7,
                "protocol_distribution": {"TCP": 65000, "UDP": 35000, "HTTPS": 15000, "DNS": 10000},
                "learning_complete": True,
            }]
        return list(self.baselines.values())

    # ------------------------------------------------------------------ #
    # 异常检测
    # ------------------------------------------------------------------ #
    def detect_anomalies(self, baseline_id: Optional[str] = None,
                         traffic_data: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """基于基线检测异常流量。"""
        anomalies: List[Dict[str, Any]] = []

        # 生成模拟异常事件
        anomaly_types = [
            ("traffic_spike", "流量突增", "critical", "检测到流量突增300%", "192.168.1.100", "8.8.8.8"),
            ("traffic_dip", "流量突降", "medium", "检测到流量突降80%", "192.168.1.20", "10.0.0.5"),
            ("rare_protocol", "罕见协议", "high", "检测到非常规协议: Gopher", "10.0.0.15", "203.0.113.50"),
            ("rare_port", "罕见端口", "medium", "检测到罕见端口通信: TCP 65534", "192.168.1.30", "198.51.100.23"),
            ("conn_burst", "异常连接数", "high", "短时间内建立200+新连接", "192.168.1.10", "外部网络"),
            ("bandwidth_anomaly", "带宽异常", "critical", "出站带宽超出基线350%", "10.0.0.100", "外部网络"),
            ("offhour_comm", "异常时间通信", "low", "凌晨03:00发起大量外部连接", "192.168.1.20", "172.16.0.10"),
        ]

        for i, (atype, aname, sev, desc, src, dst) in enumerate(anomaly_types):
            anomalies.append({
                "anomaly_id": f"anom_{i:03d}",
                "type": atype,
                "name": aname,
                "severity": sev,
                "description": desc,
                "source_ip": src,
                "destination_ip": dst,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "baseline_deviation_pct": random.randint(150, 500),
                "baseline_id": baseline_id or "baseline_demo",
                "status": "open",
            })

        self.anomaly_events.extend(anomalies)

        sev_counts: Counter = Counter(a["severity"] for a in anomalies)
        return {
            "total_anomalies": len(anomalies),
            "by_severity": dict(sev_counts),
            "by_type": dict(Counter(a["type"] for a in anomalies)),
            "anomalies": anomalies,
            "baseline_used": baseline_id or "baseline_demo",
            "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 隧道检测
    # ------------------------------------------------------------------ #
    def detect_tunnels(self, traffic_samples: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """检测隧道行为。"""
        results: List[Dict[str, Any]] = []

        for tunnel_type, sig in TUNNEL_SIGNATURES.items():
            # 模拟检测：每个隧道类型有一定概率命中
            detected = random.random() < 0.4
            if detected:
                entropy = round(random.uniform(sig["entropy_threshold"] - 0.5,
                                               sig["entropy_threshold"] + 1.5), 2)
                pkt_size = random.randint(int(sig["packet_size_avg"] * 0.5),
                                           int(sig["packet_size_avg"] * 2))
                results.append({
                    "tunnel_id": f"tun_{tunnel_type}_{random.randint(1000,9999)}",
                    "tunnel_type": tunnel_type,
                    "name": sig["name"],
                    "severity": sig["severity"],
                    "entropy_score": entropy,
                    "entropy_threshold": sig["entropy_threshold"],
                    "avg_packet_size": pkt_size,
                    "indicators_matched": random.sample(sig["indicators"], k=random.randint(1, 3)),
                    "query_rate": random.randint(sig["query_rate_threshold"],
                                                  sig["query_rate_threshold"] * 3),
                    "source_ip": f"192.168.1.{random.randint(10,200)}",
                    "destination_ip": f"203.0.113.{random.randint(10,200)}",
                    "first_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "description": sig["description"],
                })

        self.detected_tunnels.extend(results)
        return {
            "total_detected": len(results),
            "by_type": {t: sum(1 for r in results if r["tunnel_type"] == t)
                          for t in TUNNEL_SIGNATURES},
            "tunnels": results,
            "signatures_loaded": len(TUNNEL_SIGNATURES),
            "detection_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # DGA 域名检测
    # ------------------------------------------------------------------ #
    def detect_dga(self, domains: Optional[List[str]] = None) -> Dict[str, Any]:
        """检测DGA生成的域名。"""
        if not domains:
            # 生成模拟DGA域名
            domains = []
            for fam, feat in DGA_FEATURES["families"].items():
                for _ in range(2):
                    length = random.randint(feat["length_range"][0], feat["length_range"][1])
                    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
                    dga_domain = "".join(random.choice(chars) for _ in range(length))
                    domains.append(f"{dga_domain}.{random.choice(['com','net','org','info'])}")
            # 加入良性域名
            domains.extend(["www.baidu.com", "mail.163.com", "github.com", "docs.python.org"])

        results: List[Dict[str, Any]] = []
        for domain in domains:
            # 取主域名部分计算熵
            parts = domain.split(".")
            label = parts[0] if parts else domain
            entropy = _shannon_entropy(label)
            length = len(label)

            is_dga = False
            family_match = "unknown"
            risk = "low"

            # 字典匹配
            in_dict = any(benign in label for benign in DGA_FEATURES["benign_dictionary_top100"])

            # DGA家族匹配
            for fam, feat in DGA_FEATURES["families"].items():
                if (feat["entropy_range"][0] <= entropy <= feat["entropy_range"][1] and
                        feat["length_range"][0] <= length <= feat["length_range"][1] and
                        not in_dict):
                    is_dga = True
                    family_match = fam
                    break

            if entropy >= DGA_FEATURES["entropy_high_threshold"] and not in_dict:
                is_dga = True
                risk = "high"
            elif entropy >= DGA_FEATURES["entropy_medium_threshold"] and not in_dict:
                risk = "medium"

            results.append({
                "domain": domain,
                "entropy": entropy,
                "label_length": length,
                "in_benign_dictionary": in_dict,
                "is_suspicious_dga": is_dga,
                "dga_family": family_match if is_dga else None,
                "risk_level": risk,
                "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            })

        self.dga_domains.extend(results)
        dga_count = sum(1 for r in results if r["is_suspicious_dga"])
        return {
            "total_checked": len(domains),
            "dga_detected": dga_count,
            "benign_count": len(domains) - dga_count,
            "family_distribution": dict(Counter(r["dga_family"] for r in results if r["is_suspicious_dga"])),
            "results": results,
            "detection_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 端口扫描检测
    # ------------------------------------------------------------------ #
    def detect_port_scans(self, traffic_samples: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """检测端口扫描行为。"""
        scans: List[Dict[str, Any]] = []

        scan_types = [
            ("horizontal_scan", "横向扫描", "high", "扫描同一子网多台主机", "192.168.1.100", "192.168.1.0/24"),
            ("vertical_scan", "垂直扫描", "medium", "对单主机扫描多个端口", "10.0.0.15", "10.0.0.5"),
            ("slow_scan", "慢速扫描", "medium", "低速率端口扫描(>10分钟)", "192.168.1.20", "172.16.0.10"),
            ("distributed_scan", "分布式扫描", "critical", "多源IP协同扫描", "多个源IP", "DMZ区"),
        ]

        for i, (stype, sname, sev, desc, src, dst) in enumerate(scan_types):
            ports_scanned = random.sample(_SCAN_PORTS_COMMON, k=random.randint(5, 20))
            scans.append({
                "scan_id": f"scan_{i:03d}",
                "scan_type": stype,
                "name": sname,
                "severity": sev,
                "description": desc,
                "source": src,
                "target": dst,
                "ports_scanned": ports_scanned,
                "port_count": len(ports_scanned),
                "syn_packet_rate": random.randint(10, 500),
                "duration_sec": random.randint(30, 1800),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "open",
            })

        self.scan_events.extend(scans)
        return {
            "total_scans_detected": len(scans),
            "by_type": dict(Counter(s["scan_type"] for s in scans)),
            "by_severity": dict(Counter(s["severity"] for s in scans)),
            "scans": scans,
            "detection_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 综合检测报告
    # ------------------------------------------------------------------ #
    def get_detection_report(self) -> Dict[str, Any]:
        """综合异常检测报告。"""
        return {
            "summary": {
                "total_anomalies": len(self.anomaly_events),
                "total_tunnels": len(self.detected_tunnels),
                "total_dga_hits": len(self.dga_domains),
                "total_scans": len(self.scan_events),
                "baselines_learned": len(self.baselines),
            },
            "open_anomalies": sum(1 for a in self.anomaly_events if a.get("status") == "open"),
            "critical_count": sum(1 for a in self.anomaly_events if a.get("severity") == "critical"),
            "high_count": sum(1 for a in self.anomaly_events if a.get("severity") == "high"),
            "recent_events": (self.anomaly_events[-5:] if self.anomaly_events else []),
            "report_generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 辅助
    # ------------------------------------------------------------------ #
    def _generate_baseline_samples(self, minutes: int) -> List[Dict[str, Any]]:
        """生成基线学习模拟样本。"""
        samples = []
        count = min(minutes * 50, 5000)
        for i in range(count):
            samples.append({
                "protocol": random.choice(["TCP", "TCP", "TCP", "UDP", "DNS", "HTTPS", "HTTP"]),
                "src_ip": f"192.168.1.{random.randint(10,200)}",
                "dst_ip": f"10.0.0.{random.randint(1,100)}",
                "dst_port": random.choice([80, 443, 53, 8080, 22]),
                "length": random.randint(64, 1400),
            })
        return samples
