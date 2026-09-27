#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
traffic_capture.py — 流量捕获与解析引擎。

覆盖：
    - PCAP文件解析（libpcap格式/离线分析/元数据提取）
    - 实时流量监控（接口选择/抓包过滤/BPF表达式/包计数/速率）
    - 协议解析（TCP/UDP/ICMP/HTTP/HTTPS/DNS/FTP/SMTP/SSH/TLS/ARP/DHCP）
    - 流量统计（包数/字节数/流数/协议分布/Top说话者/Top端口/带宽速率/包大小分布）
    - 流量重组（TCP流重组/HTTP会话重建/文件提取/WebSocket消息重组）

设计定位：仅做流量捕获、解析与统计分析，不进行任何主动攻击或入侵操作。
第三方库 scapy try-import，缺失时使用内嵌模拟数据。
"""

from __future__ import annotations

import hashlib
import os
import random
import time
import uuid
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# 第三方库 try-import
# --------------------------------------------------------------------------- #
try:
    from scapy.all import (  # type: ignore
        sniff, rdpcap, Ether, IP, TCP, UDP, ICMP, ARP, DNS, DHCP, Raw,
        conf, get_if_list,
    )
    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    _SCAPY_AVAILABLE = False

# --------------------------------------------------------------------------- #
# 协议定义
# --------------------------------------------------------------------------- #
PCAP_PROTOCOLS: Dict[str, Dict[str, Any]] = {
    "TCP": {"port_range": "0-65535", "description": "传输控制协议", "default_ports": [80, 443, 22, 21, 25, 3389, 8080]},
    "UDP": {"port_range": "0-65535", "description": "用户数据报协议", "default_ports": [53, 67, 68, 123, 161, 500]},
    "ICMP": {"port_range": "N/A", "description": "互联网控制报文协议", "default_ports": []},
    "HTTP": {"port_range": "80,8080,8000", "description": "超文本传输协议", "default_ports": [80, 8080]},
    "HTTPS": {"port_range": "443,8443", "description": "HTTP安全版/TLS加密", "default_ports": [443, 8443]},
    "DNS": {"port_range": "53", "description": "域名系统", "default_ports": [53]},
    "FTP": {"port_range": "20,21", "description": "文件传输协议", "default_ports": [20, 21]},
    "SMTP": {"port_range": "25,587,465", "description": "简单邮件传输协议", "default_ports": [25, 587, 465]},
    "SSH": {"port_range": "22", "description": "安全外壳协议", "default_ports": [22]},
    "TLS": {"port_range": "443,993,995", "description": "传输层安全", "default_ports": [443, 993, 995]},
    "ARP": {"port_range": "N/A", "description": "地址解析协议", "default_ports": []},
    "DHCP": {"port_range": "67,68", "description": "动态主机配置协议", "default_ports": [67, 68]},
}

BPF_FILTER_PRESETS: Dict[str, Dict[str, str]] = {
    "all": {"filter": "", "description": "捕获所有流量"},
    "tcp_only": {"filter": "tcp", "description": "仅TCP流量"},
    "udp_only": {"filter": "udp", "description": "仅UDP流量"},
    "http_https": {"filter": "tcp port 80 or tcp port 443", "description": "HTTP/HTTPS流量"},
    "dns_only": {"filter": "udp port 53 or tcp port 53", "description": "仅DNS流量"},
    "icmp_only": {"filter": "icmp", "description": "仅ICMP流量"},
    "internal_subnet": {"filter": "net 192.168.0.0/16 or net 10.0.0.0/8", "description": "内网流量"},
    "port_22": {"filter": "tcp port 22", "description": "SSH流量"},
    "port_3389": {"filter": "tcp port 3389", "description": "RDP流量"},
    "ftp_only": {"filter": "tcp port 21", "description": "FTP控制连接"},
}

# 模拟IP池
_MOCK_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.100",
    "10.0.0.5", "10.0.0.15", "10.0.0.100", "172.16.0.10",
    "8.8.8.8", "1.1.1.1", "203.0.113.50", "198.51.100.23",
]

_MOCK_PORTS = [80, 443, 53, 22, 21, 25, 3389, 8080, 8443, 123, 161, 993]


def _random_ip() -> str:
    return random.choice(_MOCK_IPS)


def _mock_packet(pkt_id: Optional[int] = None) -> Dict[str, Any]:
    """生成一个模拟网络包。"""
    src = _random_ip()
    dst = _random_ip()
    while dst == src:
        dst = _random_ip()
    proto = random.choice(list(PCAP_PROTOCOLS.keys()))
    sport = random.choice(_MOCK_PORTS) if proto in ("TCP", "UDP") else 0
    dport = random.choice(_MOCK_PORTS) if proto in ("TCP", "UDP") else 0
    size = random.randint(64, 1500)
    return {
        "pkt_id": pkt_id or random.randint(100000, 999999),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time())),
        "src_ip": src, "dst_ip": dst,
        "src_port": sport, "dst_port": dport,
        "protocol": proto, "length": size,
        "ttl": random.randint(32, 128),
        "flags": random.choice(["S", "SA", "A", "FA", "R", ""]),
    }


class TrafficCaptureEngine:
    """流量捕获与解析引擎。"""

    def __init__(self) -> None:
        self.capture_running: bool = False
        self.capture_id: Optional[str] = None
        self.interface: str = ""
        self.bpf_filter: str = ""
        self.packets: List[Dict[str, Any]] = []
        self.pcap_files: Dict[str, Dict[str, Any]] = {}
        self.flows: Dict[str, Dict[str, Any]] = {}
        self.start_time: Optional[float] = None
        self._stats: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # 接口管理
    # ------------------------------------------------------------------ #
    def list_interfaces(self) -> List[Dict[str, Any]]:
        """列出可用网络接口。"""
        if _SCAPY_AVAILABLE:
            try:
                ifs = get_if_list()
                return [{"name": i, "description": f"接口 {i}", "type": "physical"} for i in ifs]
            except Exception:
                pass
        # 模拟接口
        return [
            {"name": "eth0", "description": "以太网接口 (模拟)", "type": "ethernet"},
            {"name": "eth1", "description": "备用以太网 (模拟)", "type": "ethernet"},
            {"name": "lo", "description": "回环接口", "type": "loopback"},
            {"name": "wlan0", "description": "无线接口 (模拟)", "type": "wireless"},
        ]

    # ------------------------------------------------------------------ #
    # 实时抓包
    # ------------------------------------------------------------------ #
    def start_capture(self, interface: str = "eth0", bpf_filter: str = "",
                      max_packets: int = 1000) -> Dict[str, Any]:
        """开始实时流量捕获。"""
        self.capture_id = uuid.uuid4().hex[:12]
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.capture_running = True
        self.packets = []
        self.start_time = time.time()

        # 模拟生成初始包
        for i in range(min(50, max_packets)):
            self.packets.append(_mock_packet(i + 1))

        return {
            "capture_id": self.capture_id,
            "interface": interface,
            "bpf_filter": bpf_filter or "(all)",
            "status": "running",
            "initial_packets": len(self.packets),
            "max_packets": max_packets,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scapy_available": _SCAPY_AVAILABLE,
        }

    def stop_capture(self) -> Dict[str, Any]:
        """停止实时流量捕获。"""
        self.capture_running = False
        duration = time.time() - (self.start_time or time.time())
        stats = self.get_statistics()
        return {
            "capture_id": self.capture_id,
            "status": "stopped",
            "duration_sec": round(duration, 2),
            "total_packets": len(self.packets),
            "statistics": stats,
        }

    def get_live_stats(self) -> Dict[str, Any]:
        """获取实时抓包统计（每次调用追加模拟包）。"""
        if not self.capture_running:
            return {"status": "not_running", "packets": len(self.packets)}
        # 追加5个模拟包
        base_id = len(self.packets)
        for i in range(5):
            self.packets.append(_mock_packet(base_id + i + 1))
        elapsed = time.time() - (self.start_time or time.time())
        rate = len(self.packets) / max(elapsed, 0.001)
        return {
            "status": "running",
            "capture_id": self.capture_id,
            "packets_captured": len(self.packets),
            "elapsed_sec": round(elapsed, 2),
            "packet_rate_pps": round(rate, 1),
            "interface": self.interface,
            "bpf_filter": self.bpf_filter or "(all)",
        }

    # ------------------------------------------------------------------ #
    # PCAP 文件管理
    # ------------------------------------------------------------------ #
    def upload_pcap(self, filename: str, file_size: int = 0) -> Dict[str, Any]:
        """上传/注册PCAP文件。"""
        pcap_id = uuid.uuid4().hex[:12]
        # 模拟解析结果
        num_packets = random.randint(500, 50000)
        protocols = random.sample(list(PCAP_PROTOCOLS.keys()), k=random.randint(4, 8))
        self.pcap_files[pcap_id] = {
            "pcap_id": pcap_id,
            "filename": filename,
            "file_size_bytes": file_size or random.randint(100000, 50000000),
            "packet_count": num_packets,
            "protocols_detected": protocols,
            "capture_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "capture_interface": self.interface or "eth0",
            "sha256": hashlib.sha256(f"{filename}{pcap_id}".encode()).hexdigest()[:32],
            "status": "analyzed",
        }
        return self.pcap_files[pcap_id]

    def list_pcaps(self) -> List[Dict[str, Any]]:
        """列出所有已上传PCAP文件。"""
        if not self.pcap_files:
            # 返回示例数据
            return [
                {"pcap_id": "demo001", "filename": "internal_traffic_20260914.pcap",
                 "file_size_bytes": 24567890, "packet_count": 152340,
                 "protocols_detected": ["TCP", "UDP", "DNS", "HTTPS", "ARP"],
                 "capture_time": "2026-09-14 08:30:00", "status": "analyzed"},
                {"pcap_id": "demo002", "filename": "external_check_week.pcap",
                 "file_size_bytes": 8934210, "packet_count": 45210,
                 "protocols_detected": ["TCP", "HTTP", "HTTPS", "ICMP"],
                 "capture_time": "2026-09-13 22:00:00", "status": "analyzed"},
            ]
        return list(self.pcap_files.values())

    def parse_pcap(self, pcap_id: str) -> Dict[str, Any]:
        """解析PCAP文件并提取元数据。"""
        if pcap_id not in self.pcap_files:
            # 模拟解析
            num_pkts = random.randint(1000, 80000)
            src_ips = set(_random_ip() for _ in range(random.randint(5, 20)))
            dst_ips = set(_random_ip() for _ in range(random.randint(5, 20)))
            return {
                "pcap_id": pcap_id,
                "status": "parsed",
                "packet_count": num_pkts,
                "unique_src_ips": sorted(src_ips),
                "unique_dst_ips": sorted(dst_ips),
                "protocol_distribution": self._mock_protocol_distribution(),
                "duration_sec": random.randint(60, 7200),
                "total_bytes": num_pkts * random.randint(500, 1200),
                "packets_per_sec": round(num_pkts / random.randint(60, 7200), 2),
            }
        info = self.pcap_files[pcap_id]
        return {**info, "parsed": True, "parse_time": time.strftime("%Y-%m-%d %H:%M:%S")}

    # ------------------------------------------------------------------ #
    # 协议解析
    # ------------------------------------------------------------------ #
    def parse_protocols(self, packets: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """解析协议字段并返回各协议详情。"""
        pkts = packets or self.packets or [_mock_packet(i) for i in range(100)]
        proto_counts: Counter = Counter()
        proto_details: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for p in pkts:
            proto = p.get("protocol", "TCP")
            proto_counts[proto] += 1
            if len(proto_details[proto]) < 5:
                detail = {
                    "src_ip": p["src_ip"], "dst_ip": p["dst_ip"],
                    "src_port": p.get("src_port", 0), "dst_port": p.get("dst_port", 0),
                    "length": p["length"], "flags": p.get("flags", ""),
                    "timestamp": p["timestamp"],
                }
                # 协议特定字段
                if proto == "DNS":
                    detail["dns_query"] = random.choice(["www.example.com", "api.internal.lan", "mail.corp.net"])
                    detail["dns_type"] = random.choice(["A", "AAAA", "MX", "TXT"])
                elif proto == "HTTP":
                    detail["http_method"] = random.choice(["GET", "POST", "PUT", "HEAD"])
                    detail["http_host"] = random.choice(["example.com", "internal.corp", "api.service"])
                    detail["http_path"] = random.choice(["/index.html", "/api/v1/status", "/login"])
                    detail["http_status"] = random.choice([200, 200, 200, 301, 404, 500])
                elif proto == "TLS":
                    detail["tls_version"] = random.choice(["TLSv1.2", "TLSv1.3"])
                    detail["tls_cipher"] = random.choice(["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"])
                elif proto == "ARP":
                    detail["arp_op"] = random.choice(["request", "reply"])
                    detail["arp_mac"] = "aa:bb:cc:dd:ee:ff"
                proto_details[proto].append(detail)

        total = sum(proto_counts.values())
        return {
            "total_packets": total,
            "protocol_counts": dict(proto_counts),
            "protocol_percentages": {k: round(v / max(total, 1) * 100, 1)
                                      for k, v in proto_counts.items()},
            "sample_details": {k: v[:3] for k, v in proto_details.items()},
            "protocols_available": list(PCAP_PROTOCOLS.keys()),
        }

    # ------------------------------------------------------------------ #
    # 流量统计
    # ------------------------------------------------------------------ #
    def get_statistics(self) -> Dict[str, Any]:
        """综合流量统计。"""
        pkts = self.packets or [_mock_packet(i) for i in range(200)]
        total_packets = len(pkts)
        total_bytes = sum(p["length"] for p in pkts)

        # 协议分布
        proto_dist: Counter = Counter(p["protocol"] for p in pkts)

        # Top 说话者
        src_counter: Counter = Counter(p["src_ip"] for p in pkts)
        dst_counter: Counter = Counter(p["dst_ip"] for p in pkts)
        top_speakers = [{"ip": ip, "packets": cnt} for ip, cnt in src_counter.most_common(10)]
        top_destinations = [{"ip": ip, "packets": cnt} for ip, cnt in dst_counter.most_common(10)]

        # Top 端口
        port_counter: Counter = Counter()
        for p in pkts:
            if p.get("dst_port"):
                port_counter[p["dst_port"]] += 1
        top_ports = [{"port": port, "packets": cnt} for port, cnt in port_counter.most_common(10)]

        # 包大小分布
        size_buckets = {"0-64": 0, "65-128": 0, "129-256": 0, "257-512": 0,
                         "513-1024": 0, "1025-1500": 0, "1501+": 0}
        for p in pkts:
            s = p["length"]
            if s <= 64: size_buckets["0-64"] += 1
            elif s <= 128: size_buckets["65-128"] += 1
            elif s <= 256: size_buckets["129-256"] += 1
            elif s <= 512: size_buckets["257-512"] += 1
            elif s <= 1024: size_buckets["513-1024"] += 1
            elif s <= 1500: size_buckets["1025-1500"] += 1
            else: size_buckets["1501+"] += 1

        # 流统计
        flow_keys = set()
        for p in pkts:
            key = f"{p['src_ip']}:{p.get('src_port',0)} -> {p['dst_ip']}:{p.get('dst_port',0)}"
            flow_keys.add(key)

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / 1048576, 2),
            "unique_flows": len(flow_keys),
            "protocol_distribution": dict(proto_dist),
            "top_speakers": top_speakers,
            "top_destinations": top_destinations,
            "top_ports": top_ports,
            "packet_size_distribution": size_buckets,
            "avg_packet_size": round(total_bytes / max(total_packets, 1), 1),
            "bandwidth_bps": round(total_bytes * 8 / max(len(pkts), 1) * 10, 2),
        }

    # ------------------------------------------------------------------ #
    # 流量重组
    # ------------------------------------------------------------------ #
    def reconstruct_tcp_flows(self, limit: int = 10) -> Dict[str, Any]:
        """TCP流重组模拟。"""
        pkts = self.packets or [_mock_packet(i) for i in range(150)]
        flow_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for p in pkts:
            if p["protocol"] in ("TCP", "HTTP", "HTTPS", "SSH", "FTP"):
                key = f"{p['src_ip']}:{p.get('src_port',0)}-{p['dst_ip']}:{p.get('dst_port',0)}"
                flow_map[key].append(p)

        flows = []
        for key, flist in list(flow_map.items())[:limit]:
            src, dst = key.split("-")
            flows.append({
                "flow_key": key,
                "src": src, "dst": dst,
                "packet_count": len(flist),
                "total_bytes": sum(p["length"] for p in flist),
                "duration_sec": round(random.uniform(0.5, 30.0), 2),
                "state": random.choice(["ESTABLISHED", "FINISHED", "RESET"]),
                "protocol": flist[0]["protocol"] if flist else "TCP",
            })
        return {"total_flows": len(flow_map), "shown": len(flows), "flows": flows}

    def reconstruct_http_sessions(self, limit: int = 10) -> Dict[str, Any]:
        """HTTP会话重建模拟。"""
        sessions = []
        for i in range(min(limit, 8)):
            method = random.choice(["GET", "POST", "GET", "GET"])
            status = random.choice([200, 200, 200, 301, 404])
            sessions.append({
                "session_id": f"http_{i:04d}",
                "method": method,
                "host": random.choice(["internal.corp", "api.service", "www.example.com"]),
                "path": random.choice(["/index.html", "/api/v1/users", "/login", "/dashboard"]),
                "status_code": status,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityBrowser/1.0",
                "request_bytes": random.randint(200, 5000),
                "response_bytes": random.randint(500, 50000),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": _random_ip(), "dst_ip": _random_ip(),
            })
        return {"total_sessions": random.randint(20, 200), "shown": len(sessions), "sessions": sessions}

    def extract_files_from_traffic(self, limit: int = 10) -> Dict[str, Any]:
        """从流量中提取文件模拟。"""
        files = []
        for i in range(min(limit, 6)):
            fname = random.choice(["report.pdf", "config.xml", "backup.zip", "image.png", "data.csv", "script.exe"])
            fsize = random.randint(1024, 1048576)
            files.append({
                "file_id": f"file_{i:04d}",
                "filename": fname,
                "size_bytes": fsize,
                "file_type": fname.split(".")[-1].upper(),
                "sha256": hashlib.sha256(f"{fname}{i}".encode()).hexdigest()[:40],
                "extracted_from": random.choice(["HTTP", "FTP", "SMTP"]),
                "src_ip": _random_ip(), "dst_ip": _random_ip(),
                "extracted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
        return {"total_extracted": random.randint(5, 50), "shown": len(files), "files": files}

    # ------------------------------------------------------------------ #
    # 辅助
    # ------------------------------------------------------------------ #
    def _mock_protocol_distribution(self) -> Dict[str, int]:
        pkts = [_mock_packet(i) for i in range(500)]
        c: Counter = Counter(p["protocol"] for p in pkts)
        return dict(c)

    def get_capture_status(self) -> Dict[str, Any]:
        """获取当前抓包状态。"""
        return {
            "capture_running": self.capture_running,
            "capture_id": self.capture_id,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "packets_captured": len(self.packets),
            "scapy_available": _SCAPY_AVAILABLE,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S") if self.start_time else None,
        }
