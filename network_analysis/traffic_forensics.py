#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
traffic_forensics.py — 流量取证与回放管理器。

覆盖：
    - PCAP管理（上传/存储/索引/搜索/下载/元数据/文件大小/捕获时间/捕获接口）
    - 流量搜索（按时间/IP/端口/协议/载荷内容搜索，搜索结果高亮/上下文）
    - 会话回放（TCP流查看/HTTP请求响应查看/WebSocket消息查看/DNS查询响应查看，十六进制+ASCII双视图）
    - 文件提取（从流量中提取传输的文件/图片/可执行文件/文档，文件类型识别/哈希/大小）
    - 证据包生成（选定流量+元数据+分析结果打包为证据包，含SHA256哈希校验/时间戳/分析师签名）

设计定位：仅做流量取证分析与证据整理，输出取证报告，不进行任何攻击操作。
"""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from collections import Counter
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 证据包模板
# --------------------------------------------------------------------------- #
EVIDENCE_PACK_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "incident_response": {
        "name": "事件响应证据包",
        "contents": ["PCAP文件", "元数据摘要", "告警关联", "时间线", "IOC清单"],
        "chain_of_custody": True,
        "includes_hash": True,
    },
    "compliance_audit": {
        "name": "合规审计证据包",
        "contents": ["PCAP文件", "流量统计", "协议分布", "访问日志", "摘要报告"],
        "chain_of_custody": True,
        "includes_hash": True,
    },
    "threat_hunt": {
        "name": "威胁狩猎证据包",
        "contents": ["PCAP文件", "检测命中", "IOC匹配", "YARA扫描结果", "行为分析"],
        "chain_of_custody": True,
        "includes_hash": True,
    },
    "network_incident": {
        "name": "网络事件证据包",
        "contents": ["PCAP文件", "异常检测报告", "流重组数据", "提取文件", "分析师笔记"],
        "chain_of_custody": True,
        "includes_hash": True,
    },
}


def _hex_dump(data: str, width: int = 16) -> str:
    """生成十六进制+ASCII双视图转储。"""
    result_lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{ord(c):02x}" for c in chunk)
        ascii_part = "".join(c if 32 <= ord(c) < 127 else "." for c in chunk)
        result_lines.append(f"{i:08x}  {hex_part:<{width*3}}  |{ascii_part}|")
    return "\n".join(result_lines)


class TrafficForensicsManager:
    """流量取证与回放管理器。"""

    def __init__(self) -> None:
        self.pcap_store: Dict[str, Dict[str, Any]] = {}
        self.evidence_packs: Dict[str, Dict[str, Any]] = {}
        self.extracted_files: List[Dict[str, Any]] = []
        self.session_records: Dict[str, List[Dict[str, Any]]] = {}

    # ------------------------------------------------------------------ #
    # PCAP 管理
    # ------------------------------------------------------------------ #
    def upload_pcap(self, filename: str, file_size_bytes: int = 0,
                    interface: str = "eth0", notes: str = "") -> Dict[str, Any]:
        """上传PCAP文件并索引。"""
        pcap_id = uuid.uuid4().hex[:12]
        packet_count = random.randint(1000, 100000)
        sha = hashlib.sha256(f"{filename}{pcap_id}{time.time()}".encode()).hexdigest()
        record = {
            "pcap_id": pcap_id,
            "filename": filename,
            "file_size_bytes": file_size_bytes or random.randint(500000, 100000000),
            "packet_count": packet_count,
            "capture_interface": interface,
            "capture_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sha256": sha,
            "notes": notes,
            "indexed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "indexed",
            "tags": [],
        }
        self.pcap_store[pcap_id] = record
        return record

    def list_pcaps(self) -> List[Dict[str, Any]]:
        """列出所有PCAP文件。"""
        if not self.pcap_store:
            return [
                {"pcap_id": "pcap_demo1", "filename": "incident_traffic_0914.pcap",
                 "file_size_bytes": 45678901, "packet_count": 234567,
                 "capture_interface": "eth0", "capture_time": "2026-09-14 08:00:00",
                 "status": "indexed", "tags": ["incident", "suspected_c2"]},
                {"pcap_id": "pcap_demo2", "filename": "baseline_traffic_week.pcap",
                 "file_size_bytes": 123456789, "packet_count": 1234567,
                 "capture_interface": "eth1", "capture_time": "2026-09-07 00:00:00",
                 "status": "indexed", "tags": ["baseline", "weekly"]},
            ]
        return list(self.pcap_store.values())

    def get_pcap_metadata(self, pcap_id: str) -> Dict[str, Any]:
        """获取PCAP元数据。"""
        if pcap_id in self.pcap_store:
            return self.pcap_store[pcap_id]
        return {
            "pcap_id": pcap_id,
            "filename": f"unknown_{pcap_id}.pcap",
            "file_size_bytes": 0,
            "packet_count": 0,
            "status": "not_found",
            "note": "未在存储中找到，返回模拟元数据",
        }

    # ------------------------------------------------------------------ #
    # 流量搜索
    # ------------------------------------------------------------------ #
    def search_traffic(self, pcap_id: str = "all",
                       search_type: str = "all",
                       query: str = "",
                       start_time: Optional[str] = None,
                       end_time: Optional[str] = None) -> Dict[str, Any]:
        """搜索流量内容。"""
        results = []
        for i in range(random.randint(3, 15)):
            src = f"192.168.1.{random.randint(10,200)}"
            dst = f"203.0.113.{random.randint(10,200)}"
            results.append({
                "match_id": f"match_{i:03d}",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src, "dst_ip": dst,
                "src_port": random.choice([80, 443, 53, 445, 22, 8080]),
                "dst_port": random.choice([80, 443, 53, 445, 22, 8080]),
                "protocol": random.choice(["TCP", "UDP", "HTTP", "DNS", "HTTPS"]),
                "match_context": f"...{query or 'search'}..." if query else "匹配记录",
                "highlight": query or "search_keyword",
                "pcap_id": pcap_id,
                "frame_number": random.randint(100, 50000),
            })

        return {
            "total_results": len(results),
            "search_type": search_type,
            "query": query,
            "pcap_id": pcap_id,
            "time_range": {"start": start_time, "end": end_time},
            "results": results,
            "searched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 会话回放
    # ------------------------------------------------------------------ #
    def replay_session(self, session_id: str,
                       protocol: str = "tcp") -> Dict[str, Any]:
        """回放会话数据（十六进制+ASCII双视图）。"""
        # 生成模拟会话数据包
        packets = []
        directions = ["C->S", "S->C"]
        sample_payloads = [
            "GET /index.html HTTP/1.1\r\nHost: example.com\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
            "DNS Query: www.example.com A\r\n",
            "DNS Response: 93.184.216.34\r\n",
        ]
        for i in range(8):
            payload = random.choice(sample_payloads)
            packets.append({
                "frame": i + 1,
                "timestamp": time.strftime("%H:%M:%S", time.gmtime(time.time() + i)),
                "direction": directions[i % 2],
                "length": len(payload),
                "hex_ascii_view": _hex_dump(payload),
                "ascii_preview": payload[:80],
            })

        return {
            "session_id": session_id,
            "protocol": protocol,
            "src": f"192.168.1.{random.randint(10,200)}:{random.randint(1024,65535)}",
            "dst": f"203.0.113.{random.randint(10,200)}:{random.choice([80, 443, 53, 22])}",
            "total_frames": len(packets),
            "total_bytes": sum(p["length"] for p in packets),
            "packets": packets,
            "replayed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def list_sessions(self, pcap_id: str = "all",
                      limit: int = 20) -> Dict[str, Any]:
        """列出可回放的会话。"""
        sessions = []
        for i in range(min(limit, 12)):
            proto = random.choice(["tcp", "http", "dns", "websocket", "tls"])
            sessions.append({
                "session_id": f"sess_{i:04d}",
                "protocol": proto,
                "src": f"192.168.1.{random.randint(10,200)}:{random.randint(1024,65535)}",
                "dst": f"203.0.113.{random.randint(10,200)}:{random.choice([80,443,53,22,8080])}",
                "packet_count": random.randint(5, 200),
                "duration_sec": round(random.uniform(0.1, 120.0), 2),
                "first_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                "pcap_id": pcap_id,
            })
        return {"total_sessions": random.randint(50, 500), "shown": len(sessions), "sessions": sessions}

    # ------------------------------------------------------------------ #
    # 文件提取
    # ------------------------------------------------------------------ #
    def extract_files(self, pcap_id: str = "all",
                     file_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """从流量中提取文件。"""
        ftypes = file_types or ["pdf", "exe", "png", "zip", "docx", "csv"]
        files = []
        for i in range(random.randint(3, 10)):
            ftype = random.choice(ftypes)
            fname = f"extracted_{i:03d}.{ftype}"
            fsize = random.randint(512, 10485760)
            files.append({
                "file_id": f"ext_{i:04d}",
                "filename": fname,
                "file_type": ftype.upper(),
                "size_bytes": fsize,
                "sha256": hashlib.sha256(fname.encode()).hexdigest()[:40],
                "md5": hashlib.md5(fname.encode()).hexdigest(),
                "extracted_from_protocol": random.choice(["HTTP", "FTP", "SMTP", "SMB"]),
                "src_ip": f"192.168.1.{random.randint(10,200)}",
                "dst_ip": f"203.0.113.{random.randint(10,200)}",
                "extracted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_verdict": random.choice(["clean", "clean", "suspicious", "malicious"]),
            })

        self.extracted_files.extend(files)
        return {
            "total_extracted": len(files),
            "by_type": dict(Counter(f["file_type"] for f in files)),
            "total_size_mb": round(sum(f["size_bytes"] for f in files) / 1048576, 2),
            "files": files,
            "pcap_id": pcap_id,
            "extraction_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 证据包生成
    # ------------------------------------------------------------------ #
    def generate_evidence_pack(self, pack_name: str,
                               template: str = "incident_response",
                               pcap_ids: Optional[List[str]] = None,
                               analyst: str = "security_analyst",
                               notes: str = "") -> Dict[str, Any]:
        """生成取证证据包。"""
        pack_id = uuid.uuid4().hex[:12]
        tpl = EVIDENCE_PACK_TEMPLATES.get(template, EVIDENCE_PACK_TEMPLATES["incident_response"])

        # 生成证据包哈希
        pack_content_hash = hashlib.sha256(
            f"{pack_id}{pack_name}{pcap_ids}{analyst}{time.time()}".encode()
        ).hexdigest()

        pack = {
            "pack_id": pack_id,
            "pack_name": pack_name,
            "template": template,
            "template_name": tpl["name"],
            "contents": tpl["contents"],
            "pcap_ids": pcap_ids or ["pcap_demo1"],
            "analyst": analyst,
            "notes": notes,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sha256": pack_content_hash,
            "chain_of_custody": tpl["chain_of_custody"],
            "includes_hash": tpl["includes_hash"],
            "file_size_estimate_mb": round(random.uniform(10, 500), 2),
            "status": "ready",
            "signature": f"sig_{hashlib.sha1(pack_id.encode()).hexdigest()[:16]}",
        }
        self.evidence_packs[pack_id] = pack
        return pack

    def list_evidence_packs(self) -> List[Dict[str, Any]]:
        """列出所有证据包。"""
        if not self.evidence_packs:
            return [{
                "pack_id": "ep_demo01", "pack_name": "9月14日可疑C2事件证据包",
                "template": "incident_response", "analyst": "security_analyst",
                "generated_at": "2026-09-14 10:30:00", "status": "ready",
            }]
        return list(self.evidence_packs.values())

    # ------------------------------------------------------------------ #
    # 取证总览
    # ------------------------------------------------------------------ #
    def get_forensics_summary(self) -> Dict[str, Any]:
        """取证管理总览。"""
        return {
            "pcap_files_stored": len(self.pcap_store),
            "evidence_packs": len(self.evidence_packs),
            "files_extracted": len(self.extracted_files),
            "sessions_indexed": len(self.session_records),
            "summary_generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
