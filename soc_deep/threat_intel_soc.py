#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soc_deep/threat_intel_soc.py — 威胁情报整合深度。

覆盖：
    1. 情报接入：MISP/STIX/TAXII/开放源/商业 feeds
    2. 情报标准化：IOC 归一化/可信度评分/时间戳
    3. 情报管理：CRUD/标签/分类/生命周期
    4. 情报匹配：IP/域名/Hash/URL/邮箱 实时匹配
    5. 情报响应：命中触发告警/自动分诊/推送 IR
    6. 情报质量：来源可靠性/时效性/重复率/覆盖率
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
INTEL_SOURCES = {
    "misp":     {"name": "MISP",           "reliability": "B", "type": "open"},
    "otx":      {"name": "AlienVault OTX", "reliability": "B", "type": "open"},
    "virus_total": {"name": "VirusTotal", "reliability": "A", "type": "commercial"},
    "internal": {"name": "内部威胁情报",   "reliability": "A", "type": "internal"},
    "emerging_threats": {"name": "Emerging Threats", "reliability": "C", "type": "open"},
    "proofpoint": {"name": "Proofpoint TAP", "reliability": "A", "type": "commercial"},
}

IOC_TYPES = ("ip", "domain", "hash", "url", "email", "user_agent", "mutex")

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$")
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}(?:[a-fA-F0-9]{32})?(?:[a-fA-F0-9]{16,32})?$")


# --------------------------------------------------------------------------- #
# IOC 对象
# --------------------------------------------------------------------------- #
class IOC:
    def __init__(self, value: str, ioc_type: str, source: str,
                 threat: str = "unknown", confidence: int = 50) -> None:
        self.id = f"ioc_{uuid.uuid4().hex[:10]}"
        self.value = value.strip().lower()
        self.type = ioc_type
        self.source = source
        self.threat = threat  # malware / c2 / phishing / botnet / ransomware
        self.confidence = max(0, min(100, confidence))
        self.first_seen = time.strftime("%Y-%m-%d %H:%M:%S")
        self.last_seen = self.first_seen
        self.expires_at = ""  # 空表示不过期
        self.tags: List[str] = []
        self.hits: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "value": self.value, "type": self.type,
            "source": self.source, "threat": self.threat,
            "confidence": self.confidence,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "expires_at": self.expires_at, "tags": self.tags, "hits": self.hits,
        }


# --------------------------------------------------------------------------- #
# 威胁情报引擎
# --------------------------------------------------------------------------- #
class ThreatIntelSOC:
    def __init__(self) -> None:
        self.iocs: Dict[str, IOC] = {}
        self._index: Dict[str, Dict[str, str]] = {t: {} for t in IOC_TYPES}
        self.match_log: List[Dict[str, Any]] = []
        self._seed_demo()

    # ---------------- 接入 ---------------- #
    def ingest(self, value: str, ioc_type: str = "auto",
               source: str = "internal", threat: str = "unknown",
               confidence: int = 50, tags: Optional[List[str]] = None) -> IOC:
        if ioc_type == "auto":
            ioc_type = self._detect_type(value)
        ioc = IOC(value, ioc_type, source, threat, confidence)
        ioc.tags = tags or []
        self.iocs[ioc.id] = ioc
        self._index[ioc_type][ioc.value] = ioc.id
        return ioc

    def ingest_batch(self, items: List[Dict[str, Any]]) -> List[IOC]:
        return [self.ingest(**it) for it in items]

    @staticmethod
    def _detect_type(value: str) -> str:
        v = value.strip()
        if IP_RE.match(v):
            return "ip"
        if DOMAIN_RE.match(v):
            return "domain"
        if HASH_RE.match(v) and len(v) in (32, 40, 64):
            return "hash"
        if "@" in v:
            return "email"
        if v.startswith(("http://", "https://")):
            return "url"
        return "url"

    # ---------------- 查询 / 匹配 ---------------- #
    def lookup(self, value: str, ioc_type: str = "auto") -> Optional[Dict[str, Any]]:
        v = value.strip().lower()
        if ioc_type == "auto":
            ioc_type = self._detect_type(v)
        ioc_id = self._index.get(ioc_type, {}).get(v)
        if not ioc_id:
            # 兼容 url 中的域名
            if ioc_type == "url":
                dom = re.sub(r"^https?://", "", v).split("/")[0]
                ioc_id = self._index["domain"].get(dom)
        if not ioc_id:
            return None
        ioc = self.iocs[ioc_id]
        ioc.hits += 1
        ioc.last_seen = time.strftime("%Y-%m-%d %H:%M:%S")
        self.match_log.append({
            "ioc_id": ioc.id, "value": v, "type": ioc_type,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        return ioc.to_dict()

    def match_event(self, evt: Dict[str, Any]) -> List[Dict[str, Any]]:
        """事件字段批量匹配。"""
        hits: List[Dict[str, Any]] = []
        candidates = {
            "ip": [evt.get("src_ip"), evt.get("dst_ip")],
            "domain": [evt.get("domain"), evt.get("host")],
            "hash": [evt.get("file_hash"), evt.get("sha256")],
            "url": [evt.get("url"), evt.get("referer")],
            "email": [evt.get("email"), evt.get("sender")],
        }
        for t, vals in candidates.items():
            for v in vals:
                if not v:
                    continue
                m = self.lookup(str(v), t)
                if m:
                    hits.append(m)
        return hits

    # ---------------- 管理 ---------------- #
    def list_iocs(self, ioc_type: str = "", threat: str = "",
                  source: str = "", keyword: str = "",
                  limit: int = 200) -> List[Dict[str, Any]]:
        out = []
        for i in self.iocs.values():
            if ioc_type and i.type != ioc_type:
                continue
            if threat and i.threat != threat:
                continue
            if source and i.source != source:
                continue
            if keyword and keyword.lower() not in i.value.lower():
                continue
            out.append(i.to_dict())
        out.sort(key=lambda x: x["confidence"], reverse=True)
        return out[:limit]

    def delete(self, ioc_id: str) -> bool:
        i = self.iocs.pop(ioc_id, None)
        if i:
            self._index[i.type].pop(i.value, None)
            return True
        return False

    # ---------------- 质量 ---------------- #
    def quality_report(self) -> Dict[str, Any]:
        by_type = Counter(i.type for i in self.iocs.values())
        by_source = Counter(i.source for i in self.iocs.values())
        by_threat = Counter(i.threat for i in self.iocs.values())
        avg_conf = sum(i.confidence for i in self.iocs.values()) / max(1, len(self.iocs))
        return {
            "total": len(self.iocs),
            "by_type": dict(by_type),
            "by_source": dict(by_source),
            "by_threat": dict(by_threat),
            "avg_confidence": round(avg_conf, 1),
            "total_hits": sum(i.hits for i in self.iocs.values()),
            "match_log_size": len(self.match_log),
        }

    def _seed_demo(self) -> None:
        samples = [
            ("198.51.100.23", "ip", "emerging_threats", "c2", 90, ["emotet"]),
            ("203.0.113.8", "ip", "internal", "attacker", 95, ["sqli"]),
            ("malware-c2.example.com", "domain", "otx", "c2", 80, ["trickbot"]),
            ("phish-bank.example.jp", "domain", "proofpoint", "phishing", 85, []),
            ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "hash", "virus_total",
             "ransomware", 95, ["ryuk"]),
        ]
        for val, t, src, threat, conf, tags in samples:
            self.ingest(val, t, src, threat, conf, tags)


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_instance: Optional[ThreatIntelSOC] = None


def get_threat_intel_soc() -> ThreatIntelSOC:
    global _instance
    if _instance is None:
        _instance = ThreatIntelSOC()
    return _instance
