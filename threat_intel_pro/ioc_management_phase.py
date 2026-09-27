# -*- coding: utf-8 -*-
"""
ioc_management_phase.py — 方向2 威胁情报 Pro：阶段2 IOC 管理。

功能:
    - IOC 分类: IP(IPv4/IPv6) / 域名 / URL / 文件哈希(MD5/SHA1/SHA256) /
      证书指纹 / 邮箱 / CVE
    - IOC 去重（按 type+value 唯一键）
    - IOC 富化（地理位置 / ASN / WHOIS / 威胁标签 / 首见/末见 / 置信度）
    - IOC 标签管理（恶意软件 / 钓鱼 / C2 / 扫描器 / 僵尸网络）
    - IOC 生命周期（新增 / 活跃 / 过期 / 撤销）
    - IOC 搜索与筛选
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# 类型识别
# --------------------------------------------------------------------------- #
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IPV6_RE = re.compile(r"^[0-9A-Fa-f:]+$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
URL_RE = re.compile(r"^https?://", re.I)
CERTFP_RE = re.compile(r"^[A-Fa-f0-9:]{20,}$")

IOC_TYPES = ["ip", "ipv6", "domain", "url", "hash",
             "cert_fingerprint", "email", "cve"]

# 内置威胁标签库
THREAT_TAGS = {
    "malware": "恶意软件",
    "phishing": "钓鱼",
    "c2": "命令控制 (C2)",
    "scanner": "扫描器",
    "botnet": "僵尸网络",
    "ransomware": "勒索软件",
    "trojan": "木马",
    "backdoor": "后门",
    "exploit": "利用",
    "data_exfil": "数据外泄",
    "proxy": "代理/匿名化",
    "bruteforce": "暴力破解",
}

# 生命周期
LIFECYCLE_STATES = ["new", "active", "expired", "revoked"]

# 富化用的离线地理/ASN 映射（无外部库时的确定性兜底）
_GEO_FALLBACK = {
    "RU": ("俄罗斯", 12345), "CN": ("中国", 4808), "US": ("美国", 14618),
    "DE": ("德国", 3320), "NL": ("荷兰", 13335), "PA": ("巴拿马", 61676),
    "KP": ("朝鲜", 13121), "IR": ("伊朗", 58224), "BR": ("巴西", 28573),
    "VN": ("越南", 45899), "ID": ("印度尼西亚", 24961),
}


def classify_ioc(value: str) -> str:
    v = (value or "").strip().strip("[]()")
    if URL_RE.match(v):
        return "url"
    if CVE_RE.match(v):
        return "cve"
    if EMAIL_RE.match(v):
        return "email"
    if MD5_RE.match(v):
        return "hash"
    if SHA1_RE.match(v):
        return "hash"
    if SHA256_RE.match(v):
        return "hash"
    if IPV4_RE.match(v):
        # 简单合法性
        parts = v.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return "ip"
    if ":" in v and IPV6_RE.match(v):
        return "ipv6"
    if CERTFP_RE.match(v):
        return "cert_fingerprint"
    if "." in v and " " not in v:
        return "domain"
    return "unknown"


def hash_algo_of(value: str) -> str:
    if MD5_RE.match(value):
        return "MD5"
    if SHA1_RE.match(value):
        return "SHA1"
    if SHA256_RE.match(value):
        return "SHA256"
    return ""


@dataclass
class ManagedIOC:
    ioc_id: str = ""
    type: str = ""
    value: str = ""
    hash_algo: str = ""
    tags: List[str] = field(default_factory=list)
    source: str = ""
    malware: str = ""
    confidence: int = 0          # 0-100
    # 富化字段
    country: str = ""
    country_name: str = ""
    asn: int = 0
    as_org: str = ""
    whois: str = ""
    first_seen: str = ""
    last_seen: str = ""
    lifecycle: str = "new"       # new/active/expired/revoked
    reference_count: int = 0
    notes: str = ""

    def key(self) -> str:
        return f"{self.type}:{self.value.lower()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_id": self.ioc_id, "type": self.type, "value": self.value,
            "hash_algo": self.hash_algo, "tags": self.tags,
            "source": self.source, "malware": self.malware,
            "confidence": self.confidence,
            "country": self.country, "country_name": self.country_name,
            "asn": self.asn, "as_org": self.as_org, "whois": self.whois,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "lifecycle": self.lifecycle,
            "reference_count": self.reference_count,
            "notes": self.notes,
        }


class IOManagementPhase:
    """阶段2: IOC 管理。"""

    def __init__(self) -> None:
        self._iocs: Dict[str, ManagedIOC] = {}     # key -> IOC
        self._tags: Dict[str, int] = {k: 0 for k in THREAT_TAGS}

    # ------------------------------------------------------------------ #
    # 入库（带去重 + 自动分类 + 富化）
    # ------------------------------------------------------------------ #
    def ingest(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        added = 0
        dedup = 0
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        for raw in items:
            value = (raw.get("value") or "").strip()
            if not value:
                continue
            itype = raw.get("type") or classify_ioc(value)
            ioc = ManagedIOC(
                ioc_id=uuid.uuid4().hex[:12],
                type=itype, value=value,
                hash_algo=raw.get("hash_algo") or hash_algo_of(value),
                tags=list(raw.get("tags") or []),
                source=raw.get("source", "unknown"),
                malware=raw.get("malware", ""),
                confidence=int(raw.get("confidence", 50) or 50),
                country=raw.get("country", ""),
                asn=int(raw.get("asn", 0) or 0),
                first_seen=raw.get("first_seen") or now,
                last_seen=raw.get("last_seen") or now,
                lifecycle="new",
            )
            self._enrich(ioc)
            k = ioc.key()
            if k in self._iocs:
                # 去重：合并标签、刷新 last_seen、累加引用
                existing = self._iocs[k]
                existing.last_seen = now
                existing.reference_count += 1
                for t in ioc.tags:
                    if t not in existing.tags:
                        existing.tags.append(t)
                existing.confidence = max(existing.confidence,
                                          ioc.confidence)
                dedup += 1
                continue
            self._iocs[k] = ioc
            self._bump_tags(ioc.tags)
            added += 1
        return {"added": added, "dedup": dedup, "total": len(self._iocs)}

    def _enrich(self, ioc: ManagedIOC) -> None:
        """离线富化：国家名 / ASN 组织 / WHOIS 占位。"""
        if ioc.country and ioc.country in _GEO_FALLBACK:
            ioc.country_name = _GEO_FALLBACK[ioc.country][0]
            if not ioc.asn:
                ioc.asn = _GEO_FALLBACK[ioc.country][1]
        if ioc.asn:
            ioc.as_org = f"AS{ioc.asn}"
        if ioc.type in ("domain", "url", "ip", "ipv6"):
            ioc.whois = (f"WHOIS 记录需外部 RDAP/WHOIS 服务；"
                         f"当前离线富化占位: {ioc.value}")
        if ioc.type == "hash":
            ioc.whois = f"样本哈希 {ioc.hash_algo}:{ioc.value[:16]}..."

    def _bump_tags(self, tags: List[str]) -> None:
        for t in tags:
            self._tags[t] = self._tags.get(t, 0) + 1

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def set_lifecycle(self, value: str, state: str) -> Dict[str, Any]:
        if state not in LIFECYCLE_STATES:
            return {"error": f"invalid state {state}"}
        k = f"{classify_ioc(value)}:{value.lower()}"
        ioc = self._iocs.get(k)
        if ioc is None:
            return {"error": "ioc not found"}
        ioc.lifecycle = state
        ioc.last_seen = time.strftime("%Y-%m-%d %H:%M:%S")
        return ioc.to_dict()

    def expire_old(self, days: int = 30) -> Dict[str, Any]:
        now = time.time()
        changed = 0
        for ioc in self._iocs.values():
            if ioc.lifecycle in ("active", "new"):
                try:
                    ts = time.mktime(time.strptime(ioc.last_seen,
                                                   "%Y-%m-%d %H:%M:%S"))
                except Exception:
                    continue
                if (now - ts) > days * 86400:
                    ioc.lifecycle = "expired"
                    changed += 1
        return {"expired": changed, "threshold_days": days}

    # ------------------------------------------------------------------ #
    # 搜索 / 筛选
    # ------------------------------------------------------------------ #
    def search(self, keyword: str = "", type: str = "",
               tag: str = "", lifecycle: str = "",
               min_confidence: int = 0,
               limit: int = 200) -> Dict[str, Any]:
        kw = keyword.strip().lower()
        out: List[ManagedIOC] = []
        for ioc in self._iocs.values():
            if type and ioc.type != type:
                continue
            if tag and tag not in ioc.tags:
                continue
            if lifecycle and ioc.lifecycle != lifecycle:
                continue
            if ioc.confidence < min_confidence:
                continue
            if kw and kw not in ioc.value.lower() \
                    and kw not in ioc.malware.lower():
                continue
            out.append(ioc)
        out.sort(key=lambda x: (x.confidence, x.last_seen), reverse=True)
        items = [i.to_dict() for i in out[:limit]]
        return {"total": len(out), "count": len(items), "items": items}

    def get(self, value: str) -> Optional[Dict[str, Any]]:
        k = f"{classify_ioc(value)}:{value.lower()}"
        ioc = self._iocs.get(k)
        return ioc.to_dict() if ioc else None

    def delete(self, value: str) -> Dict[str, Any]:
        k = f"{classify_ioc(value)}:{value.lower()}"
        ioc = self._iocs.pop(k, None)
        if ioc is None:
            return {"error": "not found"}
        return {"deleted": value, "type": ioc.type}

    # ------------------------------------------------------------------ #
    # 标签管理 / 统计
    # ------------------------------------------------------------------ #
    def tag_stats(self) -> Dict[str, int]:
        return dict(sorted(self._tags.items(),
                           key=lambda x: x[1], reverse=True))

    def stats(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        by_life: Dict[str, int] = {}
        conf_buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for ioc in self._iocs.values():
            by_type[ioc.type] = by_type.get(ioc.type, 0) + 1
            by_life[ioc.lifecycle] = by_life.get(ioc.lifecycle, 0) + 1
            c = ioc.confidence
            if c >= 90:
                conf_buckets["critical"] += 1
            elif c >= 75:
                conf_buckets["high"] += 1
            elif c >= 50:
                conf_buckets["medium"] += 1
            else:
                conf_buckets["low"] += 1
        return {
            "total": len(self._iocs),
            "by_type": by_type, "by_lifecycle": by_life,
            "by_confidence": conf_buckets,
            "tag_usage": self.tag_stats(),
        }

    def all_values_by_type(self, itype: str) -> List[str]:
        return [i.value for i in self._iocs.values() if i.type == itype]

    def count(self) -> int:
        return len(self._iocs)


_phase: Optional[IOManagementPhase] = None


def get_management_phase() -> IOManagementPhase:
    global _phase
    if _phase is None:
        _phase = IOManagementPhase()
    return _phase
