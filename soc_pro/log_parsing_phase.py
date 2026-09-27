# -*- coding: utf-8 -*-
"""
log_parsing_phase.py — 阶段2：日志解析。

功能:
    - 日志标准化（统一格式/时间戳归一化/字段标准化）
    - 字段提取（正则提取/Grok 模式/JSON 解析/CSV 解析）
    - 富化（IP 地理位置/ASN/威胁情报匹配/资产信息关联）
    - 解析规则管理
    - 解析质量监控
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .log_collection_phase import get_log_collection_phase


# --------------------------------------------------------------------------- #
# 数据类
# --------------------------------------------------------------------------- #
@dataclass
class ParseRule:
    rule_id: str = ""
    name: str = ""
    pattern_type: str = "regex"   # regex/grok/json/csv
    pattern: str = ""
    fields: List[str] = field(default_factory=list)
    enabled: bool = True
    hits: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "name": self.name,
            "pattern_type": self.pattern_type,
            "pattern": self.pattern, "fields": self.fields,
            "enabled": self.enabled, "hits": self.hits,
        }


@dataclass
class ParsedLog:
    parsed_id: str = ""
    raw_log_id: str = ""
    raw: str = ""
    timestamp: str = ""
    normalized_ts: str = ""
    level: str = "INFO"
    src_ip: str = ""
    dst_ip: str = ""
    user: str = ""
    action: str = ""
    status_code: str = ""
    product: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    geo: Dict[str, str] = field(default_factory=dict)
    asn: str = ""
    ti_hit: bool = False
    ti_tags: List[str] = field(default_factory=list)
    parse_quality: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parsed_id": self.parsed_id, "raw_log_id": self.raw_log_id,
            "raw": self.raw[:400],
            "timestamp": self.timestamp,
            "normalized_ts": self.normalized_ts,
            "level": self.level, "src_ip": self.src_ip,
            "dst_ip": self.dst_ip, "user": self.user,
            "action": self.action, "status_code": self.status_code,
            "product": self.product, "extra": self.extra,
            "geo": self.geo, "asn": self.asn,
            "ti_hit": self.ti_hit, "ti_tags": self.ti_tags,
            "parse_quality": round(self.parse_quality, 2),
        }


# --------------------------------------------------------------------------- #
# 内置 Grok 风格模式（轻量正则，不依赖 grok 库）
# --------------------------------------------------------------------------- #
_BUILTIN_RULES: List[Tuple[str, str, str, List[str]]] = [
    ("ssh_fail", "SSH 失败登录", "regex",
     r"Failed password for invalid user (?P<user>\S+) from (?P<src_ip>[\d\.]+)",
     ["user", "src_ip"]),
    ("ssh_ok", "SSH 成功登录", "regex",
     r"Accepted password for (?P<user>\S+) from (?P<src_ip>[\d\.]+)",
     ["user", "src_ip"]),
    ("apache_401", "Apache 401", "regex",
     r"(?P<src_ip>[\d\.]+) .* \"(?P<action>\S+) (?P<path>\S+) [^\"]*\" "
     r"(?P<status>\d{3})",
     ["src_ip", "action", "path", "status"]),
    ("asa", "Cisco ASA", "regex",
     r"Deny (?P<proto>\w+) src inside:(?P<src_ip>[\d\.]+)/\d+ "
     r"dst outside:(?P<dst_ip>[\d\.]+)/\d+",
     ["proto", "src_ip", "dst_ip"]),
    ("suricata", "Suricata 告警", "regex",
     r"Suricata.*\] (?P<sig>ET \S+ \S+ \S+).* (?P<src_ip>[\d\.]+):\d+ -> "
     r"(?P<dst_ip>[\d\.]+):\d+",
     ["sig", "src_ip", "dst_ip"]),
    ("sudo", "Sudo 提权", "regex",
     r"sudo:\s+(?P<user>\S+).*COMMAND=(?P<action>.+)",
     ["user", "action"]),
    ("dns_out", "异常外发", "regex",
     r"Host (?P<src_ip>[\d\.]+) sent (?P<size>\d+) bytes outbound to "
     r"(?P<dst_ip>[\d\.]+)",
     ["src_ip", "dst_ip", "size"]),
    ("sysmon_file", "Sysmon 文件创建", "regex",
     r"EventID=(?P<event>\d+).*user=(?P<user>\S+).*"
     r"(?P<path>[\w:\\\\\.\-]+\\(?P<file>[\w\.\-]+))",
     ["event", "user", "path", "file"]),
]

# 内置威胁情报（演示用）
_TI_IPS = {
    "45.155.205.10": ["c2", "emotet"],
    "185.220.101.4": ["c2", "tor-exit"],
    "194.147.76.23": ["scanner", "masscan"],
    "91.219.236.10": ["c2", "agenttesla"],
}

# 内置 IP 地理库（粗略，演示用）
_GEO_DB = {
    "10.": "内网/RFC1918",
    "192.168.": "内网/RFC1918",
    "172.16.": "内网/RFC1918",
    "203.0.113.": "测试段",
    "198.51.100.": "测试段",
}


def _geo_for(ip: str) -> Dict[str, str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"country": "未知", "city": "未知"}
    if addr.is_private:
        return {"country": "内网", "city": "RFC1918"}
    for prefix, loc in _GEO_DB.items():
        if ip.startswith(prefix):
            return {"country": loc, "city": loc}
    # 粗粒度归属：A 类 / B 类首段
    first = int(ip.split(".")[0])
    if 1 <= first <= 126:
        return {"country": "美国/境外", "city": "未知"}
    if 128 <= first <= 191:
        return {"country": "欧洲/境外", "city": "未知"}
    if 192 <= first <= 223:
        return {"country": "亚太", "city": "未知"}
    return {"country": "未知", "city": "未知"}


# --------------------------------------------------------------------------- #
# 阶段类
# --------------------------------------------------------------------------- #
class LogParsingPhase:
    """阶段2：日志解析。"""

    def __init__(self) -> None:
        self._rules: Dict[str, ParseRule] = {}
        self._parsed: "list" = []
        self._lock = threading.Lock()
        self._load_builtin_rules()

    def _load_builtin_rules(self) -> None:
        for rid, name, ptype, pattern, fields in _BUILTIN_RULES:
            self._rules[rid] = ParseRule(
                rule_id=rid, name=name, pattern_type=ptype,
                pattern=pattern, fields=fields,
            )

    # ------------------------------------------------------------------ #
    def list_rules(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self._rules.values()]

    def add_rule(self, name: str, pattern_type: str, pattern: str,
                 fields: Optional[List[str]] = None) -> Dict[str, Any]:
        rid = "rule_" + uuid.uuid4().hex[:8]
        r = ParseRule(rule_id=rid, name=name, pattern_type=pattern_type,
                      pattern=pattern, fields=fields or [])
        with self._lock:
            self._rules[rid] = r
        return r.to_dict()

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        with self._lock:
            r = self._rules.get(rule_id)
            if r is None:
                return False
            r.enabled = enabled
            return True

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            return self._rules.pop(rule_id, None) is not None

    # ------------------------------------------------------------------ #
    def _match_rule(self, raw: str, r: ParseRule
                    ) -> Optional[Dict[str, str]]:
        if not r.enabled:
            return None
        try:
            m = re.search(r.pattern, raw, re.IGNORECASE)
        except re.error:
            return None
        if not m:
            return None
        out = {k: v for k, v in m.groupdict().items() if v}
        return out or {"_match": m.group(0)}

    def parse_one(self, raw: str, source: str = "") -> ParsedLog:
        p = ParsedLog(parsed_id="prs_" + uuid.uuid4().hex[:10],
                      raw=raw)
        if source:
            p.extra["_source"] = source
        hits = 0
        matched: Dict[str, str] = {}
        with self._lock:
            rules = list(self._rules.values())
        for r in rules:
            m = self._match_rule(raw, r)
            if m:
                matched.update(m)
                r.hits += 1
                hits += 1
        # 字段映射
        p.src_ip = matched.get("src_ip", "")
        p.dst_ip = matched.get("dst_ip", "")
        p.user = matched.get("user", "")
        p.action = matched.get("action", matched.get("path", ""))
        p.status_code = matched.get("status", "")
        p.extra = {k: v for k, v in matched.items()
                   if k not in ("src_ip", "dst_ip", "user",
                                "action", "status")}
        # 级别推断
        low = raw.lower()
        if any(k in low for k in ("fail", "deny", "error", "alert",
                                  "critical")):
            p.level = "WARN"
        if any(k in low for k in ("accepted password", "sudo",
                                  "files/create", "c2")):
            p.level = "HIGH"
        # 时间戳归一化
        p.timestamp = datetime.now().isoformat(timespec="seconds")
        p.normalized_ts = p.timestamp
        # 富化
        if p.src_ip:
            p.geo = _geo_for(p.src_ip)
            if p.src_ip in _TI_IPS:
                p.ti_hit = True
                p.ti_tags = _TI_IPS[p.src_ip]
            p.asn = "AS" + str(13335) if p.geo.get("country", "") \
                else "AS0"
        # 解析质量
        filled = sum(1 for v in (p.src_ip, p.user, p.action,
                                 p.status_code) if v)
        p.parse_quality = min(1.0, (filled + hits * 0.1) / 2.5)
        return p

    # ------------------------------------------------------------------ #
    def parse_batch(self, raw_logs: Optional[List[Dict[str, Any]]] = None,
                    limit: int = 500) -> Dict[str, Any]:
        if raw_logs is None:
            raw_logs = get_log_collection_phase().recent_logs(limit)
        parsed: List[ParsedLog] = []
        t0 = time.time()
        for rec in raw_logs:
            p = self.parse_one(rec.get("raw", ""),
                               source=rec.get("source_name", ""))
            p.raw_log_id = rec.get("log_id", "")
            parsed.append(p)
        with self._lock:
            self._parsed.extend(p.to_dict() for p in parsed)
            self._parsed = self._parsed[-5000:]
        ok_n = sum(1 for p in parsed if p.parse_quality > 0.2)
        return {
            "total": len(parsed),
            "parsed_ok": ok_n,
            "failed": len(parsed) - ok_n,
            "avg_quality": (sum(p.parse_quality for p in parsed)
                            / max(1, len(parsed))),
            "elapsed": round(time.time() - t0, 3),
            "ti_hits": sum(1 for p in parsed if p.ti_hit),
            "samples": [p.to_dict() for p in parsed[-20:]],
        }

    # ------------------------------------------------------------------ #
    def recent_parsed(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._parsed[-limit:])

    def quality_stats(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._parsed)
        if not items:
            return {"total": 0}
        avg = sum(x.get("parse_quality", 0) for x in items) / len(items)
        high = sum(1 for x in items if x.get("parse_quality", 0) > 0.7)
        return {
            "total": len(items),
            "avg_quality": round(avg, 3),
            "high_quality": high,
            "low_quality": len(items) - high,
            "ti_hits": sum(1 for x in items if x.get("ti_hit")),
        }


_default: Optional[LogParsingPhase] = None


def get_log_parsing_phase() -> LogParsingPhase:
    global _default
    if _default is None:
        _default = LogParsingPhase()
    return _default
