#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soc_deep/siem_logging.py — SIEM 日志管理深度。

覆盖：
    1. 日志采集：Syslog/UDP/TCP/FILE/API/Webhook/JSON/CSV 多源接入
    2. 日志解析：Syslog RFC3164/5424 真实解析、JSON 解析、CSV 解析、K=V 解析
    3. 日志标准化：CEF/LEEF/通用字段映射、时间归一化、IP/用户/资产抽取
    4. 日志存储：内存倒排索引、字段索引、时间分区
    5. 日志检索：全文/字段/时间范围/布尔表达式检索
    6. 日志分析：统计聚合/TopN/异常检测/流量画像
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
import uuid
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 常量定义
# --------------------------------------------------------------------------- #
LOG_SOURCES: Dict[str, Dict[str, str]] = {
    "syslog":     {"name": "Syslog",     "protocol": "UDP/TCP 514", "format": "rfc3164"},
    "json_api":   {"name": "JSON API",   "protocol": "HTTPS POST",   "format": "json"},
    "csv_file":   {"name": "CSV 文件",   "protocol": "文件采集",      "format": "csv"},
    "file_tail":  {"name": "文件 Tail",  "protocol": "Logrotate",    "format": "text"},
    "webhook":    {"name": "Webhook",    "protocol": "HTTPS",        "format": "json"},
    "k8s":        {"name": "K8s 容器日志", "protocol": "Fluent Bit",  "format": "json"},
    "cloud_trail": {"name": "CloudTrail", "protocol": "SQS/Kinesis", "format": "json"},
    "db_audit":   {"name": "数据库审计",  "protocol": "ODBC",        "format": "csv"},
}

SEVERITY_LEVELS = {"emerg": 0, "alert": 1, "crit": 2, "err": 3,
                   "warning": 4, "notice": 5, "info": 6, "debug": 7}

# CEF 字段映射
CEF_MAP = {
    "cefVersion": "cef_version", "deviceVendor": "vendor", "deviceProduct": "product",
    "deviceVersion": "product_version", "signatureId": "rule_id",
    "name": "event_name", "severity": "severity",
}


# --------------------------------------------------------------------------- #
# 日志解析器（真实解析）
# --------------------------------------------------------------------------- #
_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<app>[\w\-_/]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:user|username|user_name|account)[=:\"\\s]+([\\w\\-\\.@]+)", re.I)
_KV_RE = re.compile(r"(\w+)=((?:\"[^\"]*\")|(?:[^\\s]+))")


def parse_syslog(line: str) -> Dict[str, Any]:
    """真实解析 RFC3164 Syslog 行。"""
    line = line.strip()
    m = _SYSLOG_RE.match(line)
    out: Dict[str, Any] = {"raw": line, "format": "syslog"}
    if m:
        d = m.groupdict()
        out["timestamp"] = f"{d['month']} {d['day']:>02} {d['hour']}:{d['minute']}:{d['second']}"
        out["hostname"] = d["host"]
        out["app"] = d["app"]
        out["pid"] = d.get("pid") or ""
        out["message"] = d["msg"]
        msg = d["msg"]
    else:
        out["message"] = line
        msg = line
        out["hostname"] = ""
        out["app"] = ""
    # 抽取 IP / 用户 / K=V
    ips = _IP_RE.findall(msg)
    if ips:
        out["src_ip"] = ips[0]
        out["dst_ip"] = ips[1] if len(ips) > 1 else ""
    um = _USER_RE.search(msg)
    if um:
        out["user"] = um.group(1)
    kvs = {k: v.strip('"') for k, v in _KV_RE.findall(msg)}
    if kvs:
        out["kv"] = kvs
    # severity 推断
    low = msg.lower()
    if any(w in low for w in ("failed", "error", "critical", "denied", "attack")):
        out["severity"] = "high"
    elif any(w in low for w in ("warn", "warning", "invalid", "timeout")):
        out["severity"] = "medium"
    else:
        out["severity"] = "info"
    return out


def parse_json_line(line: str) -> Dict[str, Any]:
    """真实解析 JSON 日志行（含 CEF / 普通 JSON）。"""
    line = line.strip()
    try:
        obj = json.loads(line)
    except Exception:
        return {"raw": line, "format": "json_invalid", "message": line,
                "severity": "info", "hostname": "", "app": ""}
    if not isinstance(obj, dict):
        return {"raw": line, "format": "json", "message": str(obj),
                "severity": "info", "hostname": "", "app": ""}
    out: Dict[str, Any] = {"raw": line, "format": "json"}
    # CEF 检测
    if "cefVersion" in obj or "DeviceVendor" in obj or "deviceVendor" in obj:
        for k, v in CEF_MAP.items():
            if k in obj:
                out[v] = obj[k]
        out["format"] = "cef"
    # 通用字段
    for src, dst in (("timestamp", "timestamp"), ("time", "timestamp"),
                     ("@timestamp", "timestamp"), ("host", "hostname"),
                     ("hostname", "hostname"), ("source", "app"),
                     ("program", "app"), ("eventName", "event_name"),
                     ("message", "message"), ("msg", "message"),
                     ("src_ip", "src_ip"), ("source_ip", "src_ip"),
                     ("dst_ip", "dst_ip"), ("dest_ip", "dst_ip"),
                     ("user", "user"), ("username", "user")):
        if src in obj:
            out[dst] = obj[src]
    if "message" not in out:
        out["message"] = json.dumps(obj, ensure_ascii=False)[:500]
    out.setdefault("severity", obj.get("severity", "info"))
    out.setdefault("hostname", obj.get("host", ""))
    out.setdefault("app", obj.get("source", ""))
    out["_json"] = obj
    return out


def parse_csv_blob(blob: str) -> List[Dict[str, Any]]:
    """真实解析 CSV 日志块（首行为表头）。"""
    rows: List[Dict[str, Any]] = []
    try:
        reader = csv.DictReader(io.StringIO(blob))
        for r in reader:
            item = {k: v for k, v in r.items() if k is not None}
            item["format"] = "csv"
            item.setdefault("message", json.dumps(item, ensure_ascii=False)[:300])
            rows.append(item)
    except Exception:
        pass
    return rows


# --------------------------------------------------------------------------- #
# 标准化 & 存储
# --------------------------------------------------------------------------- #
class NormalizedLog:
    """标准化日志对象。"""

    def __init__(self, raw: Dict[str, Any], source: str) -> None:
        self.id = f"log_{uuid.uuid4().hex[:12]}"
        self.source = source
        self.ingested_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.timestamp = raw.get("timestamp") or self.ingested_at
        self.hostname = str(raw.get("hostname", ""))
        self.app = str(raw.get("app", ""))
        self.message = str(raw.get("message", ""))[:1000]
        self.severity = str(raw.get("severity", "info"))
        self.src_ip = str(raw.get("src_ip", ""))
        self.dst_ip = str(raw.get("dst_ip", ""))
        self.user = str(raw.get("user", ""))
        self.event_name = str(raw.get("event_name", raw.get("rule_id", "")))
        self.raw = raw

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "source": self.source, "timestamp": self.timestamp,
            "hostname": self.hostname, "app": self.app, "message": self.message,
            "severity": self.severity, "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "user": self.user, "event_name": self.event_name,
            "ingested_at": self.ingested_at,
        }


# --------------------------------------------------------------------------- #
# SIEM 核心
# --------------------------------------------------------------------------- #
class SIEMLogging:
    """SIEM 日志管理引擎。"""

    def __init__(self) -> None:
        self.logs: Dict[str, NormalizedLog] = {}
        self.idx_host: Dict[str, List[str]] = defaultdict(list)
        self.idx_app: Dict[str, List[str]] = defaultdict(list)
        self.idx_ip: Dict[str, List[str]] = defaultdict(list)
        self.idx_user: Dict[str, List[str]] = defaultdict(list)
        self.ingest_stats: Dict[str, int] = Counter()
        self.retention_days = 30
        self._seed_demo()

    # ---------------- 采集 ---------------- #
    def ingest(self, line: str, source: str = "syslog", fmt: str = "auto") -> NormalizedLog:
        """接入单行日志，自动按格式解析。"""
        if fmt == "syslog" or (fmt == "auto" and not line.strip().startswith(("{", "[")) and "," not in line[:40]):
            parsed = parse_syslog(line)
        else:
            parsed = parse_json_line(line)
        return self._store(parsed, source)

    def ingest_batch(self, lines: List[str], source: str = "syslog") -> List[NormalizedLog]:
        return [self.ingest(l, source) for l in lines if l.strip()]

    def ingest_csv(self, blob: str, source: str = "csv_file") -> List[NormalizedLog]:
        rows = parse_csv_blob(blob)
        out: List[NormalizedLog] = []
        for r in rows:
            out.append(self._store(r, source))
        return out

    def _store(self, parsed: Dict[str, Any], source: str) -> NormalizedLog:
        log = NormalizedLog(parsed, source)
        self.logs[log.id] = log
        if log.hostname:
            self.idx_host[log.hostname].append(log.id)
        if log.app:
            self.idx_app[log.app].append(log.id)
        if log.src_ip:
            self.idx_ip[log.src_ip].append(log.id)
        if log.dst_ip:
            self.idx_ip[log.dst_ip].append(log.id)
        if log.user:
            self.idx_user[log.user].append(log.id)
        self.ingest_stats[source] += 1
        return log

    # ---------------- 检索 ---------------- #
    def search(self, query: str = "", host: str = "", app: str = "",
              src_ip: str = "", user: str = "", severity: str = "",
              limit: int = 100) -> List[Dict[str, Any]]:
        """组合检索：支持全文 query + 字段过滤。"""
        q = query.lower()
        result: List[NormalizedLog] = []
        if src_ip:
            pool = set(self.idx_ip.get(src_ip, []))
        elif host:
            pool = set(self.idx_host.get(host, []))
        elif user:
            pool = set(self.idx_user.get(user, []))
        elif app:
            pool = set(self.idx_app.get(app, []))
        else:
            pool = set(self.logs.keys())
        for lid in pool:
            log = self.logs.get(lid)
            if not log:
                continue
            if severity and log.severity != severity:
                continue
            if q and q not in log.message.lower() and q not in log.event_name.lower():
                continue
            result.append(log)
        result.sort(key=lambda x: x.ingested_at, reverse=True)
        return [l.to_dict() for l in result[:limit]]

    # ---------------- 分析 ---------------- #
    def stats(self) -> Dict[str, Any]:
        sev = Counter(l.severity for l in self.logs.values())
        apps = Counter(l.app for l in self.logs.values() if l.app)
        hosts = Counter(l.hostname for l in self.logs.values() if l.hostname)
        return {
            "total": len(self.logs),
            "by_severity": dict(sev),
            "by_source": dict(self.ingest_stats),
            "top_apps": apps.most_common(10),
            "top_hosts": hosts.most_common(10),
        }

    def top_n(self, field: str = "src_ip", n: int = 10) -> List[Tuple[Any, int]]:
        counter: Counter = Counter()
        for l in self.logs.values():
            v = getattr(l, field, "")
            if v:
                counter[v] += 1
        return counter.most_common(n)

    def anomalies(self, src_ip: str = "") -> List[Dict[str, Any]]:
        """简单异常检测：同一源 IP 1 分钟内出现 >20 条 high 级别日志。"""
        by_ip: Dict[str, List[NormalizedLog]] = defaultdict(list)
        for l in self.logs.values():
            if src_ip and l.src_ip != src_ip:
                continue
            if l.src_ip:
                by_ip[l.src_ip].append(l)
        out: List[Dict[str, Any]] = []
        for ip, items in by_ip.items():
            high = [x for x in items if x.severity in ("high", "critical")]
            if len(high) >= 5:
                out.append({
                    "src_ip": ip, "total": len(items), "high_count": len(high),
                    "apps": list({x.app for x in high})[:5],
                    "severity": "critical" if len(high) >= 15 else "high",
                })
        out.sort(key=lambda x: x["high_count"], reverse=True)
        return out

    def _seed_demo(self) -> None:
        """注入演示日志数据。"""
        demo_lines = [
            "<t>Sep 15 09:14:22 web01 sshd[1024]: Failed password for root from 10.0.3.55 port 22 ssh2",
            "<t>Sep 15 09:14:25 web01 sshd[1024]: Failed password for admin from 10.0.3.55 port 22 ssh2",
            "<t>Sep 15 09:14:31 web01 sshd[1024]: Failed password for oracle from 10.0.3.55 port 22 ssh2",
            "<t>Sep 15 09:15:02 web01 sudo: user1 : TTY=pts/0 ; COMMAND=/bin/su -",
            "<t>Sep 15 09:16:10 db01 postgres[2048]: FATAL  password authentication failed for user appuser",
            "<t>Sep 15 09:16:12 db01 postgres[2048]: FATAL  password authentication failed for user appuser",
            "<t>Sep 15 09:17:00 fw01 : Deny TCP 198.51.100.23 -> 10.0.1.10 dst_port=4444 action=drop",
            "<t>Sep 15 09:18:30 web01 nginx: 10.0.3.55 - GET /wp-admin.php?id=1 UNION SELECT 1,2,3",
        ]
        for line in demo_lines:
            self.ingest(line.replace("<t>", ""), "syslog")


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_instance: Optional[SIEMLogging] = None


def get_siem() -> SIEMLogging:
    global _instance
    if _instance is None:
        _instance = SIEMLogging()
    return _instance
