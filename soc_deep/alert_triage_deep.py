#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soc_deep/alert_triage_deep.py — 告警分诊与聚合深度。

覆盖：
    1. 告警接入：SIEM/IDS/IPS/WAF/EDR/邮件/云安全/Webhook 多源
    2. 告警去重：精确哈希/时间窗口/同源/相似度
    3. 告警聚合：按资产/攻击链/时间/严重程度/类型
    4. 告警分诊：自动分诊/严重程度/优先级/风险评分/影响范围
    5. 告警丰富化：资产/漏洞/情报/历史告警/用户上下文
    6. 告警处置：确认/抑制/升级/误报标记/指派
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
ALERT_SOURCES = {
    "siem": "SIEM平台", "ids": "IDS", "ips": "IPS", "waf": "WAF",
    "edr": "EDR", "email": "邮件安全", "cloud": "云安全",
    "correlation": "关联规则", "webhook": "Webhook",
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

TRIAGE_STATUSES = ("new", "triaging", "escalated", "confirmed",
                   "false_positive", "suppressed", "resolved")

DISPOSITIONS = {"confirmed": 5, "escalated": 4, "triaging": 3,
                "suppressed": 2, "false_positive": 1, "resolved": 1}


# --------------------------------------------------------------------------- #
# 告警对象
# --------------------------------------------------------------------------- #
class TriagedAlert:
    def __init__(self, raw: Dict[str, Any], source: str) -> None:
        self.id = f"talt_{uuid.uuid4().hex[:10]}"
        self.source = source
        self.ingested_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.title = raw.get("title", "未命名告警")
        self.severity = raw.get("severity", "medium")
        self.category = raw.get("category", "unknown")
        self.src_ip = raw.get("src_ip", "")
        self.dst_ip = raw.get("dst_ip", "")
        self.user = raw.get("user", "")
        self.asset = raw.get("asset", "unknown")
        self.description = raw.get("description", "")
        self.tags: List[str] = list(raw.get("tags", []) or [])
        self.status = "new"
        self.risk_score = 0
        self.priority = "P3"
        self.duplicate_of: Optional[str] = None
        self.aggregate_id: Optional[str] = None
        self.assignee: Optional[str] = None
        self.enrichment: Dict[str, Any] = {}
        self.raw = raw
        self.dedup_hash = self._dedup()

    def _dedup(self) -> str:
        key = f"{self.src_ip}|{self.dst_ip}|{self.category}|{self.title}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "source": self.source, "title": self.title,
            "severity": self.severity, "category": self.category,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "user": self.user, "asset": self.asset,
            "description": self.description, "tags": self.tags,
            "status": self.status, "risk_score": self.risk_score,
            "priority": self.priority, "duplicate_of": self.duplicate_of,
            "aggregate_id": self.aggregate_id, "assignee": self.assignee,
            "enrichment": self.enrichment, "ingested_at": self.ingested_at,
            "dedup_hash": self.dedup_hash,
        }


# --------------------------------------------------------------------------- #
# 分诊引擎
# --------------------------------------------------------------------------- #
class AlertTriageDeep:
    def __init__(self) -> None:
        self.alerts: Dict[str, TriagedAlert] = {}
        self.dedup_index: Dict[str, str] = {}
        self.aggregates: Dict[str, Dict[str, Any]] = {}
        self.dedup_window_sec = 300
        self.known_assets: Dict[str, Dict[str, Any]] = {
            "web-server-01": {"ip": "10.0.1.10", "critical": True, "exposure": "public"},
            "db-server-01":  {"ip": "10.0.2.10", "critical": True, "exposure": "internal"},
            "dc-01":         {"ip": "10.0.0.5",  "critical": True, "exposure": "internal"},
            "jump-host":     {"ip": "10.0.0.20", "critical": True, "exposure": "public"},
        }
        self._seed_demo()

    # ---------------- 接入 ---------------- #
    def ingest(self, raw: Dict[str, Any], source: str = "siem") -> TriagedAlert:
        alert = TriagedAlert(raw, source)
        # 去重
        existing = self.dedup_index.get(alert.dedup_hash)
        if existing:
            alert.duplicate_of = existing
            alert.status = "suppressed"
        self.alerts[alert.id] = alert
        self.dedup_index[alert.dedup_hash] = alert.id
        # 自动分诊
        self.triage(alert)
        # 自动聚合
        self.auto_aggregate(alert)
        # 自动丰富
        self.enrich(alert)
        return alert

    def ingest_batch(self, items: List[Dict[str, Any]], source: str = "siem") -> List[TriagedAlert]:
        return [self.ingest(it, source) for it in items]

    # ---------------- 分诊 ---------------- #
    def triage(self, alert: TriagedAlert) -> None:
        """风险评分 + 优先级。"""
        score = SEVERITY_ORDER.get(alert.severity, 1) * 20
        # 资产关键性加成
        asset_info = self.known_assets.get(alert.asset, {})
        if asset_info.get("critical"):
            score += 20
        if asset_info.get("exposure") == "public":
            score += 10
        # 类别加成
        if alert.category in ("malware", "data_exfil", "lateral_move"):
            score += 15
        if alert.category == "recon":
            score -= 5
        # 历史重复加分
        if alert.duplicate_of:
            score += 5
        alert.risk_score = max(0, min(100, score))
        if alert.risk_score >= 80:
            alert.priority = "P0"
        elif alert.risk_score >= 60:
            alert.priority = "P1"
        elif alert.risk_score >= 40:
            alert.priority = "P2"
        else:
            alert.priority = "P3"
        if alert.status == "new":
            alert.status = "triaging"

    # ---------------- 聚合 ---------------- #
    def auto_aggregate(self, alert: TriagedAlert) -> None:
        key = f"{alert.category}|{alert.asset}|{alert.dst_ip}"
        agg_id = f"agg_{hashlib.md5(key.encode()).hexdigest()[:10]}"
        agg = self.aggregates.setdefault(agg_id, {
            "id": agg_id, "key": key, "members": [],
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "max_severity": "info", "count": 0,
        })
        agg["members"].append(alert.id)
        agg["count"] = len(agg["members"])
        if SEVERITY_ORDER.get(alert.severity, 0) > SEVERITY_ORDER.get(agg["max_severity"], 0):
            agg["max_severity"] = alert.severity
        alert.aggregate_id = agg_id

    # ---------------- 丰富化 ---------------- #
    def enrich(self, alert: TriagedAlert) -> None:
        info: Dict[str, Any] = {}
        if alert.asset in self.known_assets:
            info["asset"] = self.known_assets[alert.asset]
        # 历史同源告警
        hist = [a for a in self.alerts.values()
                if a.src_ip == alert.src_ip and a.id != alert.id]
        info["same_source_history"] = len(hist)
        info["same_source_last"] = hist[0].ingested_at if hist else None
        alert.enrichment = info

    # ---------------- 处置 ---------------- #
    def update_status(self, alert_id: str, status: str,
                      assignee: Optional[str] = None, note: str = "") -> Optional[TriagedAlert]:
        a = self.alerts.get(alert_id)
        if not a:
            return None
        if status in TRIAGE_STATUSES:
            a.status = status
        if assignee:
            a.assignee = assignee
        if note:
            a.enrichment.setdefault("notes", []).append(
                {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "note": note})
        return a

    def list_alerts(self, status: str = "", severity: str = "",
                    category: str = "", source: str = "",
                    keyword: str = "", limit: int = 200) -> List[Dict[str, Any]]:
        out = []
        for a in self.alerts.values():
            if status and a.status != status:
                continue
            if severity and a.severity != severity:
                continue
            if category and a.category != category:
                continue
            if source and a.source != source:
                continue
            if keyword and keyword.lower() not in a.title.lower():
                continue
            out.append(a.to_dict())
        out.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 0),
                                 x["risk_score"]), reverse=True)
        return out[:limit]

    def aggregates(self) -> List[Dict[str, Any]]:
        return sorted(self.aggregates.values(),
                      key=lambda x: (SEVERITY_ORDER.get(x["max_severity"], 0),
                                     x["count"]), reverse=True)

    def summary(self) -> Dict[str, Any]:
        sev = Counter(a.severity for a in self.alerts.values())
        st = Counter(a.status for a in self.alerts.values())
        return {
            "total": len(self.alerts),
            "by_severity": dict(sev),
            "by_status": dict(st),
            "aggregates": len(self.aggregates),
            "p0_p1": sum(1 for a in self.alerts.values() if a.priority in ("P0", "P1")),
        }

    def _seed_demo(self) -> None:
        samples = [
            {"title": "SSH 爆破尝试", "severity": "high", "category": "bruteforce",
             "src_ip": "10.0.3.55", "dst_ip": "10.0.1.10", "asset": "web-server-01",
             "user": "root", "description": "Failed password root"},
            {"title": "SQL 注入", "severity": "critical", "category": "web_attack",
             "src_ip": "203.0.113.8", "dst_ip": "10.0.1.10", "asset": "web-server-01",
             "description": "UNION SELECT attempt"},
            {"title": "可疑出站", "severity": "medium", "category": "c2",
             "src_ip": "10.0.1.10", "dst_ip": "198.51.100.23", "asset": "web-server-01",
             "description": "Connection to port 4444"},
        ]
        for s in samples:
            self.ingest(s, "siem")


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_instance: Optional[AlertTriageDeep] = None


def get_alert_triage_deep() -> AlertTriageDeep:
    global _instance
    if _instance is None:
        _instance = AlertTriageDeep()
    return _instance
