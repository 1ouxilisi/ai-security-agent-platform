#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar_deep/alert_triage.py — 深度告警分诊与聚合。

覆盖：
    1. 告警接入：多源(SIEM/IDS/IPS/WAF/EDR/邮件/云安全/自定义API/Webhook)
    2. 告警标准化：格式标准化/字段映射/严重程度归一化/分类标准化/标签标准化
    3. 告警去重：精确/模糊/时间窗口/同源/相似度算法/去重策略配置
    4. 告警聚合：按资产/攻击链/时间/严重程度/类型/自定义规则
    5. 告警分诊：自动分诊/严重程度评估/优先级排序/风险评分/影响范围/可利用性
    6. 告警丰富化：资产/漏洞/威胁情报/历史告警/用户/上下文关联
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 告警源定义
# --------------------------------------------------------------------------- #
ALERT_SOURCES: Dict[str, Dict[str, str]] = {
    "siem":          {"name": "SIEM平台", "vendor": "Splunk/ELK/QRadar", "format": "cef"},
    "ids":           {"name": "IDS入侵检测", "vendor": "Snort/Suricata", "format": "eve_json"},
    "ips":           {"name": "IPS入侵防御", "vendor": "Palo Alto/Fortinet", "format": "syslog"},
    "waf":           {"name": "WAF Web防火墙", "vendor": "Cloudflare/ModSecurity", "format": "json"},
    "edr":           {"name": "EDR终端防护", "vendor": "CrowdStrike/SentinelOne", "format": "json"},
    "email_security": {"name": "邮件安全", "vendor": "Mimecast/Proofpoint", "format": "json"},
    "cloud_security": {"name": "云安全", "vendor": "AWS GuardDuty/Azure ASC", "format": "json"},
    "webhook":       {"name": "Webhook接入", "vendor": "自定义", "format": "json"},
    "custom_api":    {"name": "自定义API", "vendor": "自定义", "format": "json"},
}

# 严重程度归一化映射
SEVERITY_MAP: Dict[str, List[str]] = {
    "critical": ["critical", "紧急", "P0", "sev1", "1", "red"],
    "high":     ["high", "严重", "P1", "sev2", "2", "orange"],
    "medium":   ["medium", "中危", "P2", "sev3", "3", "yellow"],
    "low":      ["low", "低危", "P3", "sev4", "4", "green", "info"],
}

# 分类标准化
CATEGORY_MAP: Dict[str, List[str]] = {
    "malware":       ["恶意软件", "malware", "ransomware", "virus", "trojan"],
    "phishing":      ["钓鱼", "phishing", "spear_phishing"],
    "bruteforce":    ["暴力破解", "brute_force", "bruteforce", "password_attack"],
    "web_attack":    ["Web攻击", "web_attack", "xss", "sqli", "rce"],
    "data_exfil":    ["数据泄露", "data_exfiltration", "exfiltration", "leak"],
    "lateral_move":  ["横向移动", "lateral_movement", "lateral"],
    "priv_esc":      ["提权", "privilege_escalation", "privesc"],
    "ddos":          ["DDoS", "ddos", "dos", "flood"],
    "recon":         ["信息收集", "recon", "scanning", "enumeration"],
    "insider":       ["内部威胁", "insider_threat", "insider"],
}


# --------------------------------------------------------------------------- #
# 告警对象
# --------------------------------------------------------------------------- #
class Alert:
    """标准化告警对象。"""

    def __init__(self, raw: Dict[str, Any], source: str) -> None:
        self.id = f"alt_{uuid.uuid4().hex[:12]}"
        self.source = source
        self.ingested_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.title = raw.get("title") or raw.get("name") or raw.get("rule_name") or "未命名告警"
        self.raw_severity = str(raw.get("severity", "medium"))
        self.severity = self._normalize_severity(self.raw_severity)
        self.category = self._normalize_category(raw.get("category", raw.get("type", "")))
        self.src_ip = raw.get("src_ip", raw.get("source_ip", ""))
        self.dst_ip = raw.get("dst_ip", raw.get("dest_ip", raw.get("target_ip", "")))
        self.src_port = raw.get("src_port", "")
        self.dst_port = raw.get("dst_port", raw.get("dest_port", ""))
        self.user = raw.get("user", raw.get("username", ""))
        self.asset = raw.get("asset", raw.get("host", raw.get("hostname", "unknown")))
        self.description = raw.get("description", raw.get("msg", raw.get("message", "")))
        self.tags: List[str] = raw.get("tags", []) if isinstance(raw.get("tags"), list) else []
        self.raw_data = raw
        self.status = "new"  # new / triaged / aggregated / enriched / resolved / false_positive
        self.risk_score = 0
        self.priority = "P3"
        self.duplicate_of: Optional[str] = None
        self.aggregate_group: Optional[str] = None
        self.enrichment: Dict[str, Any] = {}
        self.dedup_hash = self._compute_dedup_hash()

    @staticmethod
    def _normalize_severity(raw: str) -> str:
        low = raw.lower().strip()
        for sev, vals in SEVERITY_MAP.items():
            if low in [v.lower() for v in vals]:
                return sev
        return "medium"

    @staticmethod
    def _normalize_category(raw: str) -> str:
        low = raw.lower().strip()
        for cat, vals in CATEGORY_MAP.items():
            for v in vals:
                if v.lower() in low:
                    return cat
        return "unknown"

    def _compute_dedup_hash(self) -> str:
        """基于关键字段计算去重哈希。"""
        key = f"{self.src_ip}|{self.dst_ip}|{self.dst_port}|{self.category}|{self.title}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "source": self.source, "title": self.title,
            "severity": self.severity, "category": self.category,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "user": self.user, "asset": self.asset,
            "description": self.description, "tags": self.tags,
            "status": self.status, "risk_score": self.risk_score,
            "priority": self.priority, "duplicate_of": self.duplicate_of,
            "aggregate_group": self.aggregate_group,
            "enrichment": self.enrichment,
            "ingested_at": self.ingested_at,
            "dedup_hash": self.dedup_hash,
        }


# --------------------------------------------------------------------------- #
# 告警分诊引擎
# --------------------------------------------------------------------------- #
class AlertTriage:
    """告警分诊与聚合引擎。"""

    def __init__(self) -> None:
        self.alerts: Dict[str, Alert] = {}
        self.dedup_index: Dict[str, str] = {}  # hash -> alert_id
        self.aggregates: Dict[str, List[str]] = {}  # group_id -> [alert_ids]
        self.dedup_window_sec = 300  # 5分钟时间窗口
        self.fuzzy_threshold = 0.85  # 相似度阈值
        self.known_assets: Dict[str, Dict[str, Any]] = {
            "web-server-01": {"ip": "10.0.1.10", "os": "Ubuntu 22.04", "critical": True,
                              "owner": "web-team", "exposure": "public"},
            "db-server-01": {"ip": "10.0.2.10", "os": "CentOS 8", "critical": True,
                             "owner": "db-team", "exposure": "internal"},
            "dc-01": {"ip": "10.0.0.5", "os": "Windows Server 2019", "critical": True,
                      "owner": "it-infra", "exposure": "internal"},
            "workstation-01": {"ip": "10.0.3.20", "os": "Windows 11", "critical": False,
                               "owner": "finance-user", "exposure": "internal"},
        }
        self.known_vulns: Dict[str, List[Dict[str, str]]] = {
            "10.0.1.10": [{"cve": "CVE-2024-21762", "cvss": "9.8", "status": "unpatched"},
                          {"cve": "CVE-2023-48795", "cvss": "7.5", "status": "patched"}],
        }
        self.threat_ips: Dict[str, Dict[str, Any]] = {
            "45.155.204.10": {"reputation": "malicious", "confidence": 95, "tags": ["c2", "botnet"]},
            "185.220.101.5": {"reputation": "malicious", "confidence": 90, "tags": ["scanner"]},
            "103.75.190.22": {"reputation": "suspicious", "confidence": 60, "tags": ["proxy"]},
        }
        self.stats_: Dict[str, int] = {"ingested": 0, "deduplicated": 0, "aggregated": 0,
                                       "triaged": 0, "enriched": 0}

    # ---- 1. 告警接入 ----
    def ingest(self, raw: Dict[str, Any], source: str = "custom_api") -> Alert:
        alert = Alert(raw, source)
        self.alerts[alert.id] = alert
        self.stats_["ingested"] += 1
        return alert

    def ingest_batch(self, items: List[Dict[str, Any]],
                     source: str = "webhook") -> List[Alert]:
        return [self.ingest(r, source) for r in items]

    # ---- 2. 告警去重 ----
    def deduplicate(self, alert_id: str) -> bool:
        """对单条告警执行去重检查。返回True=新告警, False=重复。"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        # 精确去重
        if alert.dedup_hash in self.dedup_index:
            existing_id = self.dedup_index[alert.dedup_hash]
            alert.duplicate_of = existing_id
            alert.status = "duplicate"
            self.stats_["deduplicated"] += 1
            return False
        self.dedup_index[alert.dedup_hash] = alert_id
        return True

    def fuzzy_deduplicate(self, alert_id: str) -> bool:
        """基于相似度的模糊去重（简化：比较src_ip+category）。"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        key = f"{alert.src_ip}|{alert.category}"
        for aid, existing in self.alerts.items():
            if aid == alert_id or existing.status == "duplicate":
                continue
            ekey = f"{existing.src_ip}|{existing.category}"
            if key == ekey:
                alert.duplicate_of = aid
                alert.status = "duplicate"
                self.stats_["deduplicated"] += 1
                return False
        return True

    # ---- 3. 告警聚合 ----
    def aggregate_by_asset(self) -> Dict[str, List[str]]:
        """按资产聚合告警。"""
        groups: Dict[str, List[str]] = {}
        for aid, alert in self.alerts.items():
            if alert.status == "duplicate":
                continue
            key = f"asset:{alert.asset}"
            groups.setdefault(key, []).append(aid)
        self.aggregates.update(groups)
        self.stats_["aggregated"] += len(groups)
        return groups

    def aggregate_by_attack_chain(self) -> Dict[str, List[str]]:
        """按攻击链阶段聚合。"""
        chain_order = ["recon", "bruteforce", "web_attack", "malware",
                       "lateral_move", "priv_esc", "data_exfil"]
        groups: Dict[str, List[str]] = {}
        for aid, alert in self.alerts.items():
            if alert.status == "duplicate":
                continue
            stage = alert.category if alert.category in chain_order else "other"
            key = f"chain:{stage}"
            groups.setdefault(key, []).append(aid)
            alert.aggregate_group = key
        self.aggregates.update(groups)
        return groups

    def aggregate_by_time(self, window_min: int = 10) -> Dict[str, List[str]]:
        """按时间窗口聚合。"""
        groups: Dict[str, List[str]] = {}
        sorted_alerts = sorted(self.alerts.values(), key=lambda a: a.ingested_at)
        for alert in sorted_alerts:
            if alert.status == "duplicate":
                continue
            # 按分钟桶聚合
            bucket = alert.ingested_at[:16]  # YYYY-MM-DD HH:MM
            key = f"time:{bucket}"
            groups.setdefault(key, []).append(alert.id)
            alert.aggregate_group = key
        self.aggregates.update(groups)
        return groups

    # ---- 4. 告警分诊 ----
    def triage(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """自动分诊：风险评分+优先级。"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return None

        score = 0
        # 严重程度分
        sev_scores = {"critical": 40, "high": 30, "medium": 15, "low": 5}
        score += sev_scores.get(alert.severity, 10)

        # 资产关键性
        asset_info = self.known_assets.get(alert.asset, {})
        if asset_info.get("critical"):
            score += 20
        if asset_info.get("exposure") == "public":
            score += 10

        # 威胁情报分
        if alert.src_ip in self.threat_ips:
            ti = self.threat_ips[alert.src_ip]
            score += int(ti["confidence"] / 2)

        # 分类风险
        cat_risk = {"malware": 25, "ransomware": 35, "data_exfil": 30,
                    "priv_esc": 25, "lateral_move": 20, "bruteforce": 15}
        score += cat_risk.get(alert.category, 5)

        alert.risk_score = min(score, 100)

        # 优先级
        if score >= 70:
            alert.priority = "P0"
        elif score >= 50:
            alert.priority = "P1"
        elif score >= 30:
            alert.priority = "P2"
        else:
            alert.priority = "P3"

        alert.status = "triaged"
        self.stats_["triaged"] += 1

        return {
            "alert_id": alert_id,
            "risk_score": alert.risk_score,
            "priority": alert.priority,
            "factors": {
                "severity_contribution": sev_scores.get(alert.severity, 10),
                "asset_critical": asset_info.get("critical", False),
                "threat_intel_match": alert.src_ip in self.threat_ips,
                "category_risk": cat_risk.get(alert.category, 5),
            },
        }

    def triage_all(self) -> Dict[str, int]:
        """对所有未分诊告警执行分诊。"""
        count = 0
        for aid, alert in self.alerts.items():
            if alert.status in ("new", "aggregated"):
                self.triage(aid)
                count += 1
        return {"triaged_count": count}

    # ---- 5. 告警丰富化 ----
    def enrich(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """告警丰富化：补充资产/漏洞/威胁情报/历史信息。"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return None

        enrichment: Dict[str, Any] = {}

        # 资产信息
        asset_info = self.known_assets.get(alert.asset, {})
        enrichment["asset"] = asset_info or {"note": "未找到资产信息"}

        # 漏洞信息
        vulns = self.known_vulns.get(alert.dst_ip, [])
        enrichment["vulnerabilities"] = vulns

        # 威胁情报
        ti = self.threat_ips.get(alert.src_ip, {})
        enrichment["threat_intel"] = ti or {"reputation": "unknown"}

        # 历史告警
        history = [a.to_dict() for a in self.alerts.values()
                   if a.src_ip == alert.src_ip and a.id != alert_id]
        enrichment["historical_alerts"] = {
            "count": len(history),
            "recent": history[:5],
        }

        # 用户信息
        enrichment["user_info"] = {
            "username": alert.user or "unknown",
            "status": "active" if alert.user else "N/A",
        }

        alert.enrichment = enrichment
        if alert.status == "triaged":
            alert.status = "enriched"
        self.stats_["enriched"] += 1
        return enrichment

    def enrich_all(self) -> Dict[str, int]:
        count = 0
        for aid, alert in self.alerts.items():
            if alert.status == "triaged":
                self.enrich(aid)
                count += 1
        return {"enriched_count": count}

    # ---- 查询 ----
    def list_alerts(self, status: Optional[str] = None,
                    severity: Optional[str] = None,
                    category: Optional[str] = None,
                    priority: Optional[str] = None,
                    limit: int = 100) -> List[Dict[str, Any]]:
        items = list(self.alerts.values())
        if status:
            items = [a for a in items if a.status == status]
        if severity:
            items = [a for a in items if a.severity == severity]
        if category:
            items = [a for a in items if a.category == category]
        if priority:
            items = [a for a in items if a.priority == priority]
        # 按风险分降序
        items.sort(key=lambda a: a.risk_score, reverse=True)
        return [a.to_dict() for a in items[:limit]]

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        a = self.alerts.get(alert_id)
        return a.to_dict() if a else None

    def list_sources(self) -> Dict[str, Dict[str, str]]:
        return ALERT_SOURCES

    def stats(self) -> Dict[str, Any]:
        sev_dist: Dict[str, int] = {}
        status_dist: Dict[str, int] = {}
        for a in self.alerts.values():
            sev_dist[a.severity] = sev_dist.get(a.severity, 0) + 1
            status_dist[a.status] = status_dist.get(a.status, 0) + 1
        return {
            **self.stats_,
            "total_alerts": len(self.alerts),
            "severity_distribution": sev_dist,
            "status_distribution": status_dist,
            "dedup_window_sec": self.dedup_window_sec,
            "fuzzy_threshold": self.fuzzy_threshold,
            "aggregation_groups": len(self.aggregates),
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_triage: Optional[AlertTriage] = None


def get_alert_triage() -> AlertTriage:
    global _triage
    if _triage is None:
        _triage = AlertTriage()
    return _triage
