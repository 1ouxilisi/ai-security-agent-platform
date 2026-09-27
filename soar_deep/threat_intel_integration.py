#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar_deep/threat_intel_integration.py — 深度威胁情报联动。

覆盖：
    1. IOC自动匹配：告警IOC自动提取/情报库匹配/匹配结果/可信度评分/历史匹配
    2. 威胁情报自动查询：IP信誉/域名信誉/URL信誉/文件哈希/威胁Actor
    3. 情报驱动响应：高风险IOC自动封禁/恶意域名阻断/恶意文件隔离/Actor监控
    4. 情报自动更新：情报源自动更新/增量同步/版本管理/变更通知/过期清理
    5. 情报共享：内部/联盟/STIX/TAXII/OpenIOC/自定义格式
    6. 情报质量评估：准确率/误报率/覆盖率/时效性/可信度/来源评分
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 情报源定义
# --------------------------------------------------------------------------- #
INTEL_SOURCES: Dict[str, Dict[str, Any]] = {
    "internal_feed": {
        "name": "内部情报库", "type": "internal",
        "format": "json", "update_freq": "realtime",
        "score": 95, "enabled": True,
    },
    "abuse_ch": {
        "name": "Abuse.ch Feeds", "type": "external",
        "format": "misp/stix", "update_freq": "hourly",
        "score": 85, "enabled": True,
    },
    "virustotal": {
        "name": "VirusTotal", "type": "external_api",
        "format": "json", "update_freq": "ondemand",
        "score": 90, "enabled": True,
    },
    "ibm_xforce": {
        "name": "IBM X-Force", "type": "external_api",
        "format": "json", "update_freq": "ondemand",
        "score": 88, "enabled": True,
    },
    "alienvault_otx": {
        "name": "AlienVault OTX", "type": "external",
        "format": "json/stix", "update_freq": "hourly",
        "score": 80, "enabled": True,
    },
    "misp_internal": {
        "name": "内部MISP实例", "type": "internal",
        "format": "misp/stix", "update_freq": "realtime",
        "score": 92, "enabled": True,
    },
}

# IOC类型
IOC_TYPES = ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256",
             "email", "cve", "mutex", "registry_key", "file_name"]


# --------------------------------------------------------------------------- #
# 情报条目
# --------------------------------------------------------------------------- #
class IntelIndicator:
    """单个威胁情报IOC条目。"""

    def __init__(self, ioc_type: str, value: str,
                 severity: str = "medium",
                 source: str = "internal_feed") -> None:
        self.id = f"ioc_{uuid.uuid4().hex[:10]}"
        self.type = ioc_type
        self.value = value
        self.severity = severity
        self.source = source
        self.confidence = 50
        self.tags: List[str] = []
        self.actor = ""
        self.malware_family = ""
        self.first_seen = time.strftime("%Y-%m-%d %H:%M:%S")
        self.last_seen = self.first_seen
        self.expires_at = time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(time.time() + 30 * 86400))
        self.references: List[str] = []
        self.match_count = 0
        self.status = "active"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "type": self.type, "value": self.value,
            "severity": self.severity, "source": self.source,
            "confidence": self.confidence, "tags": self.tags,
            "actor": self.actor, "malware_family": self.malware_family,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "expires_at": self.expires_at,
            "references": self.references,
            "match_count": self.match_count, "status": self.status,
        }


# --------------------------------------------------------------------------- #
# 威胁情报引擎
# --------------------------------------------------------------------------- #
class ThreatIntelEngine:
    """威胁情报联动引擎。"""

    def __init__(self) -> None:
        self.indicators: Dict[str, IntelIndicator] = {}
        self.match_history: List[Dict[str, Any]] = []
        self.update_logs: List[Dict[str, Any]] = []
        self.shared_feeds: Dict[str, List[Dict[str, Any]]] = {}
        self._seed_intel()

    def _seed_intel(self) -> None:
        """预置演示情报。"""
        seeds = [
            ("ip", "45.155.204.10", "critical", "abuse_ch", 95,
             ["c2", "botnet", "emotet"], "Emotet Gang", "Emotet"),
            ("ip", "185.220.101.5", "high", "abuse_ch", 90,
             ["scanner", "tor_exit"], "", ""),
            ("ip", "103.75.190.22", "medium", "alienvault_otx", 65,
             ["proxy", "suspicious"], "", ""),
            ("domain", "fake-hr-update.com", "high", "internal_feed", 88,
             ["phishing", "hr_spoof"], "", ""),
            ("domain", "malware-c2[.]xyz", "critical", "misp_internal", 97,
             ["c2", "ransomware"], "Locky Group", "Locky"),
            ("url", "hxxp://fake-hr-update.com/login", "high", "internal_feed", 85,
             ["phishing", "credential_harvest"], "", ""),
            ("hash_sha256", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
             "critical", "virustotal", 99, ["malware", "ransomware", "locky"],
             "Locky Group", "Locky"),
            ("hash_md5", "d41d8cd98f00b204e9800998ecf8427e", "high", "virustotal", 92,
             ["trojan", "agenttesla"], "", "AgentTesla"),
        ]
        for ioc_type, value, sev, src, conf, tags, actor, malware in seeds:
            ind = IntelIndicator(ioc_type, value, sev, src)
            ind.confidence = conf
            ind.tags = tags
            ind.actor = actor
            ind.malware_family = malware
            self.indicators[ind.id] = ind

    # ---- 1. IOC自动匹配 ----
    def match_ioc(self, ioc_type: str, value: str,
                  context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """匹配单个IOC到情报库。"""
        results = []
        for ind in self.indicators.values():
            if ind.type != ioc_type or ind.status != "active":
                continue
            if ind.value == value or value in ind.value or ind.value in value:
                results.append(ind.to_dict())
                ind.match_count += 1
                ind.last_seen = time.strftime("%Y-%m-%d %H:%M:%S")

        match_entry = {
            "ioc_type": ioc_type, "value": value,
            "matched_count": len(results),
            "matched": results,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "context": context or {},
        }
        self.match_history.append(match_entry)
        return match_entry

    def match_alerts_iocs(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量提取告警中的IOC并匹配。"""
        extracted = []
        for alert in alerts:
            for field in ("src_ip", "dst_ip"):
                if alert.get(field):
                    r = self.match_ioc("ip", alert[field], {"alert_id": alert.get("id")})
                    extracted.append({"field": field, **r})
            if alert.get("description"):
                # 简单提取URL
                import re
                urls = re.findall(r'https?://[^\s<>"\']+', alert["description"])
                for url in urls:
                    r = self.match_ioc("url", url, {"alert_id": alert.get("id")})
                    extracted.append({"field": "url_extracted", **r})
        return {
            "total_extracted": len(extracted),
            "matches": extracted,
        }

    # ---- 2. 情报查询 ----
    def query_ip(self, ip: str) -> Dict[str, Any]:
        """查询IP信誉。"""
        matches = [ind.to_dict() for ind in self.indicators.values()
                   if ind.type == "ip" and (ind.value == ip or ip in ind.value)]
        # 综合信誉分
        if matches:
            worst = max(matches, key=lambda x: x["confidence"])
            reputation = "malicious" if worst["confidence"] >= 80 else "suspicious"
        else:
            reputation = "clean"
            worst = {}
        return {
            "ip": ip, "reputation": reputation,
            "confidence": worst.get("confidence", 0),
            "matches": matches,
            "queried_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def query_domain(self, domain: str) -> Dict[str, Any]:
        matches = [ind.to_dict() for ind in self.indicators.values()
                   if ind.type == "domain" and (ind.value == domain or domain in ind.value)]
        reputation = "malicious" if matches and matches[0]["confidence"] >= 80 else (
                     "suspicious" if matches else "clean")
        return {"domain": domain, "reputation": reputation,
                "matches": matches,
                "queried_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    def query_url(self, url: str) -> Dict[str, Any]:
        matches = [ind.to_dict() for ind in self.indicators.values()
                   if ind.type == "url" and ind.value in url]
        reputation = "malicious" if matches else "clean"
        return {"url": url, "reputation": reputation, "matches": matches,
                "queried_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    def query_hash(self, file_hash: str) -> Dict[str, Any]:
        matches = [ind.to_dict() for ind in self.indicators.values()
                   if ind.type.startswith("hash") and ind.value == file_hash]
        reputation = "malicious" if matches else "unknown"
        return {"hash": file_hash, "reputation": reputation, "matches": matches,
                "queried_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    def list_threat_actors(self) -> List[Dict[str, Any]]:
        actors: Dict[str, Dict[str, Any]] = {}
        for ind in self.indicators.values():
            if ind.actor:
                if ind.actor not in actors:
                    actors[ind.actor] = {"name": ind.actor, "ioc_count": 0,
                                         "malware_families": set(),
                                         "severity": ind.severity}
                actors[ind.actor]["ioc_count"] += 1
                if ind.malware_family:
                    actors[ind.actor]["malware_families"].add(ind.malware_family)
        result = []
        for a in actors.values():
            a["malware_families"] = list(a["malware_families"])
            result.append(a)
        return result

    # ---- 3. 情报驱动响应 ----
    def get_high_risk_iocs(self, min_severity: str = "high") -> List[Dict[str, Any]]:
        sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_level = sev_order.get(min_severity, 2)
        return [ind.to_dict() for ind in self.indicators.values()
                if ind.status == "active"
                and sev_order.get(ind.severity, 0) >= min_level]

    # ---- 4. 情报更新 ----
    def update_source(self, source_id: str) -> Dict[str, Any]:
        """模拟情报源增量更新。"""
        src = INTEL_SOURCES.get(source_id)
        if not src:
            return {"error": "情报源不存在"}
        log_entry = {
            "source": source_id, "source_name": src["name"],
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "indicators_added": 0, "indicators_updated": 0,
            "status": "success",
        }
        self.update_logs.append(log_entry)
        return log_entry

    def cleanup_expired(self) -> Dict[str, int]:
        """清理过期情报。"""
        now = time.time()
        expired = []
        for ind in self.indicators.values():
            try:
                exp_ts = time.mktime(time.strptime(ind.expires_at, "%Y-%m-%d %H:%M:%S"))
                if now > exp_ts:
                    ind.status = "expired"
                    expired.append(ind.id)
            except Exception:
                pass
        return {"expired_count": len(expired), "expired_ids": expired}

    # ---- 5. 情报共享 ----
    def export_stix(self, ioc_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """导出为STIX格式（模拟）。"""
        items = [ind.to_dict() for ind in self.indicators.values()
                 if ind.status == "active"]
        if ioc_ids:
            items = [i for i in items if i["id"] in ioc_ids]
        return {
            "format": "STIX 2.1",
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "count": len(items),
            "indicators": items,
        }

    def export_openioc(self, ioc_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        items = [ind.to_dict() for ind in self.indicators.values()
                 if ind.status == "active"]
        if ioc_ids:
            items = [i for i in items if i["id"] in ioc_ids]
        return {
            "format": "OpenIOC",
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "count": len(items),
            "indicators": items,
        }

    def share_to_feed(self, feed_name: str,
                      ioc_ids: List[str]) -> Dict[str, Any]:
        """共享情报到联盟feed。"""
        items = [self.indicators[i].to_dict() for i in ioc_ids if i in self.indicators]
        self.shared_feeds[feed_name] = items
        return {
            "feed": feed_name, "shared_count": len(items),
            "shared_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---- 6. 质量评估 ----
    def quality_report(self) -> Dict[str, Any]:
        total = len(self.indicators)
        active = sum(1 for i in self.indicators.values() if i.status == "active")
        expired = sum(1 for i in self.indicators.values() if i.status == "expired")
        avg_confidence = round(
            sum(i.confidence for i in self.indicators.values()) / max(1, total), 1)
        # 来源评分
        source_scores: Dict[str, Dict[str, Any]] = {}
        for ind in self.indicators.values():
            s = source_scores.setdefault(ind.source, {"count": 0, "total_conf": 0})
            s["count"] += 1
            s["total_conf"] += ind.confidence
        for s in source_scores.values():
            s["avg_confidence"] = round(s["total_conf"] / max(1, s["count"]), 1)
            del s["total_conf"]

        return {
            "total_indicators": total,
            "active": active,
            "expired": expired,
            "avg_confidence": avg_confidence,
            "match_history_count": len(self.match_history),
            "sources": source_scores,
            "shared_feeds": list(self.shared_feeds.keys()),
            "update_logs_count": len(self.update_logs),
        }

    # ---- 查询 ----
    def list_indicators(self, ioc_type: Optional[str] = None,
                        severity: Optional[str] = None,
                        status: str = "active") -> List[Dict[str, Any]]:
        items = list(self.indicators.values())
        if ioc_type:
            items = [i for i in items if i.type == ioc_type]
        if severity:
            items = [i for i in items if i.severity == severity]
        if status:
            items = [i for i in items if i.status == status]
        return [i.to_dict() for i in items]

    def list_sources(self) -> Dict[str, Dict[str, Any]]:
        return INTEL_SOURCES

    def list_ioc_types(self) -> List[str]:
        return IOC_TYPES


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_intel: Optional[ThreatIntelEngine] = None


def get_threat_intel() -> ThreatIntelEngine:
    global _intel
    if _intel is None:
        _intel = ThreatIntelEngine()
    return _intel
