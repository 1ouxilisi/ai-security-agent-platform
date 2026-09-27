# -*- coding: utf-8 -*-
"""
ioc_enrichment.py — IOC关联与富化。

提供IOC管理、自动富化、关联分析、导入导出和评分五大子系统。

设计定位：仅用于经过授权的威胁情报关联与防御性分析。
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# IOC管理
# --------------------------------------------------------------------------- #
class IOCManager:
    """IOC管理器。"""

    IOC_TYPES = {"ip", "domain", "url", "hash", "certificate", "email", "file"}
    IOC_STATUS = {"active", "expired", "false_positive", "archived"}

    def __init__(self) -> None:
        self._iocs: Dict[str, Dict[str, Any]] = {}
        self._seed_default_iocs()

    def _seed_default_iocs(self) -> None:
        """预置默认IOC。"""
        defaults = [
            {"value": "45.132.9.87", "ioc_type": "ip", "classification": "c2_server",
             "tags": ["c2", "apt", "rus"], "source": "internal_hunt"},
            {"value": "185.220.101.45", "ioc_type": "ip", "classification": "proxy",
             "tags": ["proxy", "tor"], "source": "internal_hunt"},
            {"value": "evil-c2[.]com", "ioc_type": "domain", "classification": "c2_domain",
             "tags": ["c2", "ddns"], "source": "internal_hunt"},
            {"value": "a1b2c3d4e5f67890", "ioc_type": "hash", "classification": "malware_sample",
             "tags": ["ransomware", "payload"], "source": "internal_hunt"},
            {"value": "attacker@evil-mail[.]com", "ioc_type": "email", "classification": "phish_sender",
             "tags": ["phishing"], "source": "email_gateway"},
        ]
        for d in defaults:
            self.add_ioc(**d)

    def add_ioc(self, value: str, ioc_type: str, classification: str = "unknown",
                tags: List[str] = None, source: str = "manual",
                confidence: float = 0.8) -> Dict[str, Any]:
        """添加IOC。"""
        iid = uuid.uuid4().hex[:12]
        entry = {
            "ioc_id": iid,
            "value": value,
            "ioc_type": ioc_type if ioc_type in self.IOC_TYPES else "unknown",
            "classification": classification,
            "tags": tags or [],
            "source": source,
            "confidence": confidence,
            "status": "active",
            "first_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
            "occurrence_count": 1,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._iocs[iid] = entry
        return entry

    def update_ioc(self, ioc_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        ioc = self._iocs.get(ioc_id)
        if not ioc:
            return None
        for k, v in kwargs.items():
            if k in ioc:
                ioc[k] = v
        return ioc

    def list_iocs(self, ioc_type: Optional[str] = None,
                  status: Optional[str] = None,
                  classification: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self._iocs.values())
        if ioc_type:
            items = [i for i in items if i["ioc_type"] == ioc_type]
        if status:
            items = [i for i in items if i["status"] == status]
        if classification:
            items = [i for i in items if i["classification"] == classification]
        return items

    def get_ioc(self, ioc_id: str) -> Optional[Dict[str, Any]]:
        return self._iocs.get(ioc_id)

    def search_iocs(self, query: str) -> List[Dict[str, Any]]:
        """按值搜索IOC。"""
        q = query.lower()
        return [i for i in self._iocs.values() if q in i["value"].lower()]


# --------------------------------------------------------------------------- #
# IOC自动富化
# --------------------------------------------------------------------------- #
class IOCEnricher:
    """IOC自动富化器（模拟）。"""

    def __init__(self) -> None:
        self._geo_db: Dict[str, Dict[str, str]] = {
            "45.132.9.87": {"country": "Russia", "city": "Moscow", "asn": "AS12345", "isp": "Bulletproof Hosting"},
            "185.220.101.45": {"country": "Netherlands", "city": "Amsterdam", "asn": "AS51852", "isp": "Tor Exit Node"},
            "104.244.74.15": {"country": "United States", "city": "San Francisco", "asn": "AS13335", "isp": "Cloudflare"},
        }
        self._blacklist: set = {"45.132.9.87", "185.220.101.45"}

    def enrich(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """富化单个IOC，返回富化详情。"""
        value = ioc.get("value", "")
        ioc_type = ioc.get("ioc_type", "")
        enrichment: Dict[str, Any] = {
            "ioc_id": ioc.get("ioc_id"),
            "value": value,
            "enriched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        if ioc_type == "ip":
            geo = self._geo_db.get(value, {"country": "Unknown", "city": "Unknown", "asn": "Unknown", "isp": "Unknown"})
            enrichment["geolocation"] = geo
            enrichment["asn"] = geo.get("asn", "Unknown")
            enrichment["blacklisted"] = value in self._blacklist
            enrichment["reputation_score"] = 95 if value in self._blacklist else 20

        elif ioc_type == "domain":
            enrichment["whois"] = {"registrar": "Unknown Registrar", "creation_date": "2025-01-01",
                                    "expires": "2027-01-01", "registrant": "Private"}
            enrichment["historical_resolutions"] = ["45.132.9.87", "185.220.101.45"]
            enrichment["reputation_score"] = 85 if "evil" in value else 30

        elif ioc_type == "hash":
            enrichment["virus_total_like"] = {"detections": 42, "total_engines": 60,
                                               "family": "Emotet-like", "first_seen": "2026-08-01"}
            enrichment["reputation_score"] = 90

        elif ioc_type == "url":
            enrichment["url_analysis"] = {"scheme": "hxxp", "is_phishing": True,
                                           "suspicious_path": "/login/verify"}
            enrichment["reputation_score"] = 80

        elif ioc_type == "email":
            enrichment["email_rep"] = {"domain_reputation": "poor",
                                        "spam_score": 85, "is_disposable": False}
            enrichment["reputation_score"] = 75

        else:
            enrichment["reputation_score"] = 50

        return enrichment


# --------------------------------------------------------------------------- #
# IOC关联分析
# --------------------------------------------------------------------------- #
class IOCRelationAnalyzer:
    """IOC关系图谱分析器。"""

    def __init__(self, ioc_manager: Optional[IOCManager] = None) -> None:
        self._manager = ioc_manager or IOCManager()

    def build_graph(self) -> Dict[str, Any]:
        """构建IOC关系图谱。"""
        iocs = self._manager.list_iocs()
        nodes = []
        edges = []

        for ioc in iocs:
            nodes.append({
                "id": ioc["ioc_id"],
                "label": ioc["value"],
                "type": ioc["ioc_type"],
                "classification": ioc["classification"],
            })

        # 模拟关联关系
        # 同一个威胁情报源的IOC之间建立关联
        sources: Dict[str, List[str]] = {}
        for ioc in iocs:
            src = ioc.get("source", "unknown")
            sources.setdefault(src, []).append(ioc["ioc_id"])

        for src, ids in sources.items():
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    edges.append({
                        "source": ids[i],
                        "target": ids[j],
                        "relation": f"common_source:{src}",
                    })

        return {
            "nodes": nodes,
            "edges": edges,
            "clusters": self._detect_clusters(nodes, edges),
            "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _detect_clusters(self, nodes: List[Dict], edges: List[Dict]) -> List[Dict[str, Any]]:
        """检测攻击集群。"""
        # 简化：按classification聚类
        clusters: Dict[str, List[str]] = {}
        for n in nodes:
            cls = n.get("classification", "unknown")
            clusters.setdefault(cls, []).append(n["id"])
        return [
            {"cluster_id": f"cluster_{i+1}", "classification": cls,
             "ioc_count": len(ids), "ioc_ids": ids}
            for i, (cls, ids) in enumerate(clusters.items())
        ]


# --------------------------------------------------------------------------- #
# IOC导入导出
# --------------------------------------------------------------------------- #
class IOCImportExport:
    """IOC导入导出器。"""

    def __init__(self, ioc_manager: Optional[IOCManager] = None) -> None:
        self._manager = ioc_manager or IOCManager()

    def export(self, fmt: str = "json") -> str:
        """导出IOC到指定格式。"""
        iocs = self._manager.list_iocs()
        if fmt == "json":
            return json.dumps(iocs, ensure_ascii=False, indent=2)
        elif fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["value", "type", "classification", "tags", "source", "status"])
            for ioc in iocs:
                writer.writerow([ioc["value"], ioc["ioc_type"], ioc["classification"],
                                 ";".join(ioc["tags"]), ioc["source"], ioc["status"]])
            return output.getvalue()
        elif fmt == "stix":
            # 模拟STIX格式
            stix = {
                "type": "bundle", "id": "bundle--" + uuid.uuid4().hex,
                "objects": [
                    {"type": "indicator", "pattern": f"[ipv4-addr:value = '{i['value']}']",
                     "valid_from": i["first_seen"]}
                    for i in iocs if i["ioc_type"] == "ip"
                ],
            }
            return json.dumps(stix, ensure_ascii=False, indent=2)
        elif fmt == "openioc":
            return f"<?xml version='1.0'?><OpenIOC><ioc><definition>{len(iocs)} IOCs</definition></ioc></OpenIOC>"
        return json.dumps(iocs, ensure_ascii=False)

    def import_data(self, data: str, fmt: str = "json") -> Dict[str, Any]:
        """从数据导入IOC。"""
        count = 0
        errors: List[str] = []
        try:
            if fmt == "json":
                items = json.loads(data)
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict) and item.get("value"):
                            self._manager.add_ioc(
                                value=item["value"],
                                ioc_type=item.get("ioc_type", "unknown"),
                                classification=item.get("classification", "imported"),
                                source="import_json",
                            )
                            count += 1
            elif fmt == "csv":
                reader = csv.DictReader(io.StringIO(data))
                for row in reader:
                    if row.get("value"):
                        self._manager.add_ioc(
                            value=row["value"],
                            ioc_type=row.get("type", "unknown"),
                            classification=row.get("classification", "imported"),
                            source="import_csv",
                        )
                        count += 1
        except Exception as e:
            errors.append(str(e))
        return {"imported": count, "errors": errors, "format": fmt}


# --------------------------------------------------------------------------- #
# IOC评分
# --------------------------------------------------------------------------- #
class IOCScorer:
    """IOC威胁评分器。"""

    def __init__(self, enricher: Optional[IOCEnricher] = None) -> None:
        self._enricher = enricher or IOCEnricher()

    def score(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """对单个IOC进行综合评分。"""
        enrichment = self._enricher.enrich(ioc)
        rep = enrichment.get("reputation_score", 50)

        # 综合评分 = 信誉 * 0.4 + 置信度 * 0.3 + 出现次数权重 * 0.3
        confidence = ioc.get("confidence", 0.5)
        occurrence_bonus = min(30, ioc.get("occurrence_count", 1) * 2)

        threat_score = int(rep * 0.4 + confidence * 100 * 0.3 + occurrence_bonus * 0.3)
        threat_score = min(100, threat_score)

        return {
            "ioc_id": ioc.get("ioc_id"),
            "value": ioc.get("value"),
            "threat_score": threat_score,
            "threat_level": self._level(threat_score),
            "confidence": confidence,
            "first_seen": ioc.get("first_seen"),
            "last_seen": ioc.get("last_seen"),
            "occurrence_count": ioc.get("occurrence_count", 1),
            "data_sources": [ioc.get("source", "manual")],
            "enrichment": enrichment,
        }

    def _level(self, score: int) -> str:
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        return "informational"
