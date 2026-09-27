# -*- coding: utf-8 -*-
"""email_threat_intel.py — 邮件威胁情报与 IOC 管理。

覆盖：恶意 URL/哈希/域名/IP 库、BEC 画像库、IOC 导入导出、实时匹配、富化。
全部内存字典，不访问外部情报 API。
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 初始情报数据（演示）
# --------------------------------------------------------------------------- #
SEED_URLS = [
    {"ioc": "http://secure-paypa1.com/login", "type": "phishing",
     "score": 95, "first_seen": "2026-08-01", "source": "internal-hunt"},
    {"ioc": "https://appleid-verify.xyz/signin", "type": "phishing",
     "score": 92, "first_seen": "2026-08-15", "source": "user-report"},
    {"ioc": "http://office365-login-update.xyz/auth", "type": "malware",
     "score": 88, "first_seen": "2026-07-22", "source": "sandbox"},
    {"ioc": "http://c2-emotet-dyn.net/beacon", "type": "c2",
     "score": 97, "first_seen": "2026-06-30", "source": "sandbox"},
    {"ioc": "http://giftcard-scam.top/buy", "type": "scam",
     "score": 80, "first_seen": "2026-09-01", "source": "user-report"},
]

SEED_HASHES = [
    {"md5": "25d55ad283aa400af464c76d713c07ad", "sha256": "a" * 64,
     "family": "Emotet-like", "type": "banker", "first_seen": "2026-06-20",
     "source": "sandbox"},
    {"md5": "5f4dcc3b5aa765d61d8327deb882cf99", "sha256": "b" * 64,
     "family": "DemoPayload", "type": "trojan", "first_seen": "2026-08-11",
     "source": "sandbox"},
    {"md5": "44d88612fea8a8f36de82e1278abb02f", "sha256": "c" * 64,
     "family": "EICAR-Test", "type": "test", "first_seen": "2026-01-01",
     "source": "internal"},
]

SEED_DOMAINS = [
    {"ioc": "paypa1-support.xyz", "type": "phishing-domain",
     "score": 90, "first_seen": "2026-08-02", "asn": "AS14061",
     "country": "US", "registrar": "NameCheap"},
    {"ioc": "office365-auth.top", "type": "phishing-domain",
     "score": 85, "first_seen": "2026-07-19", "asn": "AS16509",
     "country": "US", "registrar": "Amazon"},
    {"ioc": "c2-emotet-dyn.net", "type": "c2",
     "score": 98, "first_seen": "2026-06-15", "asn": "AS9009",
     "country": "DE", "registrar": "DE-Nic"},
]

SEED_IPS = [
    {"ioc": "185.220.101.45", "type": "c2", "score": 96,
     "asn": "AS20473", "country": "DE", "first_seen": "2026-06-15"},
    {"ioc": "103.75.190.22", "type": "phishing-relay", "score": 78,
     "asn": "AS13335", "country": "HK", "first_seen": "2026-08-20"},
]

BEC_PERSONAS = [
    {"persona_id": "BEC-P01", "impersonates": "CEO", "industry": "制造业",
     "tactics": ["urgent wire", "confidential", "after hours"],
     "common_lures": ["并购保密", "紧急付款给律师", "绕过审批"],
     "related_iocs": ["185.220.101.45", "office365-auth.top"]},
    {"persona_id": "BEC-P02", "impersonates": "Supplier", "industry": "贸易",
     "tactics": ["new bank account", "invoice update", "split payment"],
     "common_lures": ["银行账户变更通知", "新发票模板"],
     "related_iocs": ["paypa1-support.xyz"]},
    {"persona_id": "BEC-P03", "impersonates": "HR", "industry": "通用",
     "tactics": ["w2 theft", "payroll update"],
     "common_lures": ["工资单收集", "银行账户更新"],
     "related_iocs": []},
]


class EmailThreatIntel:
    """邮件威胁情报库。"""

    def __init__(self) -> None:
        self.urls: List[Dict[str, Any]] = [dict(x) for x in SEED_URLS]
        self.hashes: List[Dict[str, Any]] = [dict(x) for x in SEED_HASHES]
        self.domains: List[Dict[str, Any]] = [dict(x) for x in SEED_DOMAINS]
        self.ips: List[Dict[str, Any]] = [dict(x) for x in SEED_IPS]
        self.personas: List[Dict[str, Any]] = [dict(x) for x in BEC_PERSONAS]
        self._version = 1

    # ------------------------------------------------------------------ #
    # 列表
    # ------------------------------------------------------------------ #
    def list_iocs(self, ioc_type: Optional[str] = None) -> Dict[str, Any]:
        buckets = {"urls": self.urls, "hashes": self.hashes,
                   "domains": self.domains, "ips": self.ips}
        if ioc_type:
            buckets = {ioc_type: buckets.get(ioc_type, [])}
        return {"iocs": buckets,
                "total": sum(len(v) for v in buckets.values()),
                "version": self._version,
                "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    def list_personas(self) -> List[Dict[str, Any]]:
        return self.personas

    # ------------------------------------------------------------------ #
    # 新增 / 删除
    # ------------------------------------------------------------------ #
    def add_ioc(self, bucket: str, entry: Dict[str, Any]) -> Dict[str, Any]:
        target = {"urls": self.urls, "hashes": self.hashes,
                  "domains": self.domains, "ips": self.ips}.get(bucket)
        if target is None:
            return {"success": False, "error": f"未知 bucket: {bucket}"}
        entry = dict(entry)
        entry.setdefault("first_seen", time.strftime("%Y-%m-%d"))
        entry.setdefault("source", "manual")
        target.append(entry)
        self._version += 1
        return {"success": True, "added": entry, "total": len(target)}

    def remove_ioc(self, bucket: str, value: str) -> bool:
        target = {"urls": self.urls, "hashes": self.hashes,
                  "domains": self.domains, "ips": self.ips}.get(bucket, [])
        before = len(target)
        target[:] = [x for x in target if x.get("ioc") != value
                     and x.get("md5") != value]
        removed = before - len(target)
        if removed:
            self._version += 1
        return bool(removed)

    # ------------------------------------------------------------------ #
    # 实时匹配
    # ------------------------------------------------------------------ #
    def match(self, *, urls: Optional[List[str]] = None,
              hashes: Optional[List[str]] = None,
              domains: Optional[List[str]] = None,
              ips: Optional[List[str]] = None,
              senders: Optional[List[str]] = None) -> Dict[str, Any]:
        hits: List[Dict[str, Any]] = []

        for u in urls or []:
            for rec in self.urls:
                if rec["ioc"] in u or u.endswith(rec["ioc"].split("//")[-1]):
                    hits.append({"ioc": u, "match": rec["ioc"],
                                 "type": rec["type"], "score": rec["score"]})
        for h in hashes or []:
            for rec in self.hashes:
                if rec["md5"] == h or rec["sha256"] == h:
                    hits.append({"ioc": h, "match": rec["md5"],
                                 "type": rec["type"], "score": 90,
                                 "family": rec["family"]})
        for d in domains or []:
            for rec in self.domains:
                if d == rec["ioc"] or d.endswith("." + rec["ioc"]):
                    hits.append({"ioc": d, "match": rec["ioc"],
                                 "type": rec["type"], "score": rec["score"]})
        for ip in ips or []:
            for rec in self.ips:
                if rec["ioc"] == ip:
                    hits.append({"ioc": ip, "match": rec["ioc"],
                                 "type": rec["type"], "score": rec["score"]})
        for s in senders or []:
            dom = s.split("@")[-1].lower() if "@" in s else s.lower()
            for rec in self.domains:
                if dom == rec["ioc"]:
                    hits.append({"ioc": s, "match": rec["ioc"],
                                 "type": "sender-" + rec["type"],
                                 "score": rec["score"]})

        max_score = max([h["score"] for h in hits], default=0)
        return {"matched": bool(hits), "hits": hits,
                "max_score": max_score,
                "verdict": "malicious" if max_score >= 80 else
                           ("suspicious" if max_score >= 50 else "clean"),
                "matched_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    # ------------------------------------------------------------------ #
    # 富化
    # ------------------------------------------------------------------ #
    def enrich(self, value: str, kind: str = "domain") -> Dict[str, Any]:
        v = value.lower()
        seed = int(hashlib.md5(v.encode()).hexdigest()[:8], 16)
        record = next((x for x in self.urls if x["ioc"] == value), None) \
                 or next((x for x in self.domains if x["ioc"] == v), None) \
                 or next((x for x in self.ips if x["ioc"] == v), None)
        return {
            "value": value, "kind": kind,
            "geo": {"country": ["CN", "US", "DE", "HK", "RU"][seed % 5],
                    "city": ["Beijing", "New York", "Frankfurt", "HK", "Moscow"][seed % 5]},
            "asn": f"AS{13000 + seed % 9000}",
            "whois_created_days_ago": 30 + seed % 3000,
            "blacklist_hits": seed % 6,
            "reputation": 20 + seed % 80,
            "known_record": record,
            "enriched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 导入导出
    # ------------------------------------------------------------------ #
    def export(self, fmt: str = "json") -> Dict[str, Any]:
        payload = {
            "version": self._version, "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "urls": self.urls, "hashes": self.hashes, "domains": self.domains,
            "ips": self.ips, "personas": self.personas,
        }
        if fmt == "json":
            return {"format": "json", "data": payload}
        if fmt == "stub":  # STIX 占位
            return {"format": "stix-21", "objects": [
                {"type": "indicator", "pattern": value["ioc"],
                 "valid_from": value["first_seen"]}
                for value in self.urls + self.domains + self.ips
            ]}
        if fmt == "csv":
            rows = ["type,ioc,score,first_seen,source"]
            for b in (self.urls, self.domains, self.ips):
                for x in b:
                    rows.append(f"ioc,{x.get('ioc')},{x.get('score')},"
                                f"{x.get('first_seen')},{x.get('source','')}")
            return {"format": "csv", "csv": "\n".join(rows)}
        return payload

    def import_iocs(self, fmt: str, raw: str) -> Dict[str, Any]:
        added = 0
        try:
            if fmt == "json":
                data = json.loads(raw)
                for k, bucket in (("urls", self.urls), ("domains", self.domains),
                                  ("ips", self.ips)):
                    for item in data.get(k, []):
                        if not any(x.get("ioc") == item.get("ioc") for x in bucket):
                            bucket.append(item); added += 1
            elif fmt == "csv":
                for line in raw.splitlines()[1:]:
                    parts = line.split(",")
                    if len(parts) >= 2 and parts[1]:
                        self.urls.append({"ioc": parts[1], "type": "imported",
                                          "score": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 50,
                                          "first_seen": parts[3] if len(parts) > 3 else "-",
                                          "source": "csv-import"})
                        added += 1
            else:
                return {"success": False, "error": f"不支持格式 {fmt}"}
        except Exception as e:
            return {"success": False, "error": f"导入失败: {e}"}
        self._version += 1
        return {"success": True, "added": added, "version": self._version}
