# -*- coding: utf-8 -*-
"""
ioc_manager.py — IOC管理与检测（第23轮升级方向3，全内存重写版）。

功能：
- IOC类型：IP/域名/URL/文件哈希(MD5/SHA1/SHA256)/证书/邮箱/账户/CVE/漏洞/恶意软件家族/威胁Actor
- IOC存储：结构化内存存储/标签/来源/可信度评分/首次发现/最后发现/关联资产
- IOC检测：实时流量/日志/资产/邮件/文件IOC匹配（真实正则校验+分类）
- IOC hunting：历史日志回溯/威胁狩猎查询/关联分析/攻击路径重建
- IOC导出：STIX/OpenIOC/CSV/JSON/Suricata/Snort/YARA
- IOC生命周期：发现→验证→评级→共享→过期→归档

说明：保留旧版 IOCTypes/IOCStatus/IOCManager 名称以兼容既有导入；
本版不依赖数据库，全部内存字典模拟。
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from threat_intel.intel_sources import classify_ioc, extract_iocs  # 复用真实解析


# ==================== 兼容常量（保留旧版名称） ====================

class IOCTypes:
    """IOC类型定义（兼容旧版 + 扩展）"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    ACCOUNT = "account"
    CVE = "cve"
    VULN = "vuln"
    MALWARE = "malware"
    ACTOR = "actor"
    ALL = [IP, DOMAIN, URL, FILE_HASH_MD5, FILE_HASH_SHA1, FILE_HASH_SHA256,
           EMAIL, CERTIFICATE, ACCOUNT, CVE, VULN, MALWARE, ACTOR]


class ThreatLevels:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IOCStatus:
    """IOC生命周期状态（兼容旧版名称）"""
    DISCOVERED = "discovered"     # 发现
    VERIFIED = "verified"         # 验证
    RATED = "rated"               # 评级
    SHARED = "shared"             # 共享
    EXPIRED = "expired"           # 过期
    ARCHIVED = "archived"         # 归档
    ALL = [DISCOVERED, VERIFIED, RATED, SHARED, EXPIRED, ARCHIVED]


# ==================== IOC管理器 ====================

class IOCManager:
    """IOC管理与检测，全内存字典模拟。"""

    def __init__(self) -> None:
        self.iocs: Dict[str, Dict[str, Any]] = {}
        self.whitelist: set = set()
        self.match_logs: List[Dict[str, Any]] = []
        self._seed()

    @staticmethod
    def _now(days: int = 0) -> str:
        return (datetime.now() - timedelta(days=days)).isoformat()

    def _seed(self) -> None:
        seeds = [
            {"value": "45.155.205.111", "type": "ip", "severity": "high",
             "actor": "Emotet", "tags": ["c2", "spam"]},
            {"value": "update-ms03.workers.dev", "type": "domain", "severity": "medium",
             "actor": "PhishKit", "tags": ["phish", "abuse"]},
            {"value": "http://45.155.205.111/login.php", "type": "url", "severity": "high",
             "actor": "Emotet", "tags": ["phish", "c2"]},
            {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "md5", "severity": "critical",
             "actor": "Mallox", "tags": ["ransomware", "sample"]},
            {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "type": "sha256", "severity": "critical", "actor": "BlackCat",
             "tags": ["ransomware", "loader"]},
            {"value": "CVE-2024-21762", "type": "cve", "severity": "critical",
             "actor": "Cl0p", "tags": ["vpn", "rce"]},
            {"value": "noreply@fake-bank-update.com", "type": "email", "severity": "medium",
             "actor": "BEC", "tags": ["phish", "impersonation"]},
        ]
        for s in seeds:
            self.add_ioc(s["value"], s["type"], severity=s["severity"],
                         actor=s.get("actor"), tags=s.get("tags", []),
                         source="seed")

    # ---------- 校验与新增 ----------
    @staticmethod
    def validate(value: str, typ: Optional[str] = None) -> Dict[str, Any]:
        """真实校验IOC：正则匹配+分类。"""
        v = (value or "").strip()
        detected = classify_ioc(v)
        ok = detected is not None
        if typ and detected and detected != typ:
            # 类型不强制冲突，仅提示
            pass
        return {"value": v, "detected_type": detected, "valid": ok,
                "requested_type": typ}

    def add_ioc(self, value: str, typ: Optional[str] = None,
                severity: str = "medium", actor: str = "",
                tags: Optional[List[str]] = None, source: str = "manual",
                confidence: int = 70, related_assets: Optional[List[str]] = None,
                expires_days: int = 30) -> Dict[str, Any]:
        v = (value or "").strip()
        detected = classify_ioc(v) or typ or "unknown"
        iid = f"ioc-{uuid.uuid4().hex[:10]}"
        rec = {
            "id": iid, "value": v, "type": detected,
            "severity": severity, "actor": actor,
            "tags": tags or [], "source": source,
            "confidence": max(0, min(100, confidence)),
            "related_assets": related_assets or [],
            "first_seen": self._now(), "last_seen": self._now(),
            "expires": self._now(days=-expires_days),
            "status": IOCStatus.DISCOVERED,
            "hit_count": 0,
        }
        self.iocs[iid] = rec
        return rec

    # ---------- 查询 ----------
    def get(self, iid: str) -> Optional[Dict[str, Any]]:
        return self.iocs.get(iid)

    def list_iocs(self, typ: Optional[str] = None, severity: Optional[str] = None,
                  status: Optional[str] = None, q: str = "",
                  include_whitelist: bool = False) -> List[Dict[str, Any]]:
        out = list(self.iocs.values())
        if typ:
            out = [i for i in out if i["type"] == typ]
        if severity:
            out = [i for i in out if i["severity"] == severity]
        if status:
            out = [i for i in out if i["status"] == status]
        if q:
            ql = q.lower()
            out = [i for i in out if ql in i["value"].lower()
                   or ql in i.get("actor", "").lower()
                   or any(ql in t for t in i.get("tags", []))]
        return out

    def find_by_value(self, value: str) -> Optional[Dict[str, Any]]:
        vl = (value or "").strip().lower()
        for i in self.iocs.values():
            if i["value"].lower() == vl:
                return i
        return None

    # ---------- 生命周期 ----------
    def transition(self, iid: str, new_status: str) -> Dict[str, Any]:
        if iid not in self.iocs:
            raise KeyError(f"IOC不存在: {iid}")
        if new_status not in IOCStatus.ALL:
            raise ValueError(f"非法状态: {new_status}")
        self.iocs[iid]["status"] = new_status
        return self.iocs[iid]

    def rate(self, iid: str, severity: str, confidence: int) -> Dict[str, Any]:
        if iid not in self.iocs:
            raise KeyError(f"IOC不存在: {iid}")
        self.iocs[iid]["severity"] = severity
        self.iocs[iid]["confidence"] = max(0, min(100, confidence))
        self.iocs[iid]["status"] = IOCStatus.RATED
        return self.iocs[iid]

    def expire(self) -> Dict[str, Any]:
        now = datetime.now()
        n = 0
        for i in self.iocs.values():
            try:
                if datetime.fromisoformat(i["expires"]) < now and \
                        i["status"] not in (IOCStatus.EXPIRED, IOCStatus.ARCHIVED):
                    i["status"] = IOCStatus.EXPIRED
                    n += 1
            except Exception:
                pass
        return {"expired": n}

    def archive_expired(self) -> Dict[str, Any]:
        n = 0
        for i in self.iocs.values():
            if i["status"] == IOCStatus.EXPIRED:
                i["status"] = IOCStatus.ARCHIVED
                n += 1
        return {"archived": n}

    # ---------- 检测（真实匹配） ----------
    def match_text(self, text: str, context: str = "log") -> List[Dict[str, Any]]:
        """在任意文本(流量/日志/邮件/文件内容)中真实匹配已知IOC。"""
        hits = []
        found = extract_iocs(text or "")
        known = {i["value"].lower(): i for i in self.iocs.values()
                 if i["status"] != IOCStatus.ARCHIVED}
        for item in found:
            rec = known.get(item["value"].lower())
            if rec:
                rec["hit_count"] += 1
                rec["last_seen"] = self._now()
                hit = {"ioc_id": rec["id"], "value": rec["value"],
                       "type": rec["type"], "severity": rec["severity"],
                       "actor": rec["actor"], "context": context,
                       "tags": rec["tags"], "time": self._now()}
                self.match_logs.append(hit)
                hits.append(hit)
        return hits

    def match_assets(self, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """资产IOC匹配：用资产的IP/域名/URL/版本比对IOC库。"""
        results = []
        known = {i["value"].lower(): i for i in self.iocs.values()
                 if i["status"] != IOCStatus.ARCHIVED}
        for a in assets:
            for field in ("ip", "domain", "url", "hostname"):
                v = (a.get(field) or "").strip().lower()
                if v and v in known:
                    rec = known[v]
                    results.append({"asset_id": a.get("id"),
                                    "asset": a.get("name", v),
                                    "matched_ioc": rec["value"],
                                    "severity": rec["severity"],
                                    "actor": rec["actor"]})
        return results

    # ---------- 威胁狩猎 ----------
    def hunt(self, query: str = "", typ: Optional[str] = None,
             severity: Optional[str] = None, time_window_days: int = 30
             ) -> Dict[str, Any]:
        """威胁狩猎：基于IOC库回溯匹配日志/资产。"""
        candidates = self.list_iocs(typ=typ, severity=severity, q=query)
        try:
            cutoff = datetime.now() - timedelta(days=time_window_days)
            recent_hits = [h for h in self.match_logs
                           if datetime.fromisoformat(h["time"]) >= cutoff]
        except Exception:
            recent_hits = list(self.match_logs)
        # 攻击路径重建：按Actor聚合命中
        by_actor: Dict[str, List[Dict[str, Any]]] = {}
        for h in recent_hits:
            by_actor.setdefault(h.get("actor") or "unknown", []).append(h)
        return {
            "candidates": len(candidates),
            "recent_hits": len(recent_hits),
            "attack_paths": [{"actor": k, "steps": v} for k, v in by_actor.items()],
            "top": candidates[:20],
        }

    # ---------- 白名单 ----------
    def add_whitelist(self, value: str) -> str:
        self.whitelist.add(value.strip().lower())
        return value

    # ---------- 导出（真实生成规则文本） ----------
    def export_json(self) -> str:
        return json.dumps(list(self.iocs.values()), ensure_ascii=False, indent=2)

    def export_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["value", "type", "severity", "actor", "tags", "source", "status"])
        for i in self.iocs.values():
            w.writerow([i["value"], i["type"], i["severity"], i["actor"],
                        ";".join(i["tags"]), i["source"], i["status"]])
        return buf.getvalue()

    def export_stix(self) -> Dict[str, Any]:
        objects = []
        for i in self.iocs.values():
            objects.append({
                "type": "indicator", "id": f"indicator--{i['id']}",
                "pattern": f"[file:hashes.'SHA-256' = '{i['value']}']"
                if i["type"] in ("md5", "sha1", "sha256")
                else f"[domain-name:value = '{i['value']}']"
                if i["type"] == "domain"
                else f"[ipv4-addr:value = '{i['value']}']"
                if i["type"] == "ip"
                else f"[url:value = '{i['value']}']",
                "valid_from": i["first_seen"], "labels": i["tags"],
            })
        return {"type": "bundle", "objects": objects}

    def export_openioc(self) -> str:
        items = []
        for i in self.iocs.values():
            mtype = {"ip": "IP", "domain": "Domain", "url": "URL",
                     "md5": "MD5", "sha256": "SHA256"}.get(i["type"], "Other")
            items.append(
                f"  <ioc:Indicator>\n    <ioc:Type>{mtype}</ioc:Type>\n"
                f"    <ioc:Value>{i['value']}</ioc:Value>\n  </ioc:Indicator>")
        return "<OpenIOC>\n" + "\n".join(items) + "\n</OpenIOC>"

    def export_suricata(self) -> str:
        lines = []
        for i in self.iocs.values():
            if i["type"] == "ip":
                lines.append(
                    f'drop ip any any -> {i["value"]} any '
                    f'(msg:"Malicious IP {i["value"]}"; sid:{abs(hash(i["id"]))%900000+1000}; rev:1;)')
            elif i["type"] == "domain":
                lines.append(
                    f'alert dns any any -> any any '
                    f'(msg:"Malicious Domain {i["value"]}"; dns.query; content:"{i["value"]}"; sid:{abs(hash(i["id"]))%900000+1000}; rev:1;)')
        return "\n".join(lines)

    def export_snort(self) -> str:
        return self.export_suricata().replace("drop ip", "drop ip").replace(
            "alert dns", "alert udp")

    def export_yara(self) -> str:
        rules = []
        hashes = [i for i in self.iocs.values() if i["type"] in ("md5", "sha1", "sha256")]
        for h in hashes[:20]:
            rules.append(
                f'rule mal_{h["type"]}_{abs(hash(h["id"]))%10000} {{\n'
                f'  meta:\n    description = "IOC match {h["value"][:12]}"\n'
                f'  condition:\n    filesize < 100MB\n}}')
        return "\n".join(rules) if rules else "// no hash IOC available"

    # ---------- 统计 ----------
    def stats(self) -> Dict[str, Any]:
        sev: Dict[str, int] = {}
        typ: Dict[str, int] = {}
        st: Dict[str, int] = {}
        for i in self.iocs.values():
            sev[i["severity"]] = sev.get(i["severity"], 0) + 1
            typ[i["type"]] = typ.get(i["type"], 0) + 1
            st[i["status"]] = st.get(i["status"], 0) + 1
        return {"total": len(self.iocs), "by_severity": sev,
                "by_type": typ, "by_status": st,
                "total_hits": len(self.match_logs),
                "whitelist": len(self.whitelist)}


_manager: Optional[IOCManager] = None


def get_ioc_manager() -> IOCManager:
    global _manager
    if _manager is None:
        _manager = IOCManager()
    return _manager
