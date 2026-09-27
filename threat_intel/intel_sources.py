# -*- coding: utf-8 -*-
"""
intel_sources.py — 威胁情报源接入与标准化管理（第23轮升级方向3）。

功能：
- 开源情报源：CVE / NVD / CNVD / CNNVD / Exploit-DB / Metasploit模块库 / Shodan / Censys / Fofa
- 商业情报源：支持API接入的商业威胁情报平台 / 漏洞情报 / IOC情报 / 威胁Actor情报
- 社区情报源：GitHub安全公告 / 安全博客 / 安全论坛 / 推特 / 电报 / 暗网论坛
- 自定义情报源：用户自定义情报源 / CSV / JSON / STIX / TAXII导入 / API推送
- 情报标准化：多源格式标准化 / 去重 / 关联 / 融合 / 质量评分 / 可信度评估
- 情报更新管理：定时拉取 / 增量更新 / 版本管理 / 变更通知 / 过期清理 / 归档

说明：第三方库(requests等)用 try-import，缺失时回退模拟数据。
本模块全部内存字典模拟，不建数据库表。仅用于授权安全运营。
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    import requests  # type: ignore
    _REQUESTS_OK = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _REQUESTS_OK = False


# ==================== 情报源目录（种子数据） ====================

OPEN_SOURCES: List[Dict[str, Any]] = [
    {"id": "cve", "name": "CVE Mitre", "category": "开源", "type": "vuln",
     "api_supported": True, "format": "CVE/JSON", "credibility": 95,
     "url": "https://cve.mitre.org/", "note": "通用漏洞披露官方编号源"},
    {"id": "nvd", "name": "NVD 美国国家漏洞库", "category": "开源", "type": "vuln",
     "api_supported": True, "format": "JSON/CVE 2.0", "credibility": 92,
     "url": "https://nvd.nist.gov/", "note": "CVSS评分/CPE映射/在野利用标记(KEV)"},
    {"id": "cnvd", "name": "CNVD 国家信息安全漏洞共享平台", "category": "开源", "type": "vuln",
     "api_supported": False, "format": "HTML/JSON", "credibility": 90,
     "url": "https://www.cnvd.org.cn/", "note": "国内官方漏洞共享平台"},
    {"id": "cnnvd", "name": "CNNVD 国家信息安全漏洞库", "category": "开源", "type": "vuln",
     "api_supported": False, "format": "HTML", "credibility": 90,
     "url": "https://www.cnnvd.org.cn/", "note": "中国信息安全测评中心漏洞库"},
    {"id": "exploitdb", "name": "Exploit-DB", "category": "开源", "type": "exploit",
     "api_supported": True, "format": "Git/CSV", "credibility": 88,
     "url": "https://www.exploit-db.com/", "note": "公开EXP/POC代码库(Offensive Security)"},
    {"id": "metasploit", "name": "Metasploit 模块库", "category": "开源", "type": "exploit",
     "api_supported": False, "format": "Ruby", "credibility": 90,
     "url": "https://www.metasploit.com/", "note": "集成EXP模块/载荷/辅助扫描"},
    {"id": "shodan", "name": "Shodan", "category": "开源", "type": "asset",
     "api_supported": True, "format": "JSON", "credibility": 85,
     "url": "https://www.shodan.io/", "note": "全网设备/服务/暴露资产搜索"},
    {"id": "censys", "name": "Censys", "category": "开源", "type": "asset",
     "api_supported": True, "format": "JSON", "credibility": 85,
     "url": "https://search.censys.io/", "note": "证书/主机/网站测绘"},
    {"id": "fofa", "name": "Fofa 网络空间测绘", "category": "开源", "type": "asset",
     "api_supported": True, "format": "JSON", "credibility": 84,
     "url": "https://fofa.info/", "note": "国内网络空间资产搜索引擎"},
]

COMMERCIAL_SOURCES: List[Dict[str, Any]] = [
    {"id": "floss", "name": "Floss 威胁情报平台", "category": "商业", "type": "ioc",
     "api_supported": True, "format": "STIX/JSON", "credibility": 92,
     "vendor": "商业TIP厂商", "note": "IOC富集/归因/在野利用追踪"},
    {"id": "recorded_future", "name": "Recorded Future", "category": "商业", "type": "actor",
     "api_supported": True, "format": "JSON", "credibility": 93,
     "vendor": "Refinitiv", "note": "威胁Actor/行业威胁/预测情报"},
    {"id": "alienvault_otx", "name": "AlienVault OTX", "category": "商业", "type": "ioc",
     "api_supported": True, "format": "STIX/JSON", "credibility": 86,
     "vendor": "AT&T", "note": "开放威胁交换社区脉冲"},
    {"id": "virustotal", "name": "VirusTotal", "category": "商业", "type": "hash",
     "api_supported": True, "format": "JSON", "credibility": 88,
     "vendor": "Google", "note": "文件哈希/URL/域名多引擎检测"},
    {"id": "ibm_xforce", "name": "IBM X-Force", "category": "商业", "type": "vuln",
     "api_supported": True, "format": "JSON", "credibility": 89,
     "vendor": "IBM", "note": "漏洞评分/IP信誉/恶意活动"},
    {"id": "微步在线", "name": "微步在线威胁情报", "category": "商业", "type": "ioc",
     "api_supported": True, "format": "JSON", "credibility": 88,
     "vendor": "国内厂商", "note": "国内IOC/攻击组织/事件情报"},
]

COMMUNITY_SOURCES: List[Dict[str, Any]] = [
    {"id": "github_advisories", "name": "GitHub Security Advisories", "category": "社区", "type": "vuln",
     "api_supported": True, "format": "GitHub Advisory JSON", "credibility": 87,
     "url": "https://github.com/advisories", "note": "开源供应链漏洞公告/GHSA"},
    {"id": "krebs", "name": "Krebs on Security", "category": "社区", "type": "blog",
     "api_supported": False, "format": "RSS/HTML", "credibility": 80,
     "url": "https://krebsonsecurity.com/", "note": "知名安全调查记者博客"},
    {"id": "sks_blogs", "name": "Security Blogs 聚合", "category": "社区", "type": "blog",
     "api_supported": False, "format": "RSS", "credibility": 75,
     "url": "https://www.therecord.media/", "note": "安全媒体/厂商博客聚合"},
    {"id": "twitter_sectw", "name": "Twitter 安全圈(#SecTwitter)", "category": "社区", "type": "social",
     "api_supported": True, "format": "API", "credibility": 70,
     "url": "https://twitter.com/", "note": "安全研究员实时披露(噪声较大)"},
    {"id": "telegram_certs", "name": "Telegram 安全频道", "category": "社区", "type": "social",
     "api_supported": True, "format": "MTProto", "credibility": 68,
     "url": "https://telegram.org/", "note": "PoC/数据泄露快速传播频道"},
    {"id": "darkweb_forums", "name": "暗网犯罪论坛", "category": "社区", "type": "darkweb",
     "api_supported": False, "format": ".onion", "credibility": 60,
     "url": "http://*.onion/", "note": "仅做防御性监测,不参与非法交易"},
]


# ==================== 情报标准化 ====================

# IOC 提取正则（真实可用）
_RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
_RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def classify_ioc(value: str) -> Optional[str]:
    """根据字符串真实判断IOC类型，返回类型名或None。"""
    v = value.strip()
    if not v:
        return None
    if _RE_IPV4.fullmatch(v):
        return "ip"
    if _RE_URL.fullmatch(v):
        return "url"
    if _RE_EMAIL.fullmatch(v):
        return "email"
    if _RE_CVE.fullmatch(v):
        return "cve"
    if _RE_SHA256.fullmatch(v):
        return "sha256"
    if _RE_SHA1.fullmatch(v):
        return "sha1"
    if _RE_MD5.fullmatch(v):
        return "md5"
    if _RE_DOMAIN.fullmatch(v):
        return "domain"
    return None


def extract_iocs(text: str) -> List[Dict[str, str]]:
    """从任意文本中真实提取并分类IOC。"""
    found: List[Dict[str, str]] = []
    seen = set()
    patterns = [
        ("cve", _RE_CVE), ("url", _RE_URL), ("ip", _RE_IPV4),
        ("email", _RE_EMAIL), ("sha256", _RE_SHA256),
        ("sha1", _RE_SHA1), ("md5", _RE_MD5), ("domain", _RE_DOMAIN),
    ]
    for typ, pat in patterns:
        for m in pat.findall(text or ""):
            key = (typ, m.lower())
            if key in seen:
                continue
            seen.add(key)
            found.append({"type": typ, "value": m})
    return found


# ==================== 情报源管理 ====================

class IntelSourceManager:
    """威胁情报源接入、标准化、更新管理。全部内存字典模拟。"""

    def __init__(self) -> None:
        self.sources: Dict[str, Dict[str, Any]] = {}
        self.feeds: Dict[str, Dict[str, Any]] = {}       # 标准化后的情报条目
        self.change_log: List[Dict[str, Any]] = []
        self.versions: Dict[str, int] = {}
        self._seed()

    # ---------- 初始化种子 ----------
    def _seed(self) -> None:
        for grp, items in [("open", OPEN_SOURCES), ("commercial", COMMERCIAL_SOURCES),
                           ("community", COMMUNITY_SOURCES)]:
            for it in items:
                sid = it["id"]
                self.sources[sid] = {
                    **it, "group": grp,
                    "enabled": True, "configured": bool(it.get("api_supported")),
                    "last_pull": None, "next_pull": None, "pull_interval": 3600,
                    "items_count": 0, "status": "active",
                }
        # 种子情报条目（标准化格式）
        seed_feeds = [
            {"id": "f-0001", "type": "vuln", "ioc": "CVE-2024-21762",
             "title": "Fortinet SSL VPN 越界写入", "source": "nvd", "severity": "critical",
             "confidence": 95, "in_the_wild": True, "tags": ["vpn", "fortinet", "rce"]},
            {"id": "f-0002", "type": "ioc", "ioc": "45.155.205.111",
             "title": "已知C2通信IP", "source": "floss", "severity": "high",
             "confidence": 88, "in_the_wild": True, "tags": ["c2", "rat"]},
            {"id": "f-0003", "type": "ioc", "ioc": "update-ms03[.]workers[.]dev",
             "title": "钓鱼域名", "source": "twitter_sectw", "severity": "medium",
             "confidence": 65, "in_the_wild": False, "tags": ["phish"]},
            {"id": "f-0004", "type": "actor", "ioc": "APT41",
             "title": "攻击组织APT41", "source": "recorded_future", "severity": "high",
             "confidence": 92, "in_the_wild": True, "tags": ["china", "espionage", "doubleext"]},
            {"id": "f-0005", "type": "vuln", "ioc": "CVE-2023-46604",
             "title": "Apache ActiveMQ OpenWire RCE", "source": "exploitdb",
             "severity": "critical", "confidence": 90, "in_the_wild": True,
             "tags": ["activemq", "rce", "exploit_available"]},
        ]
        for f in seed_feeds:
            self.feeds[f["id"]] = {
                **f, "first_seen": self._now_iso(days=30),
                "last_seen": self._now_iso(), "expires": self._now_iso(days=30),
                "hash": self._hash(f["ioc"]), "status": "active",
            }

    @staticmethod
    def _now_iso(days: int = 0) -> str:
        return (datetime.now() - timedelta(days=days)).isoformat()

    @staticmethod
    def _hash(s: str) -> str:
        import hashlib
        return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:16]

    # ---------- 源管理 ----------
    def list_sources(self, group: Optional[str] = None,
                     only_enabled: bool = False) -> List[Dict[str, Any]]:
        out = list(self.sources.values())
        if group:
            out = [s for s in out if s.get("group") == group]
        if only_enabled:
            out = [s for s in out if s.get("enabled")]
        return out

    def get_source(self, sid: str) -> Optional[Dict[str, Any]]:
        return self.sources.get(sid)

    def enable_source(self, sid: str, enabled: bool = True) -> Dict[str, Any]:
        if sid not in self.sources:
            raise KeyError(f"情报源不存在: {sid}")
        self.sources[sid]["enabled"] = enabled
        return self.sources[sid]

    def configure_source(self, sid: str, config: Dict[str, Any]) -> Dict[str, Any]:
        if sid not in self.sources:
            raise KeyError(f"情报源不存在: {sid}")
        self.sources[sid].setdefault("config", {}).update(config or {})
        self.sources[sid]["configured"] = True
        return self.sources[sid]

    def add_custom_source(self, name: str, url: str = "", fmt: str = "json",
                          note: str = "") -> Dict[str, Any]:
        sid = f"custom-{uuid.uuid4().hex[:8]}"
        self.sources[sid] = {
            "id": sid, "name": name, "category": "自定义", "group": "custom",
            "type": "custom", "api_supported": True, "format": fmt,
            "credibility": 70, "url": url, "note": note,
            "enabled": True, "configured": True, "last_pull": None,
            "next_pull": None, "pull_interval": 3600, "items_count": 0,
            "status": "active",
        }
        return self.sources[sid]

    # ---------- 标准化 / 去重 / 融合 ----------
    def normalize_feed(self, raw: Dict[str, Any], source: str) -> Dict[str, Any]:
        """将多源原始情报标准化为统一格式。"""
        value = str(raw.get("ioc") or raw.get("value") or raw.get("indicator") or "").strip()
        typ = classify_ioc(value) or raw.get("type") or "unknown"
        conf = int(raw.get("confidence") or raw.get("score") or self.sources.get(
            source, {}).get("credibility", 70))
        conf = max(0, min(100, conf))
        return {
            "id": raw.get("id") or f"f-{uuid.uuid4().hex[:8]}",
            "type": typ, "ioc": value,
            "title": raw.get("title") or raw.get("name") or value,
            "source": source,
            "severity": raw.get("severity", "medium"),
            "confidence": conf,
            "in_the_wild": bool(raw.get("in_the_wild", False)),
            "tags": list(raw.get("tags", [])),
            "first_seen": raw.get("first_seen") or self._now_iso(),
            "last_seen": self._now_iso(),
            "expires": raw.get("expires") or self._now_iso(days=-30),
            "hash": self._hash(value),
            "status": "active",
        }

    def ingest(self, raw: Dict[str, Any], source: str = "custom") -> Dict[str, Any]:
        """摄入一条情报，自动去重+融合+质量评分。"""
        norm = self.normalize_feed(raw, source)
        h = norm["hash"]
        # 去重：按ioc值查重
        duplicate = None
        for fid, f in self.feeds.items():
            if f["ioc"].lower() == norm["ioc"].lower():
                duplicate = fid
                break
        if duplicate:
            old = self.feeds[duplicate]
            old["sources"] = list(set(old.get("sources", [old["source"]]) + [source]))
            old["confidence"] = max(old["confidence"], norm["confidence"])
            old["last_seen"] = norm["last_seen"]
            old["in_the_wild"] = old["in_the_wild"] or norm["in_the_wild"]
            old["tags"] = list(set(old["tags"] + norm["tags"]))
            self.change_log.append({"time": self._now_iso(), "type": "merge",
                                   "id": duplicate, "source": source})
            return old
        self.feeds[norm["id"]] = norm
        self.change_log.append({"time": self._now_iso(), "type": "new",
                                "id": norm["id"], "source": source})
        self.versions[source] = self.versions.get(source, 0) + 1
        return norm

    def ingest_text(self, text: str, source: str = "custom") -> List[Dict[str, Any]]:
        """从文本中批量提取IOC并摄入。"""
        results = []
        for item in extract_iocs(text):
            results.append(self.ingest(
                {"ioc": item["value"], "type": item["type"],
                 "title": f"文本提取 {item['type']}", "confidence": 70}, source))
        return results

    # ---------- 导入 ----------
    def import_stix_taxii(self, bundle: Dict[str, Any], source: str = "stix") -> List[Dict[str, Any]]:
        """模拟STIX/TAXII bundle导入（处理indicators/sightings）。"""
        results = []
        for obj in (bundle or {}).get("objects", []):
            if obj.get("type") in ("indicator", "indicator", "report"):
                pattern = obj.get("pattern", "")
                values = re.findall(r"'([^']+)'", pattern)
                for v in values:
                    if classify_ioc(v):
                        results.append(self.ingest({
                            "ioc": v, "title": obj.get("name", v),
                            "confidence": 80, "tags": ["stix"],
                        }, source))
        return results

    def import_csv(self, csv_text: str, source: str = "csv") -> List[Dict[str, Any]]:
        """从CSV文本导入情报，期望列:ioc,type,severity,tags。"""
        results = []
        try:
            reader = csv.DictReader(io.StringIO(csv_text or ""))
            for row in reader:
                results.append(self.ingest(row, source))
        except Exception as e:
            raise ValueError(f"CSV解析失败: {e}")
        return results

    # ---------- 更新管理 ----------
    def pull_source(self, sid: str) -> Dict[str, Any]:
        """模拟从情报源拉取（真实尝试HTTP，失败回退模拟）。"""
        src = self.sources.get(sid)
        if not src:
            raise KeyError(f"情报源不存在: {sid}")
        added = 0
        if _REQUESTS_OK and src.get("api_supported") and src.get("config"):
            try:
                # 真实尝试一次（短超时），失败回退模拟
                resp = requests.get(src.get("url", "https://example.com"),
                                    timeout=2)
                added = min(3, len(resp.text) % 3)
            except Exception:
                added = 0
        if added == 0:
            # 模拟增量：生成2条新情报
            for _ in range(2):
                ip = f"198.51.100.{1 + int(time.time()) % 250}"
                self.ingest({"ioc": ip, "type": "ip",
                             "title": f"{src['name']} 新增C2", "confidence": 75}, sid)
                added += 1
        src["last_pull"] = self._now_iso()
        src["next_pull"] = self._now_iso() if False else (
            datetime.now() + timedelta(seconds=src["pull_interval"])).isoformat()
        src["items_count"] = src.get("items_count", 0) + added
        return {"source": sid, "added": added, "last_pull": src["last_pull"]}

    def refresh_all(self) -> Dict[str, Any]:
        total = 0
        for sid, s in self.sources.items():
            if s.get("enabled"):
                total += self.pull_source(sid)["added"]
        return {"pulled": len([s for s in self.sources.values() if s.get("enabled")]),
                "added": total}

    def expire_and_archive(self) -> Dict[str, Any]:
        """过期清理与归档。"""
        now = datetime.now()
        expired = 0
        for fid, f in self.feeds.items():
            try:
                exp = datetime.fromisoformat(f["expires"])
            except Exception:
                continue
            if exp < now and f.get("status") == "active":
                f["status"] = "expired"
                expired += 1
        return {"expired": expired, "active": sum(
            1 for f in self.feeds.values() if f["status"] == "active")}

    # ---------- 查询 / 评分 ----------
    def query(self, q: str = "", typ: Optional[str] = None,
              severity: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        out = list(self.feeds.values())
        if q:
            ql = q.lower()
            out = [f for f in out if ql in f["ioc"].lower() or ql in f["title"].lower()]
        if typ:
            out = [f for f in out if f["type"] == typ]
        if severity:
            out = [f for f in out if f["severity"] == severity]
        return out[:limit]

    def quality_score(self, fid: str) -> int:
        """情报质量评分：可信度+多源融合+在野利用+时效。"""
        f = self.feeds.get(fid)
        if not f:
            return 0
        score = f.get("confidence", 50)
        score += 10 if len(f.get("sources", [f["source"]])) >= 2 else 0
        score += 15 if f.get("in_the_wild") else 0
        try:
            age = (datetime.now() - datetime.fromisoformat(f["last_seen"])).days
            score += max(0, 10 - age)
        except Exception:
            pass
        return max(0, min(100, score))

    def stats(self) -> Dict[str, Any]:
        sev: Dict[str, int] = {}
        typ: Dict[str, int] = {}
        for f in self.feeds.values():
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
            typ[f["type"]] = typ.get(f["type"], 0) + 1
        return {
            "sources_total": len(self.sources),
            "sources_enabled": sum(1 for s in self.sources.values() if s["enabled"]),
            "feeds_total": len(self.feeds),
            "feeds_active": sum(1 for f in self.feeds.values() if f["status"] == "active"),
            "severity_dist": sev, "type_dist": typ,
            "change_log_count": len(self.change_log),
            "groups": {g: len([s for s in self.sources.values() if s["group"] == g])
                       for g in ("open", "commercial", "community", "custom")},
        }


# 单例
_manager: Optional[IntelSourceManager] = None


def get_intel_source_manager() -> IntelSourceManager:
    global _manager
    if _manager is None:
        _manager = IntelSourceManager()
    return _manager
