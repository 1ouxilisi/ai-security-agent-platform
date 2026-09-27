# -*- coding: utf-8 -*-
"""
ioc_collection_phase.py — 方向2 威胁情报 Pro：阶段1 IOC 收集。

真实威胁情报源集成框架:
    - AlienVault OTX        (API 集成, OTX_API_KEY)
    - AbuseIPDB             (API 集成, ABUSEIPDB_API_KEY)
    - VirusTotal            (API 集成, VIRUSTOTAL_API_KEY)
    - ThreatFox             (API 集成, 免 Key, 只读)
    - URLhaus               (API 集成, 免 Key, 只读)
    - MalwareBazaar         (API 集成, 免 Key, 只读)
    - 自定义情报源            (RSS / JSON / CSV / STIX)

原则:
    - 真实 API 调用用 requests, 超时 30s;
    - 未配置 API Key 时明确提示 "未配置", 不 mock 返回伪造数据;
    - 全部不可用时退到内置 IOC 库兜底 (builtin_ioc_library), 并标注来源="内置兜底".
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

try:
    import requests  # type: ignore
    _REQUESTS_OK = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _REQUESTS_OK = False

HTTP_TIMEOUT = 30  # 秒


# --------------------------------------------------------------------------- #
# 内置兜底 IOC 库（公开周知的历史恶意 IOC，仅用于无 API Key 时演示/离线）
# --------------------------------------------------------------------------- #
BUILTIN_IOC_LIBRARY: List[Dict[str, Any]] = [
    {"type": "ip", "value": "185.220.101.1", "tags": ["tor_exit", "anonymizer"],
     "source": "内置兜底", "confidence": 70, "country": "DE", "asn": 24940,
     "malware": "TOR"},
    {"type": "ip", "value": "45.155.205.99", "tags": ["c2", "emotet"],
     "source": "内置兜底", "confidence": 85, "country": "RU", "asn": 44512,
     "malware": "Emotet"},
    {"type": "ip", "value": "104.244.76.117", "tags": ["c2", "mirai"],
     "source": "内置兜底", "confidence": 80, "country": "US", "asn": 13335,
     "malware": "Mirai"},
    {"type": "domain", "value": "secure-login-verification.xyz",
     "tags": ["phishing", "credential_harvest"], "source": "内置兜底",
     "confidence": 90, "country": "PA", "malware": "PhishKit"},
    {"type": "domain", "value": "update-checker[.]top",
     "tags": ["c2", " TrickBot".strip()], "source": "内置兜底",
     "confidence": 88, "country": "RU", "malware": "TrickBot"},
    {"type": "url", "value": "hxxp://malware-dist[.]biz/download/payload.bin",
     "tags": ["malware_delivery"], "source": "内置兜底", "confidence": 82,
     "malware": "Emotet"},
    {"type": "hash", "value": "44d88612fea8a8f36de82e1278abb02f",
     "tags": ["malware_sample", "eicar_like"], "hash_algo": "MD5",
     "source": "内置兜底", "confidence": 95, "malware": "TestSample"},
    {"type": "hash",
     "value":
     "275a021bbfb6489e20b471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
     "tags": ["malware_sample", "ransomware"], "hash_algo": "SHA256",
     "source": "内置兜底", "confidence": 90, "malware": "Conti"},
    {"type": "email", "value": "noreply@fake-bank-verify.com",
     "tags": ["phishing_sender"], "source": "内置兜底", "confidence": 75},
    {"type": "cve", "value": "CVE-2021-44228",
     "tags": ["rce", "log4shell"], "source": "内置兜底", "confidence": 100,
     "cvss": 10.0},
    {"type": "cve", "value": "CVE-2017-0144",
     "tags": ["rce", "eternalblue", "worm"], "source": "内置兜底",
     "confidence": 100, "cvss": 9.3},
    {"type": "cert_fingerprint",
     "value": "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01",
     "tags": ["malicious_cert"], "source": "内置兜底", "confidence": 60},
]


@dataclass
class CollectedIOC:
    ioc_id: str = ""
    type: str = ""            # ip/domain/url/hash/cert_fingerprint/email/cve
    value: str = ""
    tags: List[str] = field(default_factory=list)
    source: str = ""
    malware: str = ""
    confidence: int = 0
    country: str = ""
    asn: int = 0
    first_seen: str = ""
    last_seen: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_id": self.ioc_id, "type": self.type, "value": self.value,
            "tags": self.tags, "source": self.source,
            "malware": self.malware, "confidence": self.confidence,
            "country": self.country, "asn": self.asn,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "raw": self.raw,
        }


# --------------------------------------------------------------------------- #
# 情报源定义
# --------------------------------------------------------------------------- #
class IntelSource:
    """单个情报源的配置与调用封装。"""

    def __init__(self, key: str, name: str, kind: str,
                 api_url: str = "", key_env: str = "",
                 enabled: bool = True, note: str = "") -> None:
        self.key = key
        self.name = name
        self.kind = kind          # api / custom_rss / custom_json / custom_csv / custom_stix
        self.api_url = api_url
        self.key_env = key_env
        self.enabled = enabled
        self.last_run: str = ""
        self.last_status: str = "never"
        self.last_count: int = 0
        self.note = note
    def configured(self) -> bool:
        """是否已配置可用的 API Key（免 Key 源视为已配置）。"""
        if self.kind != "api":
            return bool(self.api_url)
        if not self.key_env:
            return True  # 免 Key 源 (ThreatFox/URLhaus/MalwareBazaar)
        val = os.environ.get(self.key_env, "").strip()
        return bool(val)

    def api_key(self) -> str:
        return os.environ.get(self.key_env, "").strip() if self.key_env else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key, "name": self.name, "kind": self.kind,
            "api_url": self.api_url, "key_env": self.key_env,
            "enabled": self.enabled, "configured": self.configured(),
            "has_api_key": bool(self.api_key()),
            "last_run": self.last_run, "last_status": self.last_status,
            "last_count": self.last_count, "note": self.note,
        }


class IOCollectionPhase:
    """阶段1: IOC 收集。"""

    def __init__(self) -> None:
        self._sources: Dict[str, IntelSource] = {}
        self._iocs: Dict[str, CollectedIOC] = {}
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._register_default_sources()

    # ------------------------------------------------------------------ #
    # 默认情报源
    # ------------------------------------------------------------------ #
    def _register_default_sources(self) -> None:
        defaults = [
            IntelSource("otx", "AlienVault OTX", "api",
                        api_url="https://otx.alienvault.com/api/v1",
                        key_env="OTX_API_KEY",
                        note="需 OTX_API_KEY；脉冲/恶意域名/IOC"),
            IntelSource("abuseipdb", "AbuseIPDB", "api",
                        api_url="https://api.abuseipdb.com/api/v2",
                        key_env="ABUSEIPDB_API_KEY",
                        note="需 ABUSEIPDB_API_KEY；IP 恶意评分"),
            IntelSource("virustotal", "VirusTotal", "api",
                        api_url="https://www.virustotal.com/api/v3",
                        key_env="VIRUSTOTAL_API_KEY",
                        note="需 VIRUSTOTAL_API_KEY；文件/URL/域名/IP"),
            IntelSource("threatfox", "ThreatFox (abuse.ch)", "api",
                        api_url="https://threatfox-api.abuse.ch/api/v1",
                        key_env="",
                        note="免 Key；IOC 与恶意软件家族映射"),
            IntelSource("urlhaus", "URLhaus (abuse.ch)", "api",
                        api_url="https://urlhaus-api.abuse.ch/v1",
                        key_env="",
                        note="免 Key；托管恶意 URL"),
            IntelSource("malwarebazaar", "MalwareBazaar (abuse.ch)", "api",
                        api_url="https://mb-api.abuse.ch/api/v1",
                        key_env="",
                        note="免 Key；恶意软件样本哈希"),
        ]
        for s in defaults:
            self._sources[s.key] = s

    # ------------------------------------------------------------------ #
    # 情报源管理
    # ------------------------------------------------------------------ #
    def list_sources(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._sources.values()]

    def add_source(self, key: str, name: str, kind: str,
                   api_url: str, key_env: str = "",
                   enabled: bool = True) -> Dict[str, Any]:
        if key in self._sources:
            return {"error": f"source {key} already exists"}
        s = IntelSource(key, name, kind, api_url, key_env, enabled)
        self._sources[key] = s
        return s.to_dict()

    def remove_source(self, key: str) -> Dict[str, Any]:
        s = self._sources.pop(key, None)
        if s is None:
            return {"error": "source not found"}
        return {"removed": key}

    def configure_source(self, key: str, api_url: Optional[str] = None,
                         key_env: Optional[str] = None,
                         enabled: Optional[bool] = None) -> Dict[str, Any]:
        s = self._sources.get(key)
        if s is None:
            return {"error": "source not found"}
        if api_url is not None:
            s.api_url = api_url
        if key_env is not None:
            s.key_env = key_env
        if enabled is not None:
            s.enabled = enabled
        return s.to_dict()

    # ------------------------------------------------------------------ #
    # HTTP 工具
    # ------------------------------------------------------------------ #
    def _get(self, url: str, headers: Optional[Dict[str, str]] = None,
             params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not _REQUESTS_OK:
            raise RuntimeError("requests 库未安装")
        r = requests.get(url, headers=headers or {}, params=params or {},
                         timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json() if "application/json" in r.headers.get(
            "Content-Type", "") else {"text": r.text}

    def _post(self, url: str, headers: Optional[Dict[str, str]] = None,
              data: Any = None, json_body: Any = None) -> Dict[str, Any]:
        if not _REQUESTS_OK:
            raise RuntimeError("requests 库未安装")
        r = requests.post(url, headers=headers or {}, data=data,
                          json=json_body, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return {"text": r.text}

    # ------------------------------------------------------------------ #
    # 各情报源真实调用
    # ------------------------------------------------------------------ #
    def _collect_otx(self, s: IntelSource) -> List[CollectedIOC]:
        key = s.api_key()
        if not key:
            raise RuntimeError(
                "AlienVault OTX 未配置 API Key (环境变量 OTX_API_KEY)")
        data = self._get(f"{s.api_url}/pulses/subscribed",
                         headers={"X-OTX-API-KEY": key})
        out: List[CollectedIOC] = []
        for p in (data.get("results") or [])[:50]:
            for ind in (p.get("indicators") or [])[:20]:
                out.append(CollectedIOC(
                    ioc_id=uuid.uuid4().hex[:12],
                    type=self._classify(ind.get("indicator", "")),
                    value=ind.get("indicator", ""),
                    tags=p.get("tags") or [], source="AlienVault OTX",
                    confidence=80, first_seen=p.get("created", ""),
                    last_seen=p.get("modified", ""),
                    raw={"pulse": p.get("name", "")}))
        return out

    def _collect_abuseipdb(self, s: IntelSource) -> List[CollectedIOC]:
        key = s.api_key()
        if not key:
            raise RuntimeError(
                "AbuseIPDB 未配置 API Key (环境变量 ABUSEIPDB_API_KEY)")
        data = self._get(
            f"{s.api_url}/blacklist",
            headers={"Key": key, "Accept": "application/json"},
            params={"confidenceMinimum": 90})
        out: List[CollectedIOC] = []
        for ip in (data.get("data") or {}).get("blacklist", [])[:100]:
            out.append(CollectedIOC(
                ioc_id=uuid.uuid4().hex[:12], type="ip",
                value=ip.get("ipAddress", ""),
                tags=["malicious_ip"], source="AbuseIPDB",
                confidence=int(ip.get("abuseConfidenceScore", 0) or 0),
                raw=ip))
        return out

    def _collect_virustotal(self, s: IntelSource,
                           query: str = "1d:") -> List[CollectedIOC]:
        key = s.api_key()
        if not key:
            raise RuntimeError(
                "VirusTotal 未配置 API Key (环境变量 VIRUSTOTAL_API_KEY)")
        data = self._get(
            f"{s.api_url}/intelligence/search",
            headers={"x-apikey": key},
            params={"query": query, "limit": "40"})
        out: List[CollectedIOC] = []
        for it in (data.get("data") or [])[:40]:
            attrs = it.get("attributes", {})
            out.append(CollectedIOC(
                ioc_id=uuid.uuid4().hex[:12],
                type=self._classify(it.get("id", "")),
                value=it.get("id", ""), source="VirusTotal",
                confidence=int(attrs.get("reputation", 0) or 0) + 50,
                raw=attrs))
        return out

    def _collect_threatfox(self, s: IntelSource) -> List[CollectedIOC]:
        data = self._post(s.api_url,
                          json_body={"query": "get_iocs", "days": 7})
        out: List[CollectedIOC] = []
        for it in (data.get("data") or [])[:80]:
            out.append(CollectedIOC(
                ioc_id=uuid.uuid4().hex[:12],
                type=self._classify(it.get("ioc", "")),
                value=it.get("ioc", ""),
                tags=[it.get("threat_type", "")],
                malware=it.get("malware", ""), source="ThreatFox",
                confidence=int(it.get("confidence_level", 50) or 50),
                country=it.get("country", ""),
                first_seen=it.get("first_seen", ""),
                last_seen=it.get("last_seen", ""), raw=it))
        return out

    def _collect_urlhaus(self, s: IntelSource) -> List[CollectedIOC]:
        data = self._post(f"{s.api_url}/recent", data={"days": 3})
        out: List[CollectedIOC] = []
        for it in (data.get("urlhaus_return") or data.get(
                "query_status") == "ok" and data.get("urls") or [])[:80]:
            out.append(CollectedIOC(
                ioc_id=uuid.uuid4().hex[:12], type="url",
                value=it.get("url", ""),
                tags=[it.get("threat", "")],
                malware=it.get("payload", {}).get("1", {}).get(
                    "filename", ""),
                source="URLhaus", confidence=85,
                country=it.get("country", ""),
                first_seen=it.get("date_added", ""), raw=it))
        return out

    def _collect_malwarebazaar(self, s: IntelSource) -> List[CollectedIOC]:
        data = self._post(s.api_url,
                          json_body={"query": "get_recent", "selector": "time"})
        out: List[CollectedIOC] = []
        for it in (data.get("data") or [])[:80]:
            out.append(CollectedIOC(
                ioc_id=uuid.uuid4().hex[:12], type="hash",
                value=it.get("sha256_hash", ""), hash_algo="SHA256",
                tags=it.get("signature", "").split("|") if it.get(
                    "signature") else [],
                malware=it.get("signature", ""), source="MalwareBazaar",
                confidence=90,
                first_seen=it.get("first_seen", ""), raw=it))
        return out

    @staticmethod
    def _classify(value: str) -> str:
        v = (value or "").strip()
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v):
            return "ip"
        if re.match(r"^(https?://)", v):
            return "url"
        if re.match(r"^[A-Fa-f0-9]{32}$", v):
            return "hash"
        if re.match(r"^[A-Fa-f0-9]{40}$", v):
            return "hash"
        if re.match(r"^[A-Fa-f0-9]{64}$", v):
            return "hash"
        if re.match(r"^CVE-\d{4}-\d{4,7}$", v, re.I):
            return "cve"
        if "@" in v and "." in v:
            return "email"
        if re.match(r"^[A-Fa-f0-9:]{20,}$", v):
            return "cert_fingerprint"
        return "domain"

    # ------------------------------------------------------------------ #
    # 自定义源解析
    # ------------------------------------------------------------------ #
    def _collect_custom(self, s: IntelSource) -> List[CollectedIOC]:
        if not _REQUESTS_OK:
            raise RuntimeError("requests 库未安装")
        resp = requests.get(s.api_url, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        out: List[CollectedIOC] = []
        if s.kind == "custom_json":
            data = resp.json()
            items = data if isinstance(data, list) else data.get(
                "iocs", data.get("indicators", []))
            for it in items:
                out.append(CollectedIOC(
                    ioc_id=uuid.uuid4().hex[:12],
                    type=self._classify(str(it.get("value", ""))),
                    value=str(it.get("value", "")),
                    tags=it.get("tags", []), source=s.name,
                    confidence=int(it.get("confidence", 50) or 50), raw=it))
        elif s.kind == "custom_csv":
            reader = csv.DictReader(io.StringIO(resp.text))
            for row in reader:
                val = row.get("value") or row.get("ioc") or row.get("indicator", "")
                out.append(CollectedIOC(
                    ioc_id=uuid.uuid4().hex[:12],
                    type=self._classify(val), value=val,
                    tags=[t for t in [row.get("tag")] if t],
                    source=s.name,
                    confidence=int(row.get("confidence", 50) or 50), raw=row))
        elif s.kind in ("custom_rss", "custom_stix"):
            # 框架: 抓取文本并粗提取 IOC 样式 token
            for m in re.findall(
                    r"\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                    r"[A-Fa-f0-9]{64}|https?://[^\s<]+)\b",
                    resp.text)[:100]:
                out.append(CollectedIOC(
                    ioc_id=uuid.uuid4().hex[:12],
                    type=self._classify(m), value=m,
                    tags=[s.kind], source=s.name, confidence=50,
                    raw={"excerpt": m[:200]}))
        return out

    # ------------------------------------------------------------------ #
    # 主收集入口
    # ------------------------------------------------------------------ #
    DISPATCH: Dict[str, Callable] = {}

    def collect_source(self, source_key: str) -> Dict[str, Any]:
        s = self._sources.get(source_key)
        if s is None:
            return {"error": "source not found"}
        if not s.enabled:
            s.last_status = "disabled"
            return {"source": source_key, "status": "disabled", "count": 0}
        dispatch = {
            "otx": self._collect_otx,
            "abuseipdb": self._collect_abuseipdb,
            "virustotal": self._collect_virustotal,
            "threatfox": self._collect_threatfox,
            "urlhaus": self._collect_urlhaus,
            "malwarebazaar": self._collect_malwarebazaar,
        }
        s.last_run = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            if source_key in dispatch:
                items = dispatch[source_key](s)
            else:
                items = self._collect_custom(s)
            for it in items:
                self._iocs[it.value] = it
            s.last_status = "ok"
            s.last_count = len(items)
            return {"source": source_key, "status": "ok",
                    "count": len(items),
                    "items": [i.to_dict() for i in items[:50]]}
        except Exception as e:  # noqa: BLE001
            s.last_status = f"error: {e}"
            s.last_count = 0
            return {"source": source_key, "status": "error",
                    "error": str(e), "count": 0}

    def collect_all(self, use_builtin_fallback: bool = True) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        total = 0
        errored = 0
        for key in list(self._sources.keys()):
            r = self.collect_source(key)
            results[key] = r
            if r.get("status") == "ok":
                total += r.get("count", 0)
            elif r.get("status", "").startswith("error"):
                errored += 1
        fallback_used = False
        if total == 0 and use_builtin_fallback:
            fallback_used = True
            for raw in BUILTIN_IOC_LIBRARY:
                c = CollectedIOC(
                    ioc_id=uuid.uuid4().hex[:12],
                    type=raw.get("type", "unknown"),
                    value=raw.get("value", ""),
                    tags=raw.get("tags", []), source=raw.get("source", ""),
                    malware=raw.get("malware", ""),
                    confidence=int(raw.get("confidence", 50) or 50),
                    country=raw.get("country", ""),
                    asn=int(raw.get("asn", 0) or 0),
                    first_seen=time.strftime("%Y-%m-%d %H:%M:%S"),
                    last_seen=time.strftime("%Y-%m-%d %H:%M:%S"),
                    raw=raw)
                self._iocs[c.value] = c
            total = len(BUILTIN_IOC_LIBRARY)
        return {
            "total_collected": total,
            "errored_sources": errored,
            "results": results,
            "builtin_fallback_used": fallback_used,
            "hint": ("所有情报源未配置/不可用，已使用内置 IOC 库兜底。"
                     "配置对应环境变量以接入真实情报源。"
                     if fallback_used else ""),
        }

    # ------------------------------------------------------------------ #
    def list_iocs(self, limit: int = 200) -> List[Dict[str, Any]]:
        return [i.to_dict() for i in
                list(self._iocs.values())[:limit]]

    def count(self) -> int:
        return len(self._iocs)

    def add_manual(self, type: str, value: str,
                   tags: Optional[List[str]] = None,
                   source: str = "manual",
                   confidence: int = 60) -> Dict[str, Any]:
        c = CollectedIOC(
            ioc_id=uuid.uuid4().hex[:12],
            type=type or self._classify(value), value=value,
            tags=tags or [], source=source, confidence=confidence,
            first_seen=time.strftime("%Y-%m-%d %H:%M:%S"),
            last_seen=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._iocs[value] = c
        return c.to_dict()

    # ------------------------------------------------------------------ #
    # 定时收集（框架）
    # ------------------------------------------------------------------ #
    def schedule(self, interval_minutes: int = 60) -> Dict[str, Any]:
        job_id = uuid.uuid4().hex[:12]
        self._jobs[job_id] = {
            "job_id": job_id, "interval_minutes": interval_minutes,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "note": "定时任务已登记；生产环境应由调度器触发 collect_all()",
        }
        return self._jobs[job_id]

    def list_jobs(self) -> List[Dict[str, Any]]:
        return list(self._jobs.values())


_phase: Optional[IOCollectionPhase] = None


def get_collection_phase() -> IOCollectionPhase:
    global _phase
    if _phase is None:
        _phase = IOCollectionPhase()
    return _phase
