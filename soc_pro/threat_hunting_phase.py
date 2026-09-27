# -*- coding: utf-8 -*-
"""
threat_hunting_phase.py — 阶段6：威胁狩猎。

功能:
    - 主动狩猎查询（自定义查询/预设狩猎场景）
    - IOC 匹配（IP/域名/URL/哈希）
    - 攻击链分析（MITRE ATT&CK 映射）
    - 异常行为检测（基线偏离/ML 异常检测框架）
    - 狩猎发现管理
    - 狩猎报告生成
"""

from __future__ import annotations

import statistics
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class HuntingQuery:
    qid: str = ""
    name: str = ""
    category: str = ""
    query: str = ""
    mitre: str = ""
    hits: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "qid": self.qid, "name": self.name,
            "category": self.category, "query": self.query,
            "mitre": self.mitre, "hits": self.hits,
        }


@dataclass
class HuntingFind:
    fid: str = ""
    query: str = ""
    summary: str = ""
    severity: str = "medium"
    mitre: str = ""
    src_ip: str = ""
    user: str = ""
    evidence: List[str] = field(default_factory=list)
    status: str = "new"   # new/triaged/benign/confirmed
    found_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fid": self.fid, "query": self.query, "summary": self.summary,
            "severity": self.severity, "mitre": self.mitre,
            "src_ip": self.src_ip, "user": self.user,
            "evidence": self.evidence, "status": self.status,
            "found_at": self.found_at,
        }


_PRESET_QUERIES: List[Dict[str, str]] = [
    {"name": "C2 回连检测", "category": "c2",
     "query": "dst_ip in (ti_c2_ip) OR dns_query in (ti_c2_domain)",
     "mitre": "T1071"},
    {"name": "横向移动痕迹", "category": "lateral",
     "query": "event_id=5140 OR event_id=4688 AND cmd IN (wmi*, psexec*)",
     "mitre": "T1021"},
    {"name": "凭证转储", "category": "cred_dump",
     "query": "process IN (mimikatz*, procdump*, lsass*)",
     "mitre": "T1003"},
    {"name": "持久化植入", "category": "persistence",
     "query": "registry IN (*\\Run, *\\Startup) AND image !contains (ms*)",
     "mitre": "T1547"},
    {"name": "PowerShell 混淆", "category": "obfuscation",
     "query": "cmdline contains -enc OR cmdline contains IEX",
     "mitre": "T1059.001"},
    {"name": "异常外连", "category": "exfil",
     "query": "bytes_out>50MB AND dst_country NOT IN (CN, internal)",
     "mitre": "T1041"},
    {"name": "AD 异常查询", "category": "ad_enum",
     "query": "ldap_search:(&(objectClass=user)(adminCount=1))",
     "mitre": "T1087.002"},
    {"name": "提权后自启动", "category": "privesc",
     "query": "user=root AND cmd IN (chmod u+s*, systemctl enable*)",
     "mitre": "T1548"},
]

_IOC_LIBRARY: Dict[str, List[str]] = {
    "ip": ["45.155.205.10", "185.220.101.4", "194.147.76.23",
           "91.219.236.10"],
    "domain": ["evil-c2.example.com", "update-check.top",
               "cdn-staticcdn.ru", "login-verify.xyz"],
    "url": ["http://45.155.205.10/x.php", "https://update-check.top/upd",
            "http://194.147.76.23:8080/beam"],
    "hash": ["a1b2c3d4e5f60718293a4b5c6d7e8f90",
             "0123456789abcdef0123456789abcdef",
             "deadbeefdeadbeefdeadbeefdeadbeef"],
}


class ThreatHuntingPhase:
    """阶段6：威胁狩猎。"""

    def __init__(self) -> None:
        self._queries: Dict[str, HuntingQuery] = {}
        self._finds: List[HuntingFind] = []
        self._baselines: Dict[str, float] = {}
        self._lock = threading.Lock()
        for i, q in enumerate(_PRESET_QUERIES):
            qid = f"hq_{i+1:03d}"
            self._queries[qid] = HuntingQuery(
                qid=qid, name=q["name"], category=q["category"],
                query=q["query"], mitre=q["mitre"])

    # ------------------------------------------------------------------ #
    def list_queries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [q.to_dict() for q in self._queries.values()]

    def run_query(self, qid: Optional[str] = None,
                  custom_query: str = "") -> Dict[str, Any]:
        from .log_parsing_phase import get_log_parsing_phase
        logs = get_log_parsing_phase().recent_parsed(500)
        query_text = custom_query
        mitre = ""
        name = "自定义查询"
        if qid:
            with self._lock:
                q = self._queries.get(qid)
            if q is None:
                return {"success": False, "error": "query not found"}
            query_text = q.query
            mitre = q.mitre
            name = q.name
            q.hits += 1

        finds: List[HuntingFind] = []
        # 狩猎：按查询类别启发式匹配
        for p in logs:
            raw = (p.get("raw") or "").lower()
            tag_hit = False
            sev = "low"
            if "c2" in query_text.lower() or "ti_c2" in query_text:
                if p.get("ti_hit"):
                    tag_hit = True
                    sev = "critical"
            elif "lateral" in query_text.lower():
                if "filecreate" in raw or "smb" in raw:
                    tag_hit = True
                    sev = "high"
            elif "cred_dump" in query_text.lower():
                if "mimikatz" in raw or "procdump" in raw:
                    tag_hit = True
                    sev = "critical"
            elif "persistence" in query_text.lower():
                if "run" in raw or "startup" in raw:
                    tag_hit = True
                    sev = "high"
            elif "obfuscation" in query_text.lower():
                if "-enc" in raw or "iex" in raw:
                    tag_hit = True
                    sev = "high"
            elif "exfil" in query_text.lower():
                if "outbound" in raw or "egress" in raw:
                    tag_hit = True
                    sev = "high"
            elif "ad_enum" in query_text.lower():
                if "ldap" in raw or "administrator" in raw:
                    tag_hit = True
                    sev = "medium"
            elif "privesc" in query_text.lower():
                if "sudo" in raw or "chmod" in raw:
                    tag_hit = True
                    sev = "medium"
            if tag_hit:
                finds.append(HuntingFind(
                    fid="hf_" + uuid.uuid4().hex[:8],
                    query=name,
                    summary=f"狩猎[{name}]命中：{p.get('raw','')[:120]}",
                    severity=sev, mitre=mitre,
                    src_ip=p.get("src_ip", ""),
                    user=p.get("user", ""),
                    evidence=[p.get("raw", "")[:200]],
                    found_at=datetime.now().isoformat(timespec="seconds"),
                ))
        with self._lock:
            self._finds.extend(finds)
        return {
            "query": query_text, "scanned": len(logs),
            "finds": len(finds),
            "results": [f.to_dict() for f in finds[:20]],
        }

    # ------------------------------------------------------------------ #
    def ioc_match(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """在采集日志中匹配 IOC。"""
        from .log_parsing_phase import get_log_parsing_phase
        logs = get_log_parsing_phase().recent_parsed(500)
        value = value.strip()
        hits = []
        for p in logs:
            raw = (p.get("raw") or "").lower()
            if ioc_type == "ip" and value in (p.get("src_ip", ""),
                                              p.get("dst_ip", "")):
                hits.append(p)
            elif value in raw:
                hits.append(p)
        return {
            "ioc_type": ioc_type, "value": value,
            "hits": len(hits),
            "samples": [h.to_dict() for h in hits[:10]],
        }

    def ioc_library(self) -> Dict[str, List[str]]:
        return {k: list(v) for k, v in _IOC_LIBRARY.items()}

    # ------------------------------------------------------------------ #
    def attack_chain(self) -> Dict[str, Any]:
        """基于现有 hits 重建 ATT&CK 攻击链。"""
        from .correlation_phase import get_correlation_phase
        hits = get_correlation_phase().recent_hits(200)
        chain: Dict[str, List[Dict[str, Any]]] = {}
        for h in hits:
            m = h.get("mitre") or "T0000"
            chain.setdefault(m, []).append({
                "rule": h.get("rule_name", ""),
                "src": h.get("src_ip", ""),
                "sev": h.get("severity", ""),
                "ts": h.get("timestamp", ""),
            })
        # 简易阶段映射
        tactics = {
            "T1046": "侦察/扫描", "T1110": "初始访问/爆破",
            "T1078": "凭证访问", "T1068": "提权",
            "T1021": "横向移动", "T1071": "C2 通信",
            "T1041": "数据外泄", "T1485": "影响/破坏",
        }
        nodes = []
        for mitre, items in chain.items():
            nodes.append({
                "mitre": mitre,
                "tactic": tactics.get(mitre, "未知"),
                "count": len(items),
                "samples": items[:3],
            })
        return {"nodes": nodes, "total_techniques": len(nodes)}

    # ------------------------------------------------------------------ #
    def anomaly_detect(self) -> Dict[str, Any]:
        """基线偏离 + 简易统计异常（Z-score）。"""
        from .alert_generation_phase import get_alert_generation_phase
        agg = get_alert_generation_phase().aggregate()
        src_counts = [item["count"]
                      for item in agg.get("top_source_ips", [])]
        if not src_counts:
            return {"anomalies": [], "note": "样本不足"}
        mean = statistics.mean(src_counts)
        std = statistics.pstdev(src_counts) or 1.0
        anomalies = []
        for item in agg.get("top_source_ips", []):
            z = (item["count"] - mean) / std
            if z > 1.5:
                anomalies.append({
                    "ip": item["ip"], "count": item["count"],
                    "z_score": round(z, 2),
                    "advice": "建议加入狩猎清单，重点关注",
                })
        return {"mean": round(mean, 2), "std": round(std, 2),
                "anomalies": anomalies}

    # ------------------------------------------------------------------ #
    def list_finds(self, status: Optional[str] = None
                   ) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._finds)
        if status:
            items = [f for f in items if f.status == status]
        return [f.to_dict() for f in items[-200:]]

    def triage(self, fid: str, status: str) -> bool:
        with self._lock:
            for f in self._finds:
                if f.fid == fid:
                    f.status = status
                    return True
        return False

    def hunting_report(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._finds)
        confirmed = sum(1 for f in items if f.status == "confirmed")
        benign = sum(1 for f in items if f.status == "benign")
        return {
            "total_finds": len(items),
            "confirmed": confirmed, "benign": benign,
            "open": len(items) - confirmed - benign,
            "attack_chain": self.attack_chain(),
            "anomaly": self.anomaly_detect(),
        }


_default: Optional[ThreatHuntingPhase] = None


def get_threat_hunting_phase() -> ThreatHuntingPhase:
    global _default
    if _default is None:
        _default = ThreatHuntingPhase()
    return _default
