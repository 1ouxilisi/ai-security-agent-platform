# -*- coding: utf-8 -*-
"""
ioc_matching_phase.py — 方向2 威胁情报 Pro：阶段3 IOC 匹配。

在真实日志 / 流量 / 资产 / 邮件中匹配已入库 IOC：
    - 日志匹配   (系统/应用/安全设备日志，行扫描)
    - 流量匹配   (网络流量 / NetFlow / PCAP 摘要)
    - 资产匹配   (终端/服务器/网络设备，对照资产清单)
    - 邮件匹配   (邮件头 / 附件 / 链接)

产出: 匹配结果 + 告警 + 统计。纯内存。
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .ioc_management_phase import get_management_phase, ManagedIOC


@dataclass
class MatchHit:
    hit_id: str = ""
    ioc_value: str = ""
    ioc_type: str = ""
    source_kind: str = ""       # log/traffic/asset/email
    source_ref: str = ""       # 日志行号/流ID/资产ID/邮件ID
    context: str = ""          # 命中上下文片段
    severity: str = "medium"
    confidence: int = 0
    timestamp: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hit_id": self.hit_id, "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type, "source_kind": self.source_kind,
            "source_ref": self.source_ref, "context": self.context,
            "severity": self.severity, "confidence": self.confidence,
            "timestamp": self.timestamp, "raw": self.raw,
        }


@dataclass
class MatchAlert:
    alert_id: str = ""
    title: str = ""
    severity: str = "medium"
    status: str = "open"        # open/ack/closed
    hits: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id, "title": self.title,
            "severity": self.severity, "status": self.status,
            "hit_count": len(self.hits), "hits": self.hits,
            "created_at": self.created_at, "updated_at": self.updated_at,
        }


SEVERITY_BY_CONF = [(90, "critical"), (75, "high"), (50, "medium"),
                    (0, "low")]


def _sev(conf: int) -> str:
    for threshold, name in SEVERITY_BY_CONF:
        if conf >= threshold:
            return name
    return "low"


class IOMatchingPhase:
    """阶段3: IOC 匹配。"""

    def __init__(self) -> None:
        self._mgmt = get_management_phase()
        self._hits: Dict[str, MatchHit] = {}
        self._alerts: Dict[str, MatchAlert] = {}

    # ------------------------------------------------------------------ #
    # 构建匹配索引
    # ------------------------------------------------------------------ #
    def _build_index(self) -> Dict[str, List[ManagedIOC]]:
        """按类型把 IOC 值建成可匹配集合。"""
        idx: Dict[str, List[ManagedIOC]] = {"ip": [], "domain": [],
                                            "url": [], "hash": [],
                                            "email": [], "cve": []}
        for ioc in self._mgmt._iocs.values():  # noqa: SLF001
            if ioc.lifecycle == "revoked":
                continue
            if ioc.type in idx:
                idx[ioc.type].append(ioc)
            elif ioc.type == "ipv6":
                idx["ip"].append(ioc)
        return idx

    # ------------------------------------------------------------------ #
    # 日志匹配
    # ------------------------------------------------------------------ #
    def match_logs(self, logs: List[str],
                   source_name: str = "syslog") -> Dict[str, Any]:
        idx = self._build_index()
        hits: List[MatchHit] = []
        for lineno, line in enumerate(logs):
            for ioc in idx["ip"]:
                if ioc.value in line:
                    hits.append(self._mk_hit(
                        ioc, "log", f"{source_name}:#{lineno}", line[:200]))
            for ioc in idx["domain"]:
                if ioc.value.lower() in line.lower():
                    hits.append(self._mk_hit(
                        ioc, "log", f"{source_name}:#{lineno}", line[:200]))
            for ioc in idx["hash"]:
                if ioc.value.lower() in line.lower():
                    hits.append(self._mk_hit(
                        ioc, "log", f"{source_name}:#{lineno}", line[:200]))
        self._persist(hits)
        self._auto_alert(hits, "日志 IOC 命中告警")
        return {"scanned_lines": len(logs), "hits": len(hits),
                "sample": [h.to_dict() for h in hits[:20]]}

    # ------------------------------------------------------------------ #
    # 流量匹配 (NetFlow / PCAP 摘要)
    # ------------------------------------------------------------------ #
    def match_traffic(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        idx = self._build_index()
        ip_set = {i.value: i for i in idx["ip"]}
        domain_set = {i.value.lower(): i for i in idx["domain"]}
        hits: List[MatchHit] = []
        for flow in flows:
            src = flow.get("src_ip", "")
            dst = flow.get("dst_ip", "")
            host = (flow.get("host") or flow.get("dns") or "").lower()
            if src in ip_set:
                hits.append(self._mk_hit(
                    ip_set[src], "traffic", flow.get("id", "-"),
                    f"流出 {src} -> {dst}:{flow.get('dst_port','')}"))
            if dst in ip_set:
                hits.append(self._mk_hit(
                    ip_set[dst], "traffic", flow.get("id", "-"),
                    f"流入 {src} -> {dst}:{flow.get('dst_port','')}"))
            for d, ioc in domain_set.items():
                if d and (d == host or host.endswith("." + d)):
                    hits.append(self._mk_hit(
                        ioc, "traffic", flow.get("id", "-"),
                        f"DNS/Host={host}"))
        self._persist(hits)
        self._auto_alert(hits, "流量 IOC 命中告警")
        return {"scanned_flows": len(flows), "hits": len(hits),
                "sample": [h.to_dict() for h in hits[:20]]}

    # ------------------------------------------------------------------ #
    # 资产匹配
    # ------------------------------------------------------------------ #
    def match_assets(self, assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        idx = self._build_index()
        ip_set = {i.value: i for i in idx["ip"]}
        domain_set = {i.value.lower(): i for i in idx["domain"]}
        hits: List[MatchHit] = []
        for asset in assets:
            aid = asset.get("asset_id") or asset.get("id", "-")
            ips = asset.get("ips", []) or [asset.get("ip", "")]
            doms = asset.get("domains", []) or [asset.get("domain", "")]
            for ip in ips:
                if ip in ip_set:
                    hits.append(self._mk_hit(
                        ip_set[ip], "asset", aid,
                        f"资产 {asset.get('name', aid)} 暴露恶意IP {ip}"))
            for d in doms:
                dl = (d or "").lower()
                if dl in domain_set:
                    hits.append(self._mk_hit(
                        domain_set[dl], "asset", aid,
                        f"资产域名 {dl} 命中恶意域名"))
        self._persist(hits)
        self._auto_alert(hits, "资产 IOC 暴露告警")
        return {"scanned_assets": len(assets), "hits": len(hits),
                "sample": [h.to_dict() for h in hits[:20]]}

    # ------------------------------------------------------------------ #
    # 邮件匹配
    # ------------------------------------------------------------------ #
    def match_emails(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        idx = self._build_index()
        email_set = {i.value.lower(): i for i in idx["email"]}
        url_set = {i.value.lower(): i for i in idx["url"]}
        hash_set = {i.value.lower(): i for i in idx["hash"]}
        hits: List[MatchHit] = []
        for mail in emails:
            mid = mail.get("message_id", "-")
            sender = (mail.get("from") or "").lower()
            body = (mail.get("body") or mail.get("subject") or "")
            attachments = mail.get("attachments", [])
            if sender in email_set:
                hits.append(self._mk_hit(
                    email_set[sender], "email", mid,
                    f"发件人 {sender} 命中"))
            for url in re.findall(r"https?://[^\s<>]+", body):
                if url.lower() in url_set:
                    hits.append(self._mk_hit(
                        url_set[url.lower()], "email", mid,
                        f"邮件链接 {url}"))
            for att in attachments:
                h = (att.get("sha256") or att.get("md5") or "").lower()
                if h in hash_set:
                    hits.append(self._mk_hit(
                        hash_set[h], "email", mid,
                        f"附件 {att.get('name','?')} 命中样本哈希"))
        self._persist(hits)
        self._auto_alert(hits, "邮件 IOC 命中告警")
        return {"scanned_emails": len(emails), "hits": len(hits),
                "sample": [h.to_dict() for h in hits[:20]]}

    # ------------------------------------------------------------------ #
    def _mk_hit(self, ioc: ManagedIOC, kind: str, ref: str,
                context: str) -> MatchHit:
        return MatchHit(
            hit_id=uuid.uuid4().hex[:12],
            ioc_value=ioc.value, ioc_type=ioc.type,
            source_kind=kind, source_ref=ref, context=context,
            severity=_sev(ioc.confidence), confidence=ioc.confidence,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            raw={"tags": ioc.tags, "malware": ioc.malware,
                 "source": ioc.source})

    def _persist(self, hits: List[MatchHit]) -> None:
        for h in hits:
            self._hits[h.hit_id] = h

    def _auto_alert(self, hits: List[MatchHit], title: str) -> None:
        if not hits:
            return
        sev = "critical" if any(h.severity == "critical" for h in hits) \
            else ("high" if any(h.severity == "high" for h in hits)
                  else "medium")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        a = MatchAlert(
            alert_id=uuid.uuid4().hex[:12], title=title, severity=sev,
            hits=[h.to_dict() for h in hits[:50]],
            created_at=now, updated_at=now)
        self._alerts[a.alert_id] = a

    # ------------------------------------------------------------------ #
    # 告警管理
    # ------------------------------------------------------------------ #
    def list_alerts(self) -> List[Dict[str, Any]]:
        return [a.to_dict() for a in sorted(
            self._alerts.values(), key=lambda x: x.created_at,
            reverse=True)]

    def update_alert(self, alert_id: str, status: str) -> Dict[str, Any]:
        a = self._alerts.get(alert_id)
        if a is None:
            return {"error": "alert not found"}
        a.status = status
        a.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return a.to_dict()

    def list_hits(self, source_kind: str = "",
                  limit: int = 200) -> List[Dict[str, Any]]:
        out = [h for h in self._hits.values()
               if not source_kind or h.source_kind == source_kind]
        out.sort(key=lambda x: x.timestamp, reverse=True)
        return [h.to_dict() for h in out[:limit]]

    def stats(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        for h in self._hits.values():
            by_kind[h.source_kind] = by_kind.get(h.source_kind, 0) + 1
            by_sev[h.severity] = by_sev.get(h.severity, 0) + 1
        open_alerts = sum(1 for a in self._alerts.values()
                          if a.status == "open")
        return {
            "total_hits": len(self._hits),
            "hits_by_source": by_kind,
            "hits_by_severity": by_sev,
            "total_alerts": len(self._alerts),
            "open_alerts": open_alerts,
        }


_phase: Optional[IOMatchingPhase] = None


def get_matching_phase() -> IOMatchingPhase:
    global _phase
    if _phase is None:
        _phase = IOMatchingPhase()
    return _phase
