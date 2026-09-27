# -*- coding: utf-8 -*-
"""
darkweb_monitor_phase.py — 方向2 威胁情报 Pro：阶段6 暗网监控。

监控框架:
    - 凭证泄露    (账号密码 / 数据库泄露)
    - 数据售卖    (用户数据 / 企业数据 / 源代码)
    - 恶意软件交易
    - 黑客服务    (DDoS / 钓鱼 / 入侵即服务)
    - 品牌提及    (品牌滥用 / 假冒网站)

凭证泄露检测 (企业域名 / 员工邮箱), 品牌保护, 暗网告警。

说明: 真实暗网抓取需 Tor 网络与授权访问；未配置时使用内置模拟框架兜底，
并在结果中明确标注 "模拟/未配置"。不伪造真实暗网数据。
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DarkwebHit:
    hit_id: str = ""
    category: str = ""           # credential_leak/data_sale/malware/
                                  # hacker_service/brand_mention
    title: str = ""
    source: str = ""            # 论坛/市场名
    url: str = ""
    snippet: str = ""
    severity: str = "medium"
    mentions_brand: str = ""
    price_usd: int = 0
    timestamp: str = ""
    simulated: bool = True       # 是否模拟数据

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hit_id": self.hit_id, "category": self.category,
            "title": self.title, "source": self.source, "url": self.url,
            "snippet": self.snippet, "severity": self.severity,
            "mentions_brand": self.mentions_brand,
            "price_usd": self.price_usd, "timestamp": self.timestamp,
            "simulated": self.simulated,
        }


# 内置模拟暗网帖（公开/示例性质，非真实抓取）
SIMULATED_POSTS: List[Dict[str, Any]] = [
    {"category": "credential_leak",
     "title": "[LEAK] AcmeCorp internal employee DB ~12k records",
     "source": "BreachForums (模拟)",
     "snippet": "Oracle DB dump, usernames + SHA1 hashes, "
                "partial plaintext for ~3k accounts.",
     "severity": "critical", "price_usd": 800},
    {"category": "data_sale",
     "title": "Source code bundle - fintech payment gateway (Java)",
     "source": "Telegram Dumps (模拟)",
     "snippet": "Full Git history, Jenkins credentials, "
                "Stripe API keys visible.",
     "severity": "high", "price_usd": 2500},
    {"category": "malware",
     "title": "Stealer token / RAT build 2026 (FUD)",
     "source": "XSS.is (模拟)",
     "snippet": "Token grabber + browser password stealer, "
                "weekly FUD pack.",
     "severity": "medium", "price_usd": 150},
    {"category": "hacker_service",
     "title": "DDoS stresser 1Tbps - 24h test, no logs",
     "source": "Stresser Market (模拟)",
     "snippet": "Layer4/7, API access, accepts crypto.",
     "severity": "medium", "price_usd": 50},
    {"category": "hacker_service",
     "title": "RDP / cPanel / WHM panel logins - bulk",
     "source": "Russian Market (模拟)",
     "snippet": "Fresh panels from Brazil/IN/ID, "
                "guaranteed 7 days.",
     "severity": "high", "price_usd": 25},
    {"category": "brand_mention",
     "title": "Fake login page: acme-corp-verify[.]xyz",
     "source": "PhishTank (模拟)",
     "snippet": "Clone of SSO login, harvests user@acme-corp.com",
     "severity": "critical", "price_usd": 0},
    {"category": "credential_leak",
     "title": "Collection #1 - mix12 (partial, 2.7GB)",
     "source": "RaidForums (模拟)",
     "snippet": "Generic combo lists, includes several "
                "@example.com corporate emails.",
     "severity": "high", "price_usd": 0},
    {"category": "data_sale",
     "title": "Healthcare patient records - 40k rows",
     "source": "BreachForums (模拟)",
     "snippet": "Name/DOB/SSN/insurance, csv.",
     "severity": "critical", "price_usd": 1200},
]


class DarkwebMonitorPhase:
    """阶段6: 暗网监控。"""

    def __init__(self) -> None:
        self._hits: Dict[str, DarkwebHit] = {}
        self._brands: List[str] = []
        self._alerts: List[Dict[str, Any]] = []
        self._configured_sources: List[str] = []

    # ------------------------------------------------------------------ #
    # 配置
    # ------------------------------------------------------------------ #
    def configure(self, brands: List[str],
                  tor_proxy: str = "",
                  custom_forums: Optional[List[str]] = None) -> Dict[str, Any]:
        self._brands = [b.lower() for b in brands if b]
        self._configured_sources = custom_forums or []
        return {
            "brands_watched": self._brands,
            "custom_forums": self._configured_sources,
            "tor_proxy": tor_proxy or "(未配置)",
            "mode": "simulation" if not tor_proxy else "configured",
            "note": ("未配置 Tor 代理/真实抓取器；以下为内置模拟框架兜底，"
                     "不代表真实暗网数据。") if not tor_proxy else
            "已配置抓取通道（由外部采集器接入）。",
        }

    # ------------------------------------------------------------------ #
    # 扫描（模拟 + 品牌/邮箱匹配）
    # ------------------------------------------------------------------ #
    def scan(self, domain: str = "",
             employee_emails: Optional[List[str]] = None) -> Dict[str, Any]:
        """扫描模拟暗网数据，匹配品牌/邮箱。"""
        hits: List[DarkwebHit] = []
        for raw in SIMULATED_POSTS:
            hit = DarkwebHit(
                hit_id=uuid.uuid4().hex[:12],
                category=raw["category"], title=raw["title"],
                source=raw["source"],
                url="http://" + uuid.uuid4().hex[:8] + ".onion",
                snippet=raw["snippet"],
                severity=raw["severity"],
                price_usd=raw.get("price_usd", 0),
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                simulated=True)
            # 品牌命中
            text = (raw["title"] + " " + raw["snippet"]).lower()
            for b in self._brands:
                if b and b in text:
                    hit.mentions_brand = b
                    hit.severity = "critical"
                    break
            # 邮箱/域名命中
            if domain and domain.lower() in text:
                hit.mentions_brand = hit.mentions_brand or domain
                hit.severity = "critical"
            hits.append(hit)
            self._hits[hit.hit_id] = hit
        # 凭证泄露: 员工邮箱匹配（模拟）
        emp = employee_emails or []
        for em in emp[:50]:
            if any(x in em.lower() for x in
                   [h.mentions_brand for h in hits if h.mentions_brand]):
                hits.append(DarkwebHit(
                    hit_id=uuid.uuid4().hex[:12],
                    category="credential_leak",
                    title=f"员工邮箱 {em} 出现在泄露列表",
                    source="模拟 Combolist",
                    url="", snippet=f"{em}:**** (hash/明文混合)",
                    severity="high", timestamp=time.strftime(
                        "%Y-%m-%d %H:%M:%S"), simulated=True))
                self._hits[hits[-1].hit_id] = hits[-1]
        # 自动告警
        crit = [h for h in hits if h.severity == "critical"]
        for h in crit:
            self._alerts.append({
                "alert_id": uuid.uuid4().hex[:12],
                "title": f"暗网 {h.category}: {h.title}",
                "severity": h.severity, "hit_id": h.hit_id,
                "timestamp": h.timestamp})
        return {
            "mode": "simulation_fallback",
            "note": "未配置真实 Tor/暗网抓取；返回内置模拟数据。",
            "scanned_posts": len(SIMULATED_POSTS),
            "hits": len(hits),
            "critical_alerts": len(crit),
            "items": [h.to_dict() for h in hits],
        }

    # ------------------------------------------------------------------ #
    # 品牌保护
    # ------------------------------------------------------------------ #
    def brand_protection(self) -> Dict[str, Any]:
        fake = [h for h in self._hits.values()
                if h.category == "brand_mention"]
        return {
            "watched_brands": self._brands,
            "fake_sites": [h.to_dict() for h in fake],
            "note": "真实环境应主动比对 DNS/WHOIS/PhishTank/Google Safe "
                    "Browsing；此处为模拟结果。",
        }

    # ------------------------------------------------------------------ #
    def list_hits(self, category: str = "") -> List[Dict[str, Any]]:
        out = list(self._hits.values())
        if category:
            out = [h for h in out if h.category == category]
        return [h.to_dict() for h in
                sorted(out, key=lambda x: x.timestamp, reverse=True)]

    def list_alerts(self) -> List[Dict[str, Any]]:
        return list(self._alerts)

    def stats(self) -> Dict[str, Any]:
        by_cat: Dict[str, int] = {}
        for h in self._hits.values():
            by_cat[h.category] = by_cat.get(h.category, 0) + 1
        return {
            "total_hits": len(self._hits),
            "by_category": by_cat,
            "alerts": len(self._alerts),
            "mode": "simulation_fallback",
            "brands_watched": len(self._brands),
        }


_phase: Optional[DarkwebMonitorPhase] = None


def get_darkweb_phase() -> DarkwebMonitorPhase:
    global _phase
    if _phase is None:
        _phase = DarkwebMonitorPhase()
    return _phase
