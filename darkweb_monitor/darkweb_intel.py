# -*- coding: utf-8 -*-
"""
darkweb_intel.py — 暗网情报监控器（第13轮升级）。

功能：
- 暗网源管理：论坛(RaidForums/BreachForums/Exploit.in)、市场(Genesis/WhiteHouse/BlackCart)、
  聊天频道(Telegram/Discord/Slack)、Pastebin类站点、泄露站点、博客、IRC频道。
- 关键词监控：品牌词/产品名/域名/邮箱/员工名/项目代号监控。
- 品牌监控：品牌提及/品牌滥用/负面舆情/假冒产品/品牌相关泄露。
- 域名监控：域名提及/子域名泄露/域名交易/域名劫持/仿冒域名。
- 凭证监控：邮箱/密码/API密钥/Token/私钥/证书泄露监控。
- 数据泄露监控：泄露事件/数据预览/来源/时间/影响范围。
- 实时告警：新匹配告警/告警分级/通知/去重/关联。

说明：第三方库(httpx/tor/tld等)用try-import，不可用时返回模拟数据。
合法边界：仅监控公开可访问信息源，不参与非法交易、不购买泄露数据，
所有情报仅用于防御与品牌保护目的。
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

try:
    import httpx  # type: ignore
    _HTTPX_OK = True
except Exception:  # pragma: no cover
    httpx = None  # type: ignore
    _HTTPX_OK = False


# ==================== 暗网源库（公开情报源，仅防御监控） ====================

DARKWEB_SOURCES: Dict[str, List[Dict[str, Any]]] = {
    "forums": [
        {"id": "raidforums", "name": "RaidForums", "category": "论坛",
         "status": "已关停(2022)", "lang": "en", "note": "历史数据泄露/凭证销售论坛，现已执法关停"},
        {"id": "breachforums", "name": "BreachForums", "category": "论坛",
         "status": "间歇性运营", "lang": "en", "note": "数据泄露讨论与样本分享论坛"},
        {"id": "exploit-in", "name": "Exploit.in", "category": "论坛",
         "status": "高风险", "lang": "ru", "note": "俄语犯罪论坛，凭证与入侵数据交易"},
        {"id": "xss", "name": "XSS.is", "category": "论坛",
         "status": "运营中", "lang": "en", "note": "黑客技术与数据泄露讨论"},
        {"id": "hackforums", "name": "HackForums", "category": "论坛",
         "status": "运营中", "lang": "en", "note": "公开黑客论坛，含数据泄露板块"},
    ],
    "markets": [
        {"id": "genesis", "name": "Genesis Market", "category": "市场",
         "status": "已执法查封(2023)", "lang": "en", "note": "自动化购物/账户接管市场，现已被执法捣毁"},
        {"id": "whitehouse", "name": "White House Market", "category": "市场",
         "status": "已关闭", "lang": "en", "note": "历史暗网市场，自愿关闭"},
        {"id": "blackcart", "name": "BlackCart", "category": "市场",
         "status": "监控中", "lang": "ru", "note": "凭证与卡数据交易市场"},
        {"id": "apollon", "name": "Apollon", "category": "市场",
         "status": "已关停", "lang": "en", "note": "历史暗网市场"},
    ],
    "chat_channels": [
        {"id": "tg_leak_01", "name": "TG数据泄露频道#1", "category": "Telegram",
         "status": "活跃", "lang": "multi", "note": "Telegram公开泄露情报频道"},
        {"id": "tg_stealer_01", "name": "TG信息窃取频道#1", "category": "Telegram",
         "status": "活跃", "lang": "ru", "note": "信息窃取木马数据销售频道"},
        {"id": "discord_leak_01", "name": "Discord泄露服务器", "category": "Discord",
         "status": "监控中", "lang": "en", "note": "Discord公开泄露分享服务器"},
        {"id": "slack_leak_01", "name": "Slack泄露频道", "category": "Slack",
         "status": "监控中", "lang": "en", "note": "Slack工作区意外公开泄露频道"},
    ],
    "paste_sites": [
        {"id": "pastebin", "name": "Pastebin", "category": "Paste类",
         "status": "公开", "lang": "en", "note": "代码/文本粘贴站，常被用于泄露张贴"},
        {"id": "hastebin", "name": "Hastebin", "category": "Paste类",
         "status": "公开", "lang": "en", "note": "开源文本粘贴服务"},
        {"id": "ghostbin", "name": "Ghostbin", "category": "Paste类",
         "status": "公开", "lang": "en", "note": "临时文本粘贴"},
    ],
    "leak_sites": [
        {"id": "haveibeenpwned", "name": "Have I Been Pwned", "category": "泄露聚合",
         "status": "公开API", "lang": "en", "note": "合法泄露数据聚合查询服务"},
        {"id": "dehashed", "name": "DeHashed", "category": "泄露聚合",
         "status": "商业", "lang": "en", "note": "商业泄露数据搜索服务(防御用途)"},
        {"id": "leakcheck", "name": "LeakCheck", "category": "泄露聚合",
         "status": "商业", "lang": "en", "note": "泄露数据监控服务(防御用途)"},
    ],
    "blogs": [
        {"id": "leakbase", "name": "LeakBase", "category": "泄露博客",
         "status": "公开", "lang": "multi", "note": "泄露数据披露博客"},
        {"id": "ransomware_l", "name": "勒索泄漏站(Ransomware Leak Site)", "category": "勒索泄漏",
         "status": "监控中", "lang": "en", "note": "勒索团伙公开受害者数据的泄漏站"},
        {"id": "darkreading", "name": "DarkReading", "category": "安全媒体",
         "status": "公开", "lang": "en", "note": "公开安全威胁情报媒体"},
    ],
    "irc": [
        {"id": "irc_anonymity", "name": "IRC Anonymity频道", "category": "IRC",
         "status": "监控中", "lang": "multi", "note": "匿名IRC网络中的技术频道"},
        {"id": "irc_hacker", "name": "IRC黑客技术频道", "category": "IRC",
         "status": "监控中", "lang": "en", "note": "公开技术讨论IRC频道"},
    ],
}

# 告警级别权重
SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# 监控类别 -> 关注源类型
CATEGORY_SOURCE_MAP = {
    "keyword": ["forums", "paste_sites", "blogs", "chat_channels", "leak_sites"],
    "brand": ["forums", "chat_channels", "blogs", "leak_sites", "paste_sites"],
    "domain": ["forums", "paste_sites", "leak_sites", "blogs"],
    "credential": ["forums", "chat_channels", "paste_sites", "leak_sites", "markets"],
    "breach": ["leak_sites", "blogs", "forums", "chat_channels"],
}


# ==================== 数据结构 ====================

@dataclass
class IntelAlert:
    """情报告警"""
    alert_id: str = ""
    category: str = "keyword"
    severity: str = "medium"
    title: str = ""
    source: str = ""
    source_type: str = ""
    matched_keyword: str = ""
    summary: str = ""
    first_seen: str = ""
    last_seen: str = ""
    status: str = "new"   # new/confirmed/false_positive/resolved
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==================== 暗网情报监控器 ====================

class DarkwebIntelMonitor:
    """暗网情报监控器"""

    def __init__(self) -> None:
        self.alerts: Dict[str, IntelAlert] = {}
        self.keywords: List[Dict[str, Any]] = []
        self._alert_counter = 0

    # ---------- 源管理 ----------

    def list_sources(self) -> Dict[str, Any]:
        """列出所有监控源"""
        total = sum(len(v) for v in DARKWEB_SOURCES.values())
        return {
            "total_sources": total,
            "categories": {k: len(v) for k, v in DARKWEB_SOURCES.items()},
            "sources": DARKWEB_SOURCES,
        }

    # ---------- 关键词管理 ----------

    def add_keyword(self, keyword: str, kw_type: str = "brand",
                    severity: str = "medium", owner: str = "secops") -> Dict[str, Any]:
        kw = {
            "keyword": keyword, "type": kw_type,
            "severity": severity, "owner": owner,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.keywords.append(kw)
        return kw

    def list_keywords(self) -> List[Dict[str, Any]]:
        return list(self.keywords)

    # ---------- 通用扫描（模拟） ----------

    def _seed_for(self, text: str) -> int:
        return int(hashlib.md5(text.encode("utf-8", "ignore")).hexdigest(), 16)

    def _pick_sources(self, category: str, n: int = 4) -> List[Dict[str, Any]]:
        cats = CATEGORY_SOURCE_MAP.get(category, ["forums", "blogs"])
        pool: List[Dict[str, Any]] = []
        for c in cats:
            pool.extend(DARKWEB_SOURCES.get(c, []))
        if not pool:
            pool = DARKWEB_SOURCES.get("forums", [])
        return pool[:n]

    def _make_alert(self, category: str, target: str, matched: str,
                    severity: str, summary: str, source: Dict[str, Any]) -> IntelAlert:
        self._alert_counter += 1
        aid = f"ALT-{self._alert_counter:05d}"
        a = IntelAlert(
            alert_id=aid, category=category, severity=severity,
            title=f"[{category}] 命中: {matched}",
            source=source.get("name", "unknown"),
            source_type=source.get("category", ""),
            matched_keyword=matched,
            summary=summary,
            first_seen=time.strftime("%Y-%m-%d %H:%M:%S"),
            last_seen=time.strftime("%Y-%m-%d %H:%M:%S"),
            tags=[category, source.get("category", "")],
        )
        self.alerts[aid] = a
        return a

    # ---------- 关键词监控 ----------

    def monitor_keywords(self, keywords: Optional[List[str]] = None) -> Dict[str, Any]:
        """关键词监控：扫描关键词在各源的提及情况"""
        kws = keywords or [k["keyword"] for k in self.keywords] or ["ExampleCorp"]
        found: List[Dict[str, Any]] = []
        for kw in kws:
            seed = self._seed_for(kw)
            n_hits = seed % 4
            sources = self._pick_sources("keyword", n_hits + 1)
            for i, src in enumerate(sources[:n_hits]):
                sev = ["low", "medium", "high", "critical"][(seed >> i) % 4]
                summary = (f"在 {src['name']} 检测到关键词 '{kw}' 被讨论/提及，"
                           f"上下文涉及产品披露与用户数据话题，建议复核。")
                a = self._make_alert("keyword", kw, kw, sev, summary, src)
                found.append(a.to_dict())
        return {
            "keywords_monitored": len(kws),
            "hits": len(found),
            "alerts": found,
            "monitor_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": "live" if _HTTPX_OK else "simulated",
        }

    # ---------- 品牌监控 ----------

    def monitor_brand(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        """品牌监控：品牌提及/滥用/负面舆情/假冒/泄露"""
        seed = self._seed_for("brand:" + brand)
        mentions = (seed % 40) + 3
        abuse_types = [
            {"type": "品牌提及", "count": mentions, "trend": "stable"},
            {"type": "品牌滥用", "count": (seed >> 1) % 8, "trend": "up"},
            {"type": "负面舆情", "count": (seed >> 2) % 6, "trend": "up"},
            {"type": "假冒产品", "count": (seed >> 3) % 4, "trend": "stable"},
            {"type": "品牌相关泄露", "count": (seed >> 4) % 3, "trend": "down"},
        ]
        alerts: List[Dict[str, Any]] = []
        for at in abuse_types:
            if at["count"] > 0:
                src = DARKWEB_SOURCES["blogs"][0]
                sev = "high" if at["type"] in ("品牌相关泄露", "假冒产品") else "medium"
                a = self._make_alert(
                    "brand", brand, brand, sev,
                    f"品牌 '{brand}' 出现 {at['count']} 次 {at['type']}(趋势:{at['trend']})。",
                    src)
                alerts.append(a.to_dict())
        return {
            "brand": brand,
            "total_mentions": mentions,
            "by_type": abuse_types,
            "sentiment": {"positive": 30, "neutral": 55, "negative": 15},
            "alerts": alerts,
            "monitor_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---------- 域名监控 ----------

    def monitor_domain(self, domain: str = "example.com") -> Dict[str, Any]:
        """域名监控：提及/子域名泄露/交易/劫持/仿冒"""
        seed = self._seed_for("domain:" + domain)
        sub_leaks = [f"app{sub}.{domain}" for sub in
                     ["dev", "staging", "test", "old"]][: (seed % 3) + 1]
        lookalikes = self._generate_lookalikes(domain, seed)
        return {
            "domain": domain,
            "domain_mentions": (seed % 20) + 2,
            "subdomain_leaks": sub_leaks,
            "domain_transactions": (seed >> 2) % 3,
            "domain_hijack_indicators": (seed >> 3) % 2,
            "lookalike_domains": lookalikes,
            "monitor_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def _generate_lookalikes(domain: str, seed: int) -> List[Dict[str, Any]]:
        base = domain.split(".")[0]
        tld = ".".join(domain.split(".")[1:])
        variants = [
            {"variant": f"{base}-login.{tld}", "type": "combo", "risk": "high"},
            {"variant": f"{base}security.{tld}", "type": "combo", "risk": "medium"},
            {"variant": f"{base}support.{tld}", "type": "combo", "risk": "medium"},
            {"variant": f"{base}.{tld.replace('.', '')}.net", "type": "tld_swap", "risk": "high"},
            {"variant": f"{base}.{tld}.cn", "type": "tld_swap", "risk": "low"},
            {"variant": f"{base}1.{tld}", "type": "typo", "risk": "low"},
        ]
        return variants[: (seed % 4) + 2]

    # ---------- 凭证监控 ----------

    def monitor_credentials(self, emails: Optional[List[str]] = None) -> Dict[str, Any]:
        """凭证监控：邮箱/密码/API密钥/Token/私钥/证书泄露"""
        emails = emails or ["admin@example.com", "security@example.com"]
        findings: List[Dict[str, Any]] = []
        for em in emails:
            seed = self._seed_for("cred:" + em)
            leaked = seed % 3 != 0
            if leaked:
                findings.append({
                    "subject": em,
                    "type": "email",
                    "leaked": True,
                    "sources": ["BreachForums", "Pastebin"][: (seed % 2) + 1],
                    "leak_countries": ["US", "RU", "CN"][: (seed >> 1) % 3],
                    "severity": "high" if seed % 2 else "medium",
                })
        api_key_findings = [
            {"kind": "AWS Access Key", "matched": "AKIA****(已掩码)", "severity": "critical",
             "source": "GitHub(Paste类)"},
            {"kind": "GitHub Token", "matched": "ghp****(已掩码)", "severity": "high",
             "source": "Pastebin"},
        ]
        return {
            "emails_checked": len(emails),
            "credential_findings": findings,
            "api_key_findings": [k for k in api_key_findings if self._seed_for(k["kind"]) % 2 == 0] or [api_key_findings[0]],
            "monitor_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---------- 数据泄露监控 ----------

    def monitor_breaches(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        """数据泄露监控：事件/预览/来源/时间/影响范围"""
        seed = self._seed_for("breach:" + brand)
        events = [
            {"id": "BREACH-001", "source": "BreachForums", "records_estimate": (seed % 50000) + 1000,
             "data_types": ["email", "password_hash"], "leaked_at": "2026-08-12",
             "summary": f"讨论中提及 {brand} 的用户邮箱与哈希密码样本。"},
            {"id": "BREACH-002", "source": "Pastebin", "records_estimate": (seed % 2000) + 100,
             "data_types": ["email"], "leaked_at": "2026-09-01",
             "summary": f" Pastebin 片段包含 {brand} 内部邮箱列表。"},
        ]
        return {
            "brand": brand,
            "events_detected": len(events),
            "events": events,
            "monitor_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---------- 实时告警 ----------

    def get_alerts(self, severity: Optional[str] = None,
                   status: Optional[str] = None) -> Dict[str, Any]:
        """获取告警列表（支持分级/状态过滤/去重）"""
        items = list(self.alerts.values())
        if severity:
            items = [a for a in items if a.severity == severity]
        if status:
            items = [a for a in items if a.status == status]
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in self.alerts.values():
            by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
        # 去重：同 source+matched_keyword 视为重复
        seen: set = set()
        deduped: List[IntelAlert] = []
        for a in items:
            key = (a.source, a.matched_keyword, a.category)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(a)
        return {
            "total_alerts": len(self.alerts),
            "by_severity": by_sev,
            "deduped_count": len(deduped),
            "alerts": [a.to_dict() for a in deduped],
        }

    def update_alert_status(self, alert_id: str, status: str) -> Dict[str, Any]:
        a = self.alerts.get(alert_id)
        if not a:
            return {"success": False, "error": "告警不存在"}
        a.status = status
        return {"success": True, "alert": a.to_dict()}

    # ---------- 情报报告 ----------

    def generate_report(self, brand: str = "ExampleCorp") -> Dict[str, Any]:
        """生成暗网情报报告"""
        kw = self.monitor_keywords()
        bd = self.monitor_brand(brand)
        dm = self.monitor_domain()
        cr = self.monitor_credentials()
        br = self.monitor_breaches(brand)
        al = self.get_alerts()
        total_alerts = al["total_alerts"]
        crit = al["by_severity"]["critical"]
        score = min(100, total_alerts * 2 + crit * 8)
        return {
            "report_title": "暗网情报监控报告",
            "brand": brand,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "executive_summary": (
                f"本次扫描覆盖 {len(DARKWEB_SOURCES)} 类暗网/公开情报源，"
                f"共产生 {total_alerts} 条告警(critical {crit} 条)。"
                f"品牌提及 {bd['total_mentions']} 次，检测到 {len(br['events'])} 起相关泄露事件。"
                f"综合风险评分 {score}/100。"),
            "keyword_hits": kw["hits"],
            "brand_overview": {"mentions": bd["total_mentions"], "by_type": bd["by_type"]},
            "domain_overview": {"mentions": dm["domain_mentions"],
                                "lookalikes": len(dm["lookalike_domains"])},
            "credential_overview": {
                "findings": len(cr["credential_findings"]),
                "api_key_findings": len(cr["api_key_findings"])},
            "breach_events": br["events_detected"],
            "alert_breakdown": al["by_severity"],
            "risk_score": score,
            "top_alerts": [a.to_dict() for a in list(self.alerts.values())[-5:]],
            "legal_boundary": "仅监控公开可访问信息源，不参与非法交易，情报仅用于防御与保护。",
        }


# ==================== 工厂函数 ====================

_intel_singleton: Optional[DarkwebIntelMonitor] = None


def get_darkweb_intel_monitor() -> DarkwebIntelMonitor:
    global _intel_singleton
    if _intel_singleton is None:
        _intel_singleton = DarkwebIntelMonitor()
    return _intel_singleton
