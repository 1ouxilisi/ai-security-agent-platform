# -*- coding: utf-8 -*-
"""
intel_dashboard.py — 威胁情报控制台聚合（第23轮升级方向3）。

功能：
- 情报总览：情报源数/IOC数/漏洞数/威胁Actor数/告警数/匹配数/趋势
- 情报管理：情报源/IOC/漏洞/Actor/TTPs/情报搜索
- 攻击面管理：资产/画像/分析/风险/变更/报告
- 告警中心：列表/详情/分级/处理/通知/统计（规则引擎+分级）
- 威胁狩猎：查询/模板/结果/报告/历史
- 系统设置：情报源配置/匹配规则/告警规则/通知/数据保留/API/审计

聚合调用 intel_sources / ioc_manager / attack_surface / vuln_intel / threat_actor。
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from threat_intel.intel_sources import get_intel_source_manager
from threat_intel.ioc_manager import get_ioc_manager
from threat_intel.attack_surface import get_attack_surface_manager
from threat_intel.vuln_intel import get_vuln_intel_manager
from threat_intel.threat_actor import get_threat_actor_manager


# ==================== 告警规则引擎 ====================

DEFAULT_ALERT_RULES: List[Dict[str, Any]] = [
    {"id": "rule-critical-ioc", "name": "关键IOC命中",
     "condition": "ioc.severity == critical", "level": "critical",
     "notify": ["email", "webhook"], "enabled": True},
    {"id": "rule-0day", "name": "0day/在野利用",
     "condition": "vuln.in_the_wild == true", "level": "critical",
     "notify": ["email", "sms"], "enabled": True},
    {"id": "rule-cert-expiry", "name": "证书7天内过期",
     "condition": "asset.cert_expires_days < 7", "level": "high",
     "notify": ["email"], "enabled": True},
    {"id": "rule-new-asset", "name": "新增暴露资产",
     "condition": "asset.changed == new", "level": "medium",
     "notify": ["webhook"], "enabled": True},
]

HUNT_TEMPLATES: List[Dict[str, Any]] = [
    {"id": "tpl-phish", "name": "钓鱼邮件投递狩猎", "mode": "ttp",
     "query": "T1566", "description": "检索近期钓鱼投递与落地"},
    {"id": "tpl-bruteforce", "name": "暴力破解登录狩猎", "mode": "hypothesis",
     "query": "异常RDP/SSH登录", "description": "多次失败后成功的登录行为"},
    {"id": "tpl-c2", "name": "C2外联狩猎", "mode": "ioc",
     "query": "已知C2 IP/域名", "description": "出站连接命中IOC库"},
]


class IntelDashboard:
    """威胁情报控制台聚合层。"""

    def __init__(self) -> None:
        self.sources = get_intel_source_manager()
        self.iocs = get_ioc_manager()
        self.surface = get_attack_surface_manager()
        self.vulns = get_vuln_intel_manager()
        self.actors = get_threat_actor_manager()
        self.alerts: List[Dict[str, Any]] = []
        self.rules: List[Dict[str, Any]] = list(DEFAULT_ALERT_RULES)
        self.settings: Dict[str, Any] = {
            "data_retention_days": 90,
            "notify_channels": ["email", "webhook"],
            "auto_match": True,
            "min_confidence": 60,
            "api_enabled": True,
            "audit_enabled": True,
        }
        self.audit_log: List[Dict[str, Any]] = []

    @staticmethod
    def _now(days: int = 0) -> str:
        return (datetime.now() - timedelta(days=days)).isoformat()

    # ---------- 总览 ----------
    def overview(self) -> Dict[str, Any]:
        src = self.sources.stats()
        ioc = self.iocs.stats()
        surf = self.surface.stats()
        vuln = self.vulns.stats()
        act = self.actors.stats()
        alert_count = len(self.alerts)
        # 趋势（近7天模拟）
        trend = [{"day": (datetime.now() - timedelta(days=i)).strftime("%m-%d"),
                  "iocs": 100 + i * 3, "alerts": 5 + i} for i in range(6, -1, -1)]
        return {
            "cards": {
                "sources": src["sources_total"],
                "iocs": ioc["total"],
                "vulns": vuln["total"],
                "actors": act["total_actors"],
                "alerts": alert_count,
                "matches": ioc["total_hits"],
                "assets": surf["total_assets"],
                "high_exposed": surf["high_exposed"],
            },
            "trend": trend,
            "severity_dist": ioc["by_severity"],
            "groups": src["groups"],
        }

    # ---------- 告警中心（规则引擎） ----------
    def evaluate_alerts(self) -> List[Dict[str, Any]]:
        """运行规则引擎生成告警。"""
        new_alerts = []
        # 关键IOC
        for ioc in self.iocs.list_iocs(severity="critical"):
            new_alerts.append(self._mk_alert(
                "critical", "ioc_hit",
                f"关键IOC命中: {ioc['value']}",
                {"ioc_id": ioc["id"], "value": ioc["value"]}))
        # 0day在野利用
        for v in self.vulns.list_vulns(in_the_wild=True):
            new_alerts.append(self._mk_alert(
                "critical", "0day",
                f"在野利用: {v['cve']} {v['title']}",
                {"cve": v["cve"]}))
        # 证书过期
        sa = self.surface.monitor_tick()
        for a in sa.get("alerts", []):
            new_alerts.append(self._mk_alert(
                a["level"], a["type"], a["message"], {"asset_id": a.get("asset_id")}))
        self.alerts.extend(new_alerts)
        return new_alerts

    def _mk_alert(self, level: str, atype: str, message: str,
                  ref: Dict[str, Any]) -> Dict[str, Any]:
        return {"id": f"alt-{uuid.uuid4().hex[:8]}", "time": self._now(),
                "level": level, "type": atype, "message": message,
                "ref": ref, "status": "open", "notified": False}

    def list_alerts(self, level: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict[str, Any]]:
        out = self.alerts
        if level:
            out = [a for a in out if a["level"] == level]
        if status:
            out = [a for a in out if a["status"] == status]
        return out

    def handle_alert(self, alert_id: str, action: str = "close",
                     note: str = "") -> Dict[str, Any]:
        for a in self.alerts:
            if a["id"] == alert_id:
                a["status"] = "closed" if action == "close" else "ack"
                a["handle_note"] = note
                self._audit("handle_alert", alert_id, action)
                return a
        raise KeyError(f"告警不存在: {alert_id}")

    def notify(self, alert_id: str) -> Dict[str, Any]:
        for a in self.alerts:
            if a["id"] == alert_id:
                a["notified"] = True
                return {"alert_id": alert_id, "sent": True,
                        "channels": self.settings["notify_channels"]}
        raise KeyError(f"告警不存在: {alert_id}")

    def alert_stats(self) -> Dict[str, Any]:
        level: Dict[str, int] = {}
        status: Dict[str, int] = {}
        for a in self.alerts:
            level[a["level"]] = level.get(a["level"], 0) + 1
            status[a["status"]] = status.get(a["status"], 0) + 1
        return {"total": len(self.alerts), "by_level": level,
                "by_status": status}

    # ---------- 狩猎 ----------
    def hunt_templates(self) -> List[Dict[str, Any]]:
        return HUNT_TEMPLATES

    def run_hunt(self, template_id: str = "", mode: str = "ttp",
                 query: str = "") -> Dict[str, Any]:
        tpl = next((t for t in HUNT_TEMPLATES if t["id"] == template_id), None)
        if tpl:
            mode, query = tpl["mode"], tpl["query"]
        result = self.actors.hunt(mode=mode, query=query)
        self._audit("hunt", query, mode)
        return {"template": tpl["name"] if tpl else None, **result}

    # ---------- 全局搜索 ----------
    def global_search(self, q: str) -> Dict[str, Any]:
        return {
            "iocs": self.iocs.list_iocs(q=q),
            "vulns": self.vulns.list_vulns(q=q),
            "actors": self.actors.list_actors(q=q),
            "feeds": self.sources.query(q=q),
            "assets": self.surface.list_assets(q=q),
        }

    # ---------- 设置 ----------
    def get_settings(self) -> Dict[str, Any]:
        return {"settings": self.settings, "rules": self.rules}

    def update_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        self.settings.update(patch or {})
        self._audit("update_settings", str(patch or {}), "")
        return self.settings

    def add_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        rule["id"] = rule.get("id") or f"rule-{uuid.uuid4().hex[:6]}"
        self.rules.append(rule)
        return rule

    def delete_rule(self, rule_id: str) -> Dict[str, Any]:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r["id"] != rule_id]
        return {"deleted": before - len(self.rules)}

    # ---------- 审计 ----------
    def _audit(self, action: str, target: str, detail: str) -> None:
        if self.settings.get("audit_enabled"):
            self.audit_log.append({"time": self._now(), "action": action,
                                  "target": target, "detail": detail})

    def list_audit(self) -> List[Dict[str, Any]]:
        return self.audit_log[-100:]

    # ---------- 数据保留清理 ----------
    def cleanup(self) -> Dict[str, Any]:
        days = self.settings.get("data_retention_days", 90)
        expired_ioc = self.iocs.expire()
        self.sources.expire_and_archive()
        return {"retention_days": days, "ioc_expired": expired_ioc,
                "audit_entries": len(self.audit_log)}


_dashboard: Optional[IntelDashboard] = None


def get_intel_dashboard() -> IntelDashboard:
    global _dashboard
    if _dashboard is None:
        _dashboard = IntelDashboard()
    return _dashboard
