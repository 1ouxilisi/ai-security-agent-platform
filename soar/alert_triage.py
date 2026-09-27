#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar/alert_triage.py — 告警分诊与丰富。

覆盖：
    - 告警接入：归一化字段 (src_ip/dst_ip/user/asset/rule/raw)
    - 聚合与去重：按 (规则+源+资产) 时间窗聚合
    - 关联分析：多告警时间/实体关联
    - 风险评分：情报分 + 资产关键性 + 用户风险 + 规则严重度
    - 优先级排序与自动分诊
    - 上下文富化：威胁情报/资产/用户
    - 误报标记与反馈学习
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 规则严重度权重
# --------------------------------------------------------------------------- #
SEVERITY_WEIGHTS = {"info": 5, "low": 15, "medium": 35, "high": 65, "critical": 90}

# 资产关键性
ASSET_CRITICALITY = {"internet_facing": 80, "domain_controller": 95,
                     "database": 85, "workstation": 40, "iot": 55, "unknown": 30}

# 优先级阈值
PRIORITY_THRESHOLDS = [(80, "P1"), (60, "P2"), (40, "P3"), (0, "P4")]


class AlertTriage:
    """告警分诊引擎。"""

    def __init__(self) -> None:
        self.alerts: Dict[str, Dict[str, Any]] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.false_positives: Dict[str, Dict[str, Any]] = {}
        self.ti_feed = self._seed_threat_intel()
        self.asset_db = self._seed_assets()
        self.user_db = self._seed_users()

    # ---- 模拟数据 ----
    @staticmethod
    def _seed_threat_intel() -> Dict[str, Dict[str, Any]]:
        return {
            "203.0.113.66": {"score": 92, "tags": ["c2", "botnet"], "country": "RU"},
            "198.51.100.23": {"score": 78, "tags": ["scanner"], "country": "KP"},
            "104.16.80.5": {"score": 10, "tags": ["cdn"], "country": "US"},
            "malicious[.]example[.]com": {"score": 88, "tags": ["phishing"], "country": "CN"},
        }

    @staticmethod
    def _seed_assets() -> Dict[str, Dict[str, Any]]:
        return {
            "DC01": {"name": "主域控", "criticality": "domain_controller", "owner": "IT基础组"},
            "DB-PROD-01": {"name": "生产数据库", "criticality": "database", "owner": "DBA组"},
            "WEB-EXT-01": {"name": "对外Web", "criticality": "internet_facing", "owner": "Web组"},
            "PC-1024": {"name": "员工办公机", "criticality": "workstation", "owner": "市场部"},
        }

    @staticmethod
    def _seed_users() -> Dict[str, Dict[str, Any]]:
        return {
            "zhang.san": {"dept": "市场部", "risk_score": 30, "vip": False},
            "li.si": {"dept": "财务部", "risk_score": 45, "vip": True},
            "wang.wu": {"dept": "运维组", "risk_score": 70, "vip": False},
        }

    # ---- 接入与归一化 ----
    def ingest(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        alert_id = raw.get("alert_id") or f"ALT-{uuid.uuid4().hex[:10]}"
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        alert = {
            "alert_id": alert_id,
            "title": raw.get("title", "未命名告警"),
            "rule": raw.get("rule", "unknown"),
            "severity": raw.get("severity", "medium"),
            "src_ip": raw.get("src_ip", ""),
            "dst_ip": raw.get("dst_ip", ""),
            "user": raw.get("user", ""),
            "asset": raw.get("asset", "unknown"),
            "raw": raw.get("raw", {}),
            "status": "new",
            "ingested_at": now,
        }
        self.alerts[alert_id] = alert
        # 自动分诊
        enriched = self.enrich(alert_id)
        scored = self.score(alert_id)
        grouped = self.group(alert_id)
        alert["triage"] = {"enrichment": enriched, "score": scored,
                           "group": grouped, "priority": self._score_to_priority(scored["score"])}
        return alert

    def list_alerts(self, status: Optional[str] = None,
                    priority: Optional[str] = None,
                    limit: int = 100) -> List[Dict[str, Any]]:
        out = list(self.alerts.values())
        if status:
            out = [a for a in out if a["status"] == status]
        if priority:
            out = [a for a in out if a.get("triage", {}).get("priority") == priority]
        out.sort(key=lambda a: a.get("triage", {}).get("score", 0), reverse=True)
        return out[:limit]

    # ---- 富化 ----
    def enrich(self, alert_id: str) -> Dict[str, Any]:
        a = self.alerts.get(alert_id)
        if not a:
            return {}
        ti = self.ti_feed.get(a["src_ip"], {})
        asset = self.asset_db.get(a["asset"], {"criticality": "unknown", "name": a["asset"]})
        user = self.user_db.get(a["user"], {})
        result = {
            "threat_intel": ti,
            "asset": asset,
            "user": user,
            "geo": {"src_country": ti.get("country", "unknown")},
            "enriched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        a["enrichment"] = result
        return result

    # ---- 风险评分 ----
    def score(self, alert_id: str) -> Dict[str, Any]:
        a = self.alerts.get(alert_id)
        if not a:
            return {}
        sev_w = SEVERITY_WEIGHTS.get(a["severity"], 10)
        ti_score = (a.get("enrichment", {}).get("threat_intel", {}) or {}).get("score", 0)
        crit = (a.get("enrichment", {}).get("asset", {}) or {}).get("criticality", "unknown")
        crit_w = ASSET_CRITICALITY.get(crit, 30)
        user_risk = (a.get("enrichment", {}).get("user", {}) or {}).get("risk_score", 20)
        # 加权合成
        total = round(sev_w * 0.35 + ti_score * 0.30 + crit_w * 0.20 + user_risk * 0.15, 1)
        total = min(100.0, max(0.0, total))
        detail = {"severity_weight": sev_w, "threat_intel": ti_score,
                  "asset_criticality": crit_w, "user_risk": user_risk}
        result = {"score": total, "priority": self._score_to_priority(total), "detail": detail}
        a["score_detail"] = result
        return result

    @staticmethod
    def _score_to_priority(score: float) -> str:
        for threshold, label in PRIORITY_THRESHOLDS:
            if score >= threshold:
                return label
        return "P4"

    # ---- 聚合/去重 ----
    def group(self, alert_id: str, window_minutes: int = 30) -> Dict[str, Any]:
        a = self.alerts.get(alert_id)
        if not a:
            return {}
        key = f"{a['rule']}|{a['src_ip']}|{a['asset']}"
        g = self.groups.get(key)
        if not g:
            g = {"group_id": key, "rule": a["rule"], "src_ip": a["src_ip"],
                 "asset": a["asset"], "members": [], "count": 0,
                 "window_minutes": window_minutes, "first_seen": a["ingested_at"]}
            self.groups[key] = g
        g["members"].append(alert_id)
        g["count"] += 1
        g["last_seen"] = a["ingested_at"]
        return {"group_id": key, "count": g["count"]}

    def list_groups(self) -> List[Dict[str, Any]]:
        return sorted(self.groups.values(), key=lambda g: g["count"], reverse=True)

    # ---- 关联分析 ----
    def correlate(self, alert_id: str) -> List[Dict[str, Any]]:
        a = self.alerts.get(alert_id)
        if not a:
            return []
        related = []
        for other in self.alerts.values():
            if other["alert_id"] == alert_id:
                continue
            shared = 0
            if other["src_ip"] and other["src_ip"] == a["src_ip"]:
                shared += 1
            if other["user"] and other["user"] == a["user"]:
                shared += 1
            if other["asset"] and other["asset"] == a["asset"]:
                shared += 1
            if shared >= 2:
                related.append({"alert_id": other["alert_id"], "title": other["title"],
                                "shared_factors": shared, "severity": other["severity"]})
        related.sort(key=lambda r: r["shared_factors"], reverse=True)
        a["correlated"] = related[:10]
        return related[:10]

    # ---- 自动分诊决策 ----
    def auto_triage(self, alert_id: str) -> Dict[str, Any]:
        a = self.alerts.get(alert_id)
        if not a:
            return {"decision": "no_alert"}
        sc = a.get("score_detail", {}).get("score", 0)
        if sc >= 80:
            decision = "auto_respond"
            note = "高分告警，自动触发剧本并立即通知值班"
        elif sc >= 60:
            decision = "assign_analyst"
            note = "中高分，分派二线分析师 15 分钟内响应"
        elif sc >= 40:
            decision = "queue"
            note = "进入待分诊队列"
        else:
            decision = "suppress"
            note = "低分，进入抑制周期，7 天内不重复通知"
        result = {"decision": decision, "score": sc, "note": note,
                  "decided_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        a["auto_triage"] = result
        a["status"] = decision
        return result

    # ---- 误报反馈 ----
    def mark_false_positive(self, alert_id: str, reason: str = "",
                            analyst: str = "") -> Dict[str, Any]:
        a = self.alerts.get(alert_id)
        if not a:
            return {"success": False, "error": "告警不存在"}
        a["status"] = "false_positive"
        self.false_positives[alert_id] = {
            "alert_id": alert_id, "rule": a["rule"], "reason": reason,
            "analyst": analyst, "marked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"success": True, "fp_rule": a["rule"], "total_fp": len(self.false_positives)}

    def fp_stats(self) -> Dict[str, Any]:
        by_rule: Dict[str, int] = {}
        for fp in self.false_positives.values():
            by_rule[fp["rule"]] = by_rule.get(fp["rule"], 0) + 1
        return {"total_false_positives": len(self.false_positives),
                "by_rule": by_rule, "top_fp_rules": sorted(by_rule.items(), key=lambda x: -x[1])[:10]}

    # ---- 仪表盘 ----
    def dashboard(self) -> Dict[str, Any]:
        by_sev: Dict[str, int] = {}
        by_pri: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for a in self.alerts.values():
            by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
            pr = a.get("triage", {}).get("priority", "P4")
            by_pri[pr] = by_pri.get(pr, 0) + 1
            st = a["status"]
            by_status[st] = by_status.get(st, 0) + 1
        return {
            "total_alerts": len(self.alerts),
            "by_severity": by_sev, "by_priority": by_pri,
            "by_status": by_status, "groups": len(self.groups),
            "false_positives": len(self.false_positives),
        }


_SINGLETON: Optional[AlertTriage] = None


def get_alert_triage() -> AlertTriage:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = AlertTriage()
    return _SINGLETON


if __name__ == "__main__":  # pragma: no cover
    t = get_alert_triage()
    r = t.ingest({"title": "疑似 C2 连接", "rule": "c2_beacon", "severity": "critical",
                  "src_ip": "203.0.113.66", "asset": "WEB-EXT-01", "user": "wang.wu"})
    print(r["triage"])
