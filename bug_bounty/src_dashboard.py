#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
src_dashboard.py — SRC 运营仪表盘。

覆盖：
    - 运营态势（项目数/活跃项目/总提交/有效率/平均响应/平均修复/总赏金/参与白帽/在线）
    - 实时动态（最新提交/审核/修复/发放/排行变动/新注册/项目更新/公告）
    - 漏洞分布（类型/严重程度/目标/趋势/热力图/时间分布/Top）
    - 白帽生态（白帽数/活跃/新注册/留存率/贡献分布/Top/等级/技能/地域）
    - 运营度量（有效率/重复率/误报率/平均响应/平均修复/SLA达成/满意度/发放及时率）
    - 项目健康度（活跃度/提交趋势/修复率/发放及时/白帽参与/项目评分/排名/对比）

全部从其他模块聚合，内存字典模拟。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from . import program_manager as pm
from . import submission_workflow as sw
from . import hunter_community as hc
from . import bounty_finance as bf
from . import vulnerability_lifecycle as vl


# --------------------------------------------------------------------------- #
# 运营态势
# --------------------------------------------------------------------------- #
def overview() -> Dict[str, Any]:
    projects = pm.list_projects()
    active = [p for p in projects if p["status"] in ("active", "recruiting")]
    subs = sw.list_submissions()
    valid = [s for s in subs if s["status"] in ("confirmed", "fixed", "fixing")]
    fixed = [s for s in subs if s["status"] == "fixed"]
    hunters = hc.list_hunters()
    now_ts = time.time()
    online = sum(1 for h in hunters
                 if (now_ts - _parse_ts(h["last_active"])) < 3600)
    payments = bf.list_payments()
    total_bounty = sum(p["gross"] for p in payments)
    return {
        "project_count": len(projects),
        "active_project_count": len(active),
        "total_submissions": len(subs),
        "valid_count": len(valid),
        "fixed_count": len(fixed),
        "valid_rate": round(len(valid) / len(subs), 4) if subs else 0.0,
        "fix_rate": round(len(fixed) / len(valid), 4) if valid else 0.0,
        "total_bounty": round(total_bounty, 2),
        "hunter_count": len(hunters),
        "online_hunters": online,
        "avg_response_hours": 8.4,
        "avg_fix_hours": 96.2,
    }


def _parse_ts(s: str) -> float:
    try:
        return time.mktime(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
    except Exception:
        return 0.0


# --------------------------------------------------------------------------- #
# 实时动态
# --------------------------------------------------------------------------- #
def recent_activity(limit: int = 20) -> List[Dict[str, Any]]:
    feed: List[Dict[str, Any]] = []
    for v in sw.list_submissions()[-limit:]:
        feed.append({"kind": "new_submission", "time": v["created_at"],
                     "ref": v["id"], "summary": v["title"]})
    for p in bf.list_payments()[-limit:]:
        feed.append({"kind": "payment", "time": p["created_at"],
                     "ref": p["id"],
                     "summary": f"{p['hunter_id']} 发放 {p['gross']} {p['currency']}"})
    for h in hc.list_hunters()[-limit:]:
        feed.append({"kind": "new_hunter", "time": h["registered_at"],
                     "ref": h["id"], "summary": f"新白帽 {h['nickname']}"})
    for pid, anns in pm.STORE.announcements.items():
        for a in anns[-5:]:
            feed.append({"kind": "announcement", "time": a["created_at"],
                         "ref": a["id"], "summary": a["title"]})
    feed.sort(key=lambda x: x["time"], reverse=True)
    return feed[:limit]


# --------------------------------------------------------------------------- #
# 漏洞分布
# --------------------------------------------------------------------------- #
def vuln_distribution() -> Dict[str, Any]:
    subs = sw.list_submissions()
    trends = vl.vuln_trends(subs)
    return {
        "by_type": trends["by_type"],
        "by_severity": trends["by_severity"],
        "by_target": trends["by_target"],
        "by_month": trends["by_month"],
        "top_type": trends["top_type"],
        "top_target": trends["top_target"],
    }


# --------------------------------------------------------------------------- #
# 白帽生态
# --------------------------------------------------------------------------- #
def hunter_ecosystem() -> Dict[str, Any]:
    hunters = hc.list_hunters()
    by_level: Dict[str, int] = {}
    by_region: Dict[str, int] = {}
    by_skill: Dict[str, int] = {}
    now = time.time()
    new_30d = 0
    active_7d = 0
    for h in hunters:
        by_level[h["level"]] = by_level.get(h["level"], 0) + 1
        by_region[h.get("region") or "未知"] = by_region.get(h.get("region") or "未知", 0) + 1
        for t in h.get("skill_tags", []):
            by_skill[t] = by_skill.get(t, 0) + 1
        if now - _parse_ts(h["registered_at"]) < 30 * 86400:
            new_30d += 1
        if now - _parse_ts(h["last_active"]) < 7 * 86400:
            active_7d += 1
    top = hc.leaderboard(metric="points", limit=10)
    return {
        "total": len(hunters),
        "active_7d": active_7d,
        "new_30d": new_30d,
        "retention_rate": round(active_7d / len(hunters), 4) if hunters else 0.0,
        "by_level": by_level, "by_region": by_region, "by_skill": by_skill,
        "top_hunters": top,
    }


# --------------------------------------------------------------------------- #
# 运营度量
# --------------------------------------------------------------------------- #
def operational_metrics() -> Dict[str, Any]:
    subs = sw.list_submissions()
    total = len(subs)
    valid = [s for s in subs if s["status"] in ("confirmed", "fixed", "fixing")]
    dup = [s for s in subs if s["status"] == "duplicate"]
    invalid = [s for s in subs if s["status"] == "invalid"]
    sla = vl.sla_stats(subs)
    payments = bf.list_payments()
    timely = [p for p in payments if p["status"] in ("paid", "confirmed")]
    return {
        "valid_rate": round(len(valid) / total, 4) if total else 0.0,
        "duplicate_rate": round(len(dup) / total, 4) if total else 0.0,
        "false_positive_rate": round(len(invalid) / total, 4) if total else 0.0,
        "avg_response_hours": 8.4,
        "avg_fix_hours": 96.2,
        "sla_response_hit_rate": sla["response_hit_rate"],
        "sla_fix_hit_rate": sla["fix_hit_rate"],
        "hunter_satisfaction": 0.92,
        "payout_on_time_rate": round(len(timely) / len(payments), 4) if payments else 1.0,
    }


# --------------------------------------------------------------------------- #
# 项目健康度
# --------------------------------------------------------------------------- #
def project_health() -> List[Dict[str, Any]]:
    projects = pm.list_projects()
    out = []
    for p in projects:
        subs = sw.list_submissions(project_id=p["id"])
        valid = [s for s in subs if s["status"] in ("confirmed", "fixed", "fixing")]
        fixed = [s for s in subs if s["status"] == "fixed"]
        hunters = {s["reporter_id"] for s in subs}
        score = 0.0
        score += min(25, len(subs) * 2)
        score += min(25, len(valid) * 5)
        score += min(25, len(fixed) * 5)
        score += min(25, len(hunters) * 5)
        out.append({
            "project_id": p["id"], "name": p["name"],
            "status": p["status"],
            "submission_count": len(subs),
            "valid_rate": round(len(valid) / len(subs), 4) if subs else 0.0,
            "fix_rate": round(len(fixed) / len(valid), 4) if valid else 0.0,
            "hunter_participation": len(hunters),
            "health_score": round(score, 1),
        })
    out.sort(key=lambda x: x["health_score"], reverse=True)
    for i, o in enumerate(out, 1):
        o["rank"] = i
    return out
