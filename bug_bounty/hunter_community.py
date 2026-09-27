#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hunter_community.py — 白帽与社区管理。

覆盖：
    - 白帽用户管理（注册/资料/技能标签/排名/信誉/历史提交/总奖金/注册时间/最后活跃/状态）
    - 排行榜（积分/奖金/有效漏洞数/响应速度/质量评分，月度/年度/总榜）
    - 白帽等级与权限（新手/认证/高级/核心：提交权限/奖励倍数/优先审核/徽章/专属任务）
    - 社区互动（评论/点赞/关注/私信/团队/讨论区/技术分享/Writeup公开）
    - 贡献者认可（月度之星/年度榜单/徽章/感谢信/实物/证书/公开致谢）
    - 争议处理（申诉/仲裁/管理员介入/争议记录/处理结果/流程/规则）

全部内存字典模拟。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


LEVELS = ["newbie", "certified", "advanced", "core"]
LEVEL_PERMS = {
    "newbie": {"max_submits_per_week": 20, "reward_multiplier": 1.0,
               "priority_review": False, "badges": [], "exclusive_tasks": False},
    "certified": {"max_submits_per_week": 100, "reward_multiplier": 1.1,
                  "priority_review": False, "badges": ["vetted"], "exclusive_tasks": False},
    "advanced": {"max_submits_per_week": 500, "reward_multiplier": 1.25,
                 "priority_review": True, "badges": ["vetted", "pro"], "exclusive_tasks": True},
    "core": {"max_submits_per_week": -1, "reward_multiplier": 1.5,
             "priority_review": True, "badges": ["vetted", "pro", "core"],
             "exclusive_tasks": True},
}
DISPUTE_STATUSES = ["open", "mediating", "resolved", "rejected"]


class _Store:
    def __init__(self) -> None:
        self.hunters: Dict[str, Dict[str, Any]] = {}
        self.interactions: Dict[str, List[Dict[str, Any]]] = {}
        self.teams: Dict[str, Dict[str, Any]] = {}
        self.writeups: Dict[str, Dict[str, Any]] = {}
        self.awards: Dict[str, List[Dict[str, Any]]] = {}
        self.disputes: Dict[str, Dict[str, Any]] = {}

    def reset(self) -> None:
        self.__init__()


STORE = _Store()


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# 白帽用户
# --------------------------------------------------------------------------- #
def register_hunter(payload: Dict[str, Any]) -> Dict[str, Any]:
    hid = payload.get("id") or _uid("h")
    h = {
        "id": hid,
        "nickname": payload.get("nickname", f"hunter_{hid[-6:]}"),
        "email": payload.get("email", ""),
        "bio": payload.get("bio", ""),
        "skill_tags": payload.get("skill_tags", []),
        "region": payload.get("region", ""),
        "level": payload.get("level", "newbie"),
        "reputation": payload.get("reputation", 0),
        "points": payload.get("points", 0),
        "total_bounty": 0.0,
        "submitted": 0, "valid": 0, "fixed": 0,
        "avg_quality": 0.0,
        "registered_at": _now(),
        "last_active": _now(),
        "status": payload.get("status", "active"),
        "followers": [], "following": [],
    }
    STORE.hunters[hid] = h
    STORE.interactions[hid] = []
    STORE.awards[hid] = []
    return h


def list_hunters(status: Optional[str] = None,
                 skill: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(STORE.hunters.values())
    if status:
        items = [h for h in items if h["status"] == status]
    if skill:
        items = [h for h in items if skill in h.get("skill_tags", [])]
    return items


def get_hunter(hid: str) -> Optional[Dict[str, Any]]:
    return STORE.hunters.get(hid)


def update_reputation(hid: str, delta: int, reason: str = "") -> Optional[Dict[str, Any]]:
    h = STORE.hunters.get(hid)
    if not h:
        return None
    h["reputation"] = max(0, h["reputation"] + delta)
    h["points"] = max(0, h["points"] + delta * 10)
    h["last_active"] = _now()
    STORE.interactions.setdefault(hid, []).append({
        "type": "reputation", "delta": delta, "reason": reason, "time": _now(),
    })
    return h


def touch_active(hid: str) -> None:
    h = STORE.hunters.get(hid)
    if h:
        h["last_active"] = _now()


# --------------------------------------------------------------------------- #
# 等级
# --------------------------------------------------------------------------- #
def level_up(hid: str) -> Optional[Dict[str, Any]]:
    h = STORE.hunters.get(hid)
    if not h:
        return None
    idx = LEVELS.index(h["level"]) if h["level"] in LEVELS else 0
    if idx < len(LEVELS) - 1:
        h["level"] = LEVELS[idx + 1]
    h["last_active"] = _now()
    return {"hunter": h, "permissions": LEVEL_PERMS[h["level"]]}


def get_permissions(level: str) -> Dict[str, Any]:
    return LEVEL_PERMS.get(level, LEVEL_PERMS["newbie"])


# --------------------------------------------------------------------------- #
# 排行榜
# --------------------------------------------------------------------------- #
def leaderboard(metric: str = "points", period: str = "all",
                limit: int = 20) -> List[Dict[str, Any]]:
    items = list(STORE.hunters.values())
    if metric not in ("points", "total_bounty", "valid", "quality"):
        metric = "points"
    key_map = {"points": "points", "total_bounty": "total_bounty",
               "valid": "valid", "quality": "avg_quality"}
    items.sort(key=lambda x: x.get(key_map[metric], 0), reverse=True)
    board = []
    for rank, h in enumerate(items[:limit], 1):
        board.append({
            "rank": rank, "hunter_id": h["id"], "nickname": h["nickname"],
            "level": h["level"], metric: h.get(key_map[metric], 0),
            "period": period, "region": h.get("region", ""),
        })
    return board


# --------------------------------------------------------------------------- #
# 社区互动
# --------------------------------------------------------------------------- #
def follow(follower_id: str, target_id: str) -> Dict[str, Any]:
    f, t = STORE.hunters.get(follower_id), STORE.hunters.get(target_id)
    if not f or not t:
        return {"ok": False, "reason": "用户不存在"}
    if target_id not in f["following"]:
        f["following"].append(target_id)
    if follower_id not in t["followers"]:
        t["followers"].append(follower_id)
    return {"ok": True, "following_count": len(f["following"]),
            "follower_count": len(t["followers"])}


def post_writeup(hunter_id: str, title: str, content: str,
                 tags: List[str], public: bool = True) -> Dict[str, Any]:
    wid = _uid("wu")
    w = {
        "id": wid, "hunter_id": hunter_id, "title": title, "content": content,
        "tags": tags, "public": public, "likes": 0, "views": 0,
        "created_at": _now(),
    }
    STORE.writeups[wid] = w
    return w


def list_writeups(public_only: bool = True) -> List[Dict[str, Any]]:
    items = list(STORE.writeups.values())
    if public_only:
        items = [w for w in items if w["public"]]
    return sorted(items, key=lambda x: x["created_at"], reverse=True)


def like_writeup(wid: str, user_id: str) -> Dict[str, Any]:
    w = STORE.writeups.get(wid)
    if not w:
        return {"ok": False}
    w["likes"] += 1
    return {"ok": True, "likes": w["likes"]}


def create_team(owner_id: str, name: str,
                members: Optional[List[str]] = None) -> Dict[str, Any]:
    tid = _uid("team")
    team = {"id": tid, "name": name, "owner": owner_id,
            "members": list(members or [owner_id]), "created_at": _now()}
    STORE.teams[tid] = team
    return team


def list_teams() -> List[Dict[str, Any]]:
    return list(STORE.teams.values())


# --------------------------------------------------------------------------- #
# 贡献者认可
# --------------------------------------------------------------------------- #
def grant_award(hunter_id: str, award_type: str,
                reason: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    a = {
        "id": _uid("award"), "type": award_type, "reason": reason,
        "meta": meta or {}, "time": _now(),
    }
    STORE.awards.setdefault(hunter_id, []).append(a)
    return a


def list_awards(hunter_id: str) -> List[Dict[str, Any]]:
    return STORE.awards.get(hunter_id, [])


def monthly_stars(year_month: Optional[str] = None) -> List[Dict[str, Any]]:
    ym = year_month or _now()[:7]
    items = sorted(STORE.hunters.values(),
                   key=lambda x: x.get("points", 0), reverse=True)[:3]
    return [{"rank": i + 1, "hunter_id": h["id"], "nickname": h["nickname"],
             "month": ym, "points": h["points"]}
            for i, h in enumerate(items)]


# --------------------------------------------------------------------------- #
# 争议处理
# --------------------------------------------------------------------------- #
def open_dispute(hunter_id: str, vuln_id: str, reason: str,
                 evidence: str = "") -> Dict[str, Any]:
    did = _uid("disp")
    d = {
        "id": did, "hunter_id": hunter_id, "vuln_id": vuln_id,
        "reason": reason, "evidence": evidence,
        "status": "open", "threads": [{
            "by": hunter_id, "body": reason, "time": _now(),
        }],
        "created_at": _now(),
    }
    STORE.disputes[did] = d
    return d


def resolve_dispute(did: str, result: str, note: str,
                    arbiter: str = "admin") -> Dict[str, Any]:
    d = STORE.disputes.get(did)
    if not d:
        return {"ok": False}
    d["status"] = "resolved" if result == "accept" else "rejected"
    d["result"] = result
    d["arbiter"] = arbiter
    d["resolved_note"] = note
    d["resolved_at"] = _now()
    return {"ok": True, "dispute": d}


def list_disputes(status: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(STORE.disputes.values())
    if status:
        items = [d for d in items if d["status"] == status]
    return items


# --------------------------------------------------------------------------- #
# 种子
# --------------------------------------------------------------------------- #
def seed_demo() -> None:
    if STORE.hunters:
        return
    register_hunter({
        "id": "hunter_001", "nickname": "p0wn_master",
        "skill_tags": ["web", "api", "idor"], "region": "北京",
        "level": "advanced", "reputation": 820, "points": 8200,
    })
    register_hunter({
        "id": "hunter_002", "nickname": "xss_lover",
        "skill_tags": ["web", "xss"], "region": "上海",
        "level": "certified", "reputation": 320, "points": 3200,
    })
    register_hunter({
        "id": "hunter_003", "nickname": "newbie_test",
        "skill_tags": ["recon"], "region": "深圳",
        "level": "newbie", "reputation": 10, "points": 100,
    })
