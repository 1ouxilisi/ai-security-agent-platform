# -*- coding: utf-8 -*-
"""ctf_platform.team_manager — 战队与团队管理模块。

战队 CRUD、成员、赛事、排名、资源、对抗。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


ROLES = {"leader": "队长", "member": "队员", "reserve": "候补"}


class TeamManager:
    def __init__(self) -> None:
        self.teams: Dict[str, Dict[str, Any]] = {}
        self.duels: List[Dict[str, Any]] = []
        self._seed()

    def _seed(self) -> None:
        demo = [
            ("NightWarriors", "老牌攻防强队", "leader"),
            ("0xBinary", "二进制专项", "member"),
            ("PinkTeam", "女性战队", "member"),
        ]
        for idx, (name, desc, role) in enumerate(demo, 1):
            tid = f"team_{3000 + idx}"
            self.teams[tid] = {
                "id": tid, "name": name, "description": desc,
                "logo_url": "", "announcement": "欢迎加入",
                "public": True, "type": "official",
                "members": [{"username": f"user_{idx}", "role": role,
                             "score": 500 - idx * 50, "active_days": 30,
                             "skills": ["Web"]}],
                "tags": ["CTF"], "score": 1500 - idx * 120,
                "matches_won": idx * 2, "matches_lost": idx,
                "created_at": _now(),
            }

    # ------------------------------------------------------------------ #
    # 战队 CRUD
    # ------------------------------------------------------------------ #
    def list_teams(self, keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.teams.values())
        if keyword:
            kw = keyword.lower()
            items = [t for t in items
                     if kw in t["name"].lower() or kw in t["description"].lower()]
        items.sort(key=lambda x: x["score"], reverse=True)
        for i, t in enumerate(items, 1):
            t["rank"] = i
        return items

    def get_team(self, tid: str) -> Optional[Dict[str, Any]]:
        return self.teams.get(tid)

    def create_team(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        tid = _uid("team")
        leader = payload.get("leader", "admin")
        team = {
            "id": tid, "name": payload.get("name", "新战队"),
            "description": payload.get("description", ""),
            "logo_url": payload.get("logo_url", ""),
            "announcement": payload.get("announcement", ""),
            "public": bool(payload.get("public", True)),
            "type": payload.get("type", "community"),
            "members": [{"username": leader, "role": "leader",
                         "score": 0, "active_days": 0, "skills": []}],
            "tags": payload.get("tags", []),
            "score": 0, "matches_won": 0, "matches_lost": 0,
            "created_at": _now(),
        }
        self.teams[tid] = team
        return team

    # ------------------------------------------------------------------ #
    # 成员
    # ------------------------------------------------------------------ #
    def invite_member(self, tid: str, username: str) -> Dict[str, Any]:
        t = self.teams.get(tid)
        if not t:
            return {"error": "战队不存在"}
        if any(m["username"] == username for m in t["members"]):
            return {"error": "已是成员"}
        t["members"].append({"username": username, "role": "member",
                             "score": 0, "active_days": 0, "skills": []})
        return t

    def remove_member(self, tid: str, username: str) -> bool:
        t = self.teams.get(tid)
        if not t:
            return False
        before = len(t["members"])
        t["members"] = [m for m in t["members"]
                        if not (m["username"] == username and m["role"] != "leader")]
        return len(t["members"]) < before

    # ------------------------------------------------------------------ #
    # 对抗
    # ------------------------------------------------------------------ #
    def challenge(self, tid_a: str, tid_b: str,
                  arena: str = "practice") -> Dict[str, Any]:
        a = self.teams.get(tid_a)
        b = self.teams.get(tid_b)
        if not a or not b:
            return {"error": "战队不存在"}
        duel = {
            "id": _uid("duel"), "team_a": a["name"], "team_b": b["name"],
            "arena": arena, "status": "pending",
            "score_a": 0, "score_b": 0,
            "at": _now(),
        }
        self.duels.append(duel)
        return duel

    def settle_duel(self, duel_id: str, winner: str) -> Optional[Dict[str, Any]]:
        d = next((x for x in self.duels if x["id"] == duel_id), None)
        if not d:
            return None
        d["status"] = "settled"
        d["winner"] = winner
        d["settled_at"] = _now()
        for t in self.teams.values():
            if t["name"] in (d["team_a"], d["team_b"]):
                if t["name"] == winner:
                    t["matches_won"] += 1
                    t["score"] += 100
                else:
                    t["matches_lost"] += 1
        return d

    def duel_history(self) -> List[Dict[str, Any]]:
        return self.duels[-50:]

    def resource_share(self, tid: str) -> Dict[str, Any]:
        t = self.teams.get(tid)
        if not t:
            return {"error": "战队不存在"}
        return {"team_id": tid, "shared_challenges": [],
                "shared_tools": ["Burp", "Ghidra", "pwntools"],
                "training_plan": "每周 2 次队内训练",
                "documents": []}


_team_singleton: Optional[TeamManager] = None


def get_team_manager() -> TeamManager:
    global _team_singleton
    if _team_singleton is None:
        _team_singleton = TeamManager()
    return _team_singleton
