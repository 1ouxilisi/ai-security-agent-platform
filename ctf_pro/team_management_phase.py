# -*- coding: utf-8 -*-
"""
team_management_phase.py — 阶段8：战队管理。

功能:
    - 战队创建（名称/Logo/描述/宣言）
    - 成员管理（加入/退出/踢出/职位/权限）
    - 训练计划（日常/赛前集训/专项）
    - 比赛记录（参赛历史/成绩/排名）
    - 战队排名（积分/胜率/解题数）
    - 战队统计 / 公告 / 申请审核
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

ROLES = ("captain", "vice", "member")
PERMISSIONS = ("admin", "edit", "view")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class Member:
    uid: str = ""
    name: str = ""
    role: str = "member"
    permission: str = "view"
    joined_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"uid": self.uid, "name": self.name,
                "role": self.role, "permission": self.permission,
                "joined_at": self.joined_at}


@dataclass
class Team:
    team_id: str = ""
    name: str = ""
    logo: str = ""
    description: str = ""
    manifesto: str = ""
    members: List[Member] = field(default_factory=list)
    training_plan: Dict[str, Any] = field(default_factory=dict)
    match_history: List[Dict[str, Any]] = field(default_factory=list)
    announcements: List[Dict[str, Any]] = field(default_factory=list)
    applicants: List[Dict[str, Any]] = field(default_factory=list)
    score: int = 0
    wins: int = 0
    solved: int = 0
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"team_id": self.team_id, "name": self.name,
                "logo": self.logo, "description": self.description,
                "manifesto": self.manifesto,
                "members": [m.to_dict() for m in self.members],
                "member_count": len(self.members),
                "training_plan": self.training_plan,
                "match_history": self.match_history,
                "announcements": self.announcements,
                "applicants": self.applicants,
                "score": self.score, "wins": self.wins,
                "solved": self.solved,
                "win_rate": round(
                    self.wins / max(1, len(self.match_history)), 2),
                "created_at": self.created_at}


class TeamManagementPhase:
    """阶段8：战队管理。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._teams: Dict[str, Team] = {}

    # ------------------------------------------------------------------ #
    def create_team(self, name: str, captain: str,
                   logo: str = "", description: str = "",
                   manifesto: str = "") -> Dict[str, Any]:
        if not name or not captain:
            raise ValueError("战队名与队长不能为空")
        t = Team(team_id="tm_" + uuid.uuid4().hex[:10],
                 name=name, logo=logo, description=description,
                 manifesto=manifesto, created_at=_now())
        t.members.append(Member(uid="u_" + uuid.uuid4().hex[:8],
                                name=captain, role="captain",
                                permission="admin", joined_at=_now()))
        with self._lock:
            self._teams[t.team_id] = t
        return t.to_dict()

    def get_team(self, team_id: str) -> Optional[Team]:
        return self._teams.get(team_id)

    def list_teams(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in
                sorted(self._teams.values(),
                       key=lambda x: x.score, reverse=True)]

    # ------------------------------------------------------------------ #
    def add_member(self, team_id: str, uid: str, name: str,
                   role: str = "member",
                   permission: str = "view") -> Dict[str, Any]:
        t = self._teams.get(team_id)
        if t is None:
            raise KeyError(f"战队不存在: {team_id}")
        m = Member(uid=uid, name=name, role=role,
                   permission=permission, joined_at=_now())
        t.members.append(m)
        return m.to_dict()

    def remove_member(self, team_id: str, uid: str) -> Dict[str, Any]:
        t = self._teams.get(team_id)
        if t is None:
            raise KeyError(f"战队不存在: {team_id}")
        before = len(t.members)
        t.members = [m for m in t.members if m.uid != uid]
        return {"team_id": team_id, "removed": before - len(t.members)}

    def set_role(self, team_id: str, uid: str,
                 role: str, permission: str = "") -> Dict[str, Any]:
        if role not in ROLES:
            raise ValueError(f"非法职位: {role}")
        t = self._teams.get(team_id)
        if t is None:
            raise KeyError(f"战队不存在: {team_id}")
        for m in t.members:
            if m.uid == uid:
                m.role = role
                if permission:
                    m.permission = permission
                return m.to_dict()
        raise KeyError(f"成员不存在: {uid}")

    # ------------------------------------------------------------------ #
    def apply_join(self, team_id: str, uid: str,
                   name: str) -> Dict[str, Any]:
        t = self._teams.get(team_id)
        if t is None:
            raise KeyError(f"战队不存在: {team_id}")
        app = {"uid": uid, "name": name, "status": "pending",
               "applied_at": _now()}
        t.applicants.append(app)
        return app

    def review_application(self, team_id: str, uid: str,
                          approve: bool) -> Dict[str, Any]:
        t = self._teams.get(team_id)
        if t is None:
            raise KeyError(f"战队不存在: {team_id}")
        for a in t.applicants:
            if a["uid"] == uid:
                a["status"] = "approved" if approve else "rejected"
                if approve:
                    self.add_member(team_id, uid, a["name"])
                return a
        raise KeyError(f"申请不存在: {uid}")

    # ------------------------------------------------------------------ #
    def set_training_plan(self, team_id: str, plan_type: str,
                        schedule: str, focus: str) -> Dict[str, Any]:
        t = self._teams.get(team_id)
        if t is None:
            raise KeyError(f"战队不存在: {team_id}")
        t.training_plan = {"type": plan_type, "schedule": schedule,
                          "focus": focus, "updated_at": _now()}
        return t.training_plan

    def record_match(self, team_id: str, comp_name: str,
                    rank: int, score: int,
                    solved: int) -> Dict[str, Any]:
        t = self._teams.get(team_id)
        if t is None:
            raise KeyError(f"战队不存在: {team_id}")
        rec = {"competition": comp_name, "rank": rank,
               "score": score, "solved": solved,
               "recorded_at": _now()}
        t.match_history.append(rec)
        t.score += score
        t.solved += solved
        if rank == 1:
            t.wins += 1
        return rec

    def add_announcement(self, team_id: str, title: str,
                        content: str) -> Dict[str, Any]:
        t = self._teams.get(team_id)
        if t is None:
            raise KeyError(f"战队不存在: {team_id}")
        a = {"title": title, "content": content,
             "created_at": _now()}
        t.announcements.append(a)
        return a

    # ------------------------------------------------------------------ #
    def ranking(self) -> List[Dict[str, Any]]:
        rows = self.list_teams()
        for i, r in enumerate(rows, 1):
            r["rank"] = i
        return rows

    def stats(self) -> Dict[str, Any]:
        total = len(self._teams)
        members = sum(len(t.members) for t in self._teams.values())
        return {"total_teams": total, "total_members": members,
                "avg_members": round(members / max(1, total), 1)}


_default: Optional[TeamManagementPhase] = None


def get_team_phase() -> TeamManagementPhase:
    global _default
    if _default is None:
        _default = TeamManagementPhase()
    return _default
