# -*- coding: utf-8 -*-
"""
competition_management_phase.py — 阶段1：赛事管理。

功能:
    - 创建赛事（名称/描述/开始结束时间/赛事类型/主办方）
    - 赛事配置（时间/题目/分值/队伍/规则/奖励）
    - 报名管理（个人/战队/审核/统计）
    - 实时排名配置
    - 赛事状态管理（未开始/进行中/已结束/已归档）
    - 赛事公告 / 规则管理
    - 赛事模板（可复用配置）
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# 赛事状态
COMPETITION_STATUSES = ("pending", "running", "finished", "archived")
# 赛事类型
COMPETITION_TYPES = ("Jeopardy", "Attack-Defense", "AWD",
                     "Mix", "邀请赛", "公开赛", "校内赛", "企业赛")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class Announcement:
    ann_id: str = ""
    title: str = ""
    content: str = ""
    level: str = "info"   # info/warning/critical
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ann_id": self.ann_id, "title": self.title,
                "content": self.content, "level": self.level,
                "created_at": self.created_at}


@dataclass
class Registration:
    reg_id: str = ""
    competition_id: str = ""
    participant_type: str = "team"   # individual/team
    name: str = ""                   # 个人名或战队名
    captain: str = ""
    members: List[str] = field(default_factory=list)
    contact: str = ""
    status: str = "pending"          # pending/approved/rejected
    registered_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"reg_id": self.reg_id,
                "competition_id": self.competition_id,
                "participant_type": self.participant_type,
                "name": self.name, "captain": self.captain,
                "members": self.members, "contact": self.contact,
                "status": self.status,
                "registered_at": self.registered_at}


@dataclass
class Competition:
    comp_id: str = ""
    name: str = ""
    description: str = ""
    start_time: str = ""
    end_time: str = ""
    comp_type: str = "Jeopardy"
    organizer: str = ""
    status: str = "pending"
    # 配置
    max_teams: int = 0               # 0=不限
    max_members_per_team: int = 5
    score_config: Dict[str, Any] = field(default_factory=dict)
    rules: str = ""
    rewards: List[str] = field(default_factory=list)
    ranking_config: Dict[str, Any] = field(default_factory=dict)
    announcements: List[Announcement] = field(default_factory=list)
    registrations: List[Registration] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        approved = sum(1 for r in self.registrations
                       if r.status == "approved")
        pending = sum(1 for r in self.registrations
                      if r.status == "pending")
        return {
            "comp_id": self.comp_id, "name": self.name,
            "description": self.description,
            "start_time": self.start_time, "end_time": self.end_time,
            "comp_type": self.comp_type, "organizer": self.organizer,
            "status": self.status,
            "max_teams": self.max_teams,
            "max_members_per_team": self.max_members_per_team,
            "score_config": self.score_config,
            "rules": self.rules, "rewards": self.rewards,
            "ranking_config": self.ranking_config,
            "announcements": [a.to_dict() for a in self.announcements],
            "reg_stats": {"total": len(self.registrations),
                          "approved": approved, "pending": pending},
            "created_at": self.created_at,
        }


class CompetitionManagementPhase:
    """阶段1：赛事管理。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._comps: Dict[str, Competition] = {}
        self._templates: Dict[str, Dict[str, Any]] = {}
        self._seed_templates()

    # ------------------------------------------------------------------ #
    def _seed_templates(self) -> None:
        self._templates = {
            "jeopardy_default": {
                "name": "Jeopardy 标准赛制模板",
                "comp_type": "Jeopardy",
                "max_members_per_team": 5,
                "score_config": {
                    "base_score": 100,
                    "dynamic_score": True,
                    "first_blood_bonus": 10,
                    "second_blood_bonus": 5,
                    "third_blood_bonus": 3,
                    "min_score_ratio": 0.5,
                },
                "rules": "一解一血，动态分值，禁止打靶与外联",
            },
            "awd_default": {
                "name": "AWD 攻防模板",
                "comp_type": "Attack-Defense",
                "max_members_per_team": 3,
                "score_config": {
                    "service_points": True,
                    "attack_points": True,
                    "defense_points": True,
                    "dynamic_score": False,
                },
                "rules": "每队防守自己靶机，攻击他队得分",
            },
            "training_default": {
                "name": "训练赛模板",
                "comp_type": "Mix",
                "max_members_per_team": 1,
                "score_config": {"dynamic_score": False, "base_score": 100},
                "rules": "单人训练，不计排名",
            },
        }

    # ------------------------------------------------------------------ #
    # 赛事 CRUD
    # ------------------------------------------------------------------ #
    def create_competition(self, name: str,
                           description: str = "",
                           start_time: str = "",
                           end_time: str = "",
                           comp_type: str = "Jeopardy",
                           organizer: str = "",
                           template: str = "") -> Dict[str, Any]:
        if not name:
            raise ValueError("赛事名称不能为空")
        tpl = self._templates.get(template, {})
        c = Competition(
            comp_id="ctf_" + uuid.uuid4().hex[:10],
            name=name, description=description,
            start_time=start_time or _now(),
            end_time=end_time,
            comp_type=comp_type or tpl.get("comp_type", "Jeopardy"),
            organizer=organizer,
            max_members_per_team=int(
                tpl.get("max_members_per_team", 5)),
            score_config=dict(tpl.get("score_config", {})),
            rules=tpl.get("rules", ""),
            ranking_config={"mode": "score_desc",
                            "tie_break": "last_solve_time"},
            created_at=_now(),
        )
        with self._lock:
            self._comps[c.comp_id] = c
        return c.to_dict()

    def list_competitions(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [c.to_dict() for c in
                    sorted(self._comps.values(),
                           key=lambda x: x.created_at, reverse=True)]

    def get_competition(self, comp_id: str
                        ) -> Optional[Competition]:
        return self._comps.get(comp_id)

    def update_config(self, comp_id: str,
                      config: Dict[str, Any]) -> Dict[str, Any]:
        c = self._comps.get(comp_id)
        if c is None:
            raise KeyError(f"赛事不存在: {comp_id}")
        for k in ("start_time", "end_time", "comp_type", "organizer",
                  "max_teams", "max_members_per_team", "rules",
                  "rewards", "ranking_config"):
            if k in config:
                setattr(c, k, config[k])
        if "score_config" in config:
            c.score_config.update(config["score_config"])
        return c.to_dict()

    def change_status(self, comp_id: str,
                      status: str) -> Dict[str, Any]:
        if status not in COMPETITION_STATUSES:
            raise ValueError(f"非法状态: {status}")
        c = self._comps.get(comp_id)
        if c is None:
            raise KeyError(f"赛事不存在: {comp_id}")
        c.status = status
        return c.to_dict()

    # ------------------------------------------------------------------ #
    # 公告 / 规则
    # ------------------------------------------------------------------ #
    def add_announcement(self, comp_id: str, title: str,
                        content: str,
                        level: str = "info") -> Dict[str, Any]:
        c = self._comps.get(comp_id)
        if c is None:
            raise KeyError(f"赛事不存在: {comp_id}")
        a = Announcement(ann_id="ann_" + uuid.uuid4().hex[:8],
                        title=title, content=content, level=level,
                        created_at=_now())
        c.announcements.append(a)
        return a.to_dict()

    def list_announcements(self, comp_id: str
                           ) -> List[Dict[str, Any]]:
        c = self._comps.get(comp_id)
        if c is None:
            return []
        return [a.to_dict() for a in
                sorted(c.announcements,
                       key=lambda x: x.created_at, reverse=True)]

    # ------------------------------------------------------------------ #
    # 报名
    # ------------------------------------------------------------------ #
    def register(self, comp_id: str, participant_type: str,
                 name: str, captain: str = "",
                 members: Optional[List[str]] = None,
                 contact: str = "") -> Dict[str, Any]:
        c = self._comps.get(comp_id)
        if c is None:
            raise KeyError(f"赛事不存在: {comp_id}")
        r = Registration(
            reg_id="reg_" + uuid.uuid4().hex[:8],
            competition_id=comp_id,
            participant_type=participant_type,
            name=name, captain=captain,
            members=members or [], contact=contact,
            registered_at=_now(),
        )
        c.registrations.append(r)
        return r.to_dict()

    def review_registration(self, reg_id: str,
                           approve: bool) -> Dict[str, Any]:
        for c in self._comps.values():
            for r in c.registrations:
                if r.reg_id == reg_id:
                    r.status = "approved" if approve else "rejected"
                    return r.to_dict()
        raise KeyError(f"报名记录不存在: {reg_id}")

    def registration_stats(self, comp_id: str
                           ) -> Dict[str, Any]:
        c = self._comps.get(comp_id)
        if c is None:
            return {}
        return c.to_dict()["reg_stats"]

    # ------------------------------------------------------------------ #
    # 模板
    # ------------------------------------------------------------------ #
    def list_templates(self) -> List[Dict[str, Any]]:
        out = []
        for tid, t in self._templates.items():
            out.append({"template_id": tid, **t})
        return out

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._comps)
            running = sum(1 for c in self._comps.values()
                          if c.status == "running")
            pending = sum(1 for c in self._comps.values()
                          if c.status == "pending")
            finished = sum(1 for c in self._comps.values()
                           if c.status == "finished")
            regs = sum(len(c.registrations)
                       for c in self._comps.values())
        return {"total": total, "running": running,
                "pending": pending, "finished": finished,
                "registrations": regs,
                "templates": len(self._templates)}


_default: Optional[CompetitionManagementPhase] = None


def get_competition_phase() -> CompetitionManagementPhase:
    global _default
    if _default is None:
        _default = CompetitionManagementPhase()
    return _default
