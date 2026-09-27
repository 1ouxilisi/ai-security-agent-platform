# -*- coding: utf-8 -*-
"""ctf_platform.competition_manager — 竞赛与赛事管理模块。

支持 Jeopardy / Attack-Defense / King of the Hill / 混合赛制，
报名、实时排名、监控与复盘全部内存模拟。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


FORMATS = [
    {"key": "jeopardy", "name": "Jeopardy 解题赛",
     "desc": "按解题得分排名，一血/二血/三血加成"},
    {"key": "attack_defense", "name": "Attack-Defense 攻防赛",
     "desc": "队伍互相攻击对方靶机，同时防守自身"},
    {"key": "king_of_hill", "name": "King of the Hill 王位赛",
     "desc": "持续占据目标机得分"},
    {"key": "mixed", "name": "混合赛", "desc": "多赛制组合"},
]

STATUSES = ["draft", "registration", "running", "paused", "finished", "archived"]
PRIZE_TIERS = [
    {"rank": 1, "prize": "冠军", "bonus_score": 1000},
    {"rank": 2, "prize": "亚军", "bonus_score": 600},
    {"rank": 3, "prize": "季军", "bonus_score": 300},
]


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


class CompetitionManager:
    def __init__(self) -> None:
        self.events: Dict[str, Dict[str, Any]] = {}
        self.registrations: Dict[str, List[Dict[str, Any]]] = {}
        self.rankings: Dict[str, List[Dict[str, Any]]] = {}
        self.rank_history: Dict[str, List[Dict[str, Any]]] = {}
        self.submission_logs: Dict[str, List[Dict[str, Any]]] = {}
        self.reports: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self) -> None:
        demo_events = [
            ("2026 春季新生赛", "jeopardy", "registration", "面向新用户的入门解题赛"),
            ("企业红蓝对抗演练", "attack_defense", "running", "攻防实战演练"),
            ("AI 安全专题赛", "king_of_hill", "draft", "围绕 AI 安全题"),
        ]
        for idx, (name, fmt, st, desc) in enumerate(demo_events, 1):
            eid = f"comp_{2000 + idx}"
            ev = {
                "id": eid, "name": name, "format": fmt, "status": st,
                "description": desc,
                "start_time": "2026-09-20 09:00:00",
                "end_time": "2026-09-21 18:00:00",
                "reg_deadline": "2026-09-19 23:59:00",
                "organizer": "平台组委会",
                "sponsors": ["Demo 赞助商"],
                "logo_url": "",
                "rules": ["禁止共享 Flag", "禁止 DoS 攻击其它队伍"],
                "prizes": PRIZE_TIERS,
                "scoring": {"first_blood": 100, "second_blood": 60,
                            "third_blood": 30, "time_decay": True},
                "team_size": {"min": 1, "max": 3},
                "public": True,
                "created_at": _now(),
            }
            self.events[eid] = ev
            self.registrations[eid] = []
            self.rankings[eid] = []
            self.rank_history[eid] = []
            self.submission_logs[eid] = []

    # ------------------------------------------------------------------ #
    # 赛事 CRUD
    # ------------------------------------------------------------------ #
    def list_events(self, status: Optional[str] = None,
                    fmt: Optional[str] = None) -> Dict[str, Any]:
        items = list(self.events.values())
        if status:
            items = [e for e in items if e["status"] == status]
        if fmt:
            items = [e for e in items if e["format"] == fmt]
        return {
            "total": len(items),
            "events": [{
                "id": e["id"], "name": e["name"], "format": e["format"],
                "status": e["status"], "start_time": e["start_time"],
                "end_time": e["end_time"],
                "registered": len(self.registrations.get(e["id"], [])),
            } for e in items],
            "formats": FORMATS, "statuses": STATUSES,
        }

    def get_event(self, eid: str) -> Optional[Dict[str, Any]]:
        return self.events.get(eid)

    def create_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        eid = _uid("comp")
        ev = {
            "id": eid,
            "name": payload.get("name", "未命名赛事"),
            "description": payload.get("description", ""),
            "format": payload.get("format", "jeopardy"),
            "status": "draft",
            "start_time": payload.get("start_time", _now()),
            "end_time": payload.get("end_time", _now()),
            "reg_deadline": payload.get("reg_deadline", _now()),
            "organizer": payload.get("organizer", "admin"),
            "sponsors": payload.get("sponsors", []),
            "logo_url": payload.get("logo_url", ""),
            "rules": payload.get("rules", []),
            "prizes": payload.get("prizes", PRIZE_TIERS),
            "scoring": payload.get("scoring", {"first_blood": 100}),
            "team_size": payload.get("team_size", {"min": 1, "max": 3}),
            "public": bool(payload.get("public", True)),
            "created_at": _now(),
        }
        self.events[eid] = ev
        self.registrations[eid] = []
        self.rankings[eid] = []
        self.rank_history[eid] = []
        self.submission_logs[eid] = []
        return ev

    def update_event_status(self, eid: str, status: str) -> Optional[Dict[str, Any]]:
        ev = self.events.get(eid)
        if not ev or status not in STATUSES:
            return None
        ev["status"] = status
        return ev

    # ------------------------------------------------------------------ #
    # 报名
    # ------------------------------------------------------------------ #
    def register(self, eid: str, team: str, members: List[str],
                 contact: str = "") -> Dict[str, Any]:
        ev = self.events.get(eid)
        if not ev:
            return {"error": "赛事不存在"}
        regs = self.registrations.setdefault(eid, [])
        if any(r["team"] == team for r in regs):
            return {"error": "该队伍已报名"}
        rec = {
            "id": _uid("reg"), "team": team, "members": members,
            "contact": contact, "status": "pending",
            "registered_at": _now(),
        }
        regs.append(rec)
        return rec

    def approve_registration(self, eid: str, reg_id: str,
                             approve: bool = True) -> Optional[Dict[str, Any]]:
        for r in self.registrations.get(eid, []):
            if r["id"] == reg_id:
                r["status"] = "approved" if approve else "rejected"
                return r
        return None

    def list_registrations(self, eid: str) -> Dict[str, Any]:
        regs = self.registrations.get(eid, [])
        pending = [r for r in regs if r["status"] == "pending"]
        approved = [r for r in regs if r["status"] == "approved"]
        return {"event_id": eid, "total": len(regs), "pending": len(pending),
                "approved": len(approved), "registrations": regs}

    # ------------------------------------------------------------------ #
    # 排名
    # ------------------------------------------------------------------ #
    def record_solve(self, eid: str, team: str, challenge_id: str,
                     score: int) -> Dict[str, Any]:
        rk = self.rankings.setdefault(eid, [])
        entry = next((r for r in rk if r["team"] == team), None)
        if entry is None:
            entry = {"team": team, "score": 0, "solves": 0,
                     "first_blood": 0, "history": []}
            rk.append(entry)
        bonus = 0
        entry["solves"] += 1
        entry["score"] += score + bonus
        entry["history"].append({"challenge": challenge_id, "score": score,
                                 "at": _now()})
        rk.sort(key=lambda x: x["score"], reverse=True)
        self.rank_history.setdefault(eid, []).append({
            "at": _now(), "top": [{"team": r["team"], "score": r["score"]}
                                  for r in rk[:5]],
        })
        return entry

    def leaderboard(self, eid: str) -> Dict[str, Any]:
        rk = sorted(self.rankings.get(eid, []),
                    key=lambda x: x["score"], reverse=True)
        for i, r in enumerate(rk, 1):
            r["rank"] = i
        ev = self.events.get(eid, {})
        return {"event_id": eid, "event_name": ev.get("name"),
                "format": ev.get("format"), "status": ev.get("status"),
                "ranking": rk, "history_ticks": len(self.rank_history.get(eid, []))}

    # ------------------------------------------------------------------ #
    # 监控与复盘
    # ------------------------------------------------------------------ #
    def log_submission(self, eid: str, team: str, challenge_id: str,
                       flag: str, correct: bool, ip: str = "") -> Dict[str, Any]:
        entry = {"at": _now(), "team": team, "challenge_id": challenge_id,
                 "flag_preview": flag[:6] + "...", "correct": correct, "ip": ip}
        self.submission_logs.setdefault(eid, []).append(entry)
        return entry

    def monitor(self, eid: str) -> Dict[str, Any]:
        ev = self.events.get(eid, {})
        logs = self.submission_logs.get(eid, [])
        rk = self.rankings.get(eid, [])
        suspicious = [l for l in logs
                      if l.get("correct") is False and
                      len([x for x in logs if x["team"] == l["team"]]) > 20]
        return {
            "event_id": eid, "status": ev.get("status"),
            "registered": len(self.registrations.get(eid, [])),
            "submissions": len(logs),
            "correct_submissions": sum(1 for l in logs if l["correct"]),
            "active_teams": len(rk),
            "suspicious_count": len(suspicious),
            "recent_logs": logs[-20:],
        }

    def postmortem(self, eid: str) -> Dict[str, Any]:
        ev = self.events.get(eid, {})
        rk = sorted(self.rankings.get(eid, []),
                    key=lambda x: x["score"], reverse=True)
        logs = self.submission_logs.get(eid, [])
        report = {
            "event_id": eid, "event_name": ev.get("name"),
            "format": ev.get("format"),
            "total_teams": len(rk),
            "total_submissions": len(logs),
            "correct_submissions": sum(1 for l in logs if l["correct"]),
            "top_teams": [{"rank": i + 1, "team": r["team"],
                           "score": r["score"], "solves": r["solves"]}
                          for i, r in enumerate(rk[:10])],
            "highlights": [l for l in logs[-5:]],
            "generated_at": _now(),
        }
        self.reports[eid] = report
        return report


_competition_singleton: Optional[CompetitionManager] = None


def get_competition_manager() -> CompetitionManager:
    global _competition_singleton
    if _competition_singleton is None:
        _competition_singleton = CompetitionManager()
    return _competition_singleton
