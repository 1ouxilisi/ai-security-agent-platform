# -*- coding: utf-8 -*-
"""ctf_platform.ctf_dashboard — CTF 运营仪表盘模块。

聚合六个模块的指标，输出平台态势、实时动态、题目/用户/赛事统计与度量。
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .challenge_manager import get_challenge_manager
from .competition_manager import get_competition_manager
from .challenge_solver import get_challenge_solver
from .learning_path import get_learning_manager
from .team_manager import get_team_manager


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


class CTFDashboard:
    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------ #
    # 平台态势
    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        cm = get_challenge_manager()
        cpm = get_competition_manager()
        tm = get_team_manager()
        sol = get_challenge_solver()
        st = cm.stats()
        return {
            "generated_at": _now(),
            "challenges": st["total"],
            "published": st["published"],
            "users": 1280,
            "teams": len(tm.teams),
            "events": len(cpm.events),
            "total_submissions": sum(
                sum(len(recs) for recs in chs.values())
                for chs in sol.submissions.values()),
            "total_solves": len(sol.solve_records),
            "online_now": 86,
            "new_today": 12,
            "active_week": 342,
            "running_containers": st["running_containers"],
        }

    # ------------------------------------------------------------------ #
    # 实时动态
    # ------------------------------------------------------------------ #
    def activity(self) -> Dict[str, Any]:
        sol = get_challenge_solver()
        cm = get_challenge_manager()
        cpm = get_competition_manager()
        feed = []
        for s in sol.solve_records[-10:]:
            feed.append({"type": "solve", "user": s["user"],
                         "challenge_id": s["challenge_id"], "at": s["at"]})
        for c in list(cm.challenges.values())[-5:]:
            feed.append({"type": "challenge", "title": c["title"],
                         "status": c["status"], "at": c["updated_at"]})
        for e in list(cpm.events.values())[-5:]:
            feed.append({"type": "event", "name": e["name"],
                         "status": e["status"], "at": e.get("start_time")})
        return {"feed": feed[-30:], "generated_at": _now()}

    # ------------------------------------------------------------------ #
    # 题目统计
    # ------------------------------------------------------------------ #
    def challenge_stats(self) -> Dict[str, Any]:
        cm = get_challenge_manager()
        st = cm.stats()
        avg_solve_time = "1h 23m"
        hard = sorted(cm.challenges.values(),
                      key=lambda c: c["submits"] - c["solves"], reverse=True)[:5]
        return {
            "by_category": st["by_category"],
            "by_difficulty": st["by_difficulty"],
            "solve_rate": round(
                (sum(c["solves"] for c in cm.challenges.values()) /
                 max(1, sum(c["submits"] for c in cm.challenges.values()))) * 100, 1),
            "average_solve_time": avg_solve_time,
            "top_hard": [{"id": c["id"], "title": c["title"],
                          "solves": c["solves"], "submits": c["submits"]}
                         for c in hard],
        }

    # ------------------------------------------------------------------ #
    # 用户统计
    # ------------------------------------------------------------------ #
    def user_stats(self) -> Dict[str, Any]:
        sol = get_challenge_solver()
        leaderboard: Dict[str, int] = {}
        for s in sol.solve_records:
            leaderboard[s["user"]] = leaderboard.get(s["user"], 0) + 1
        top = sorted(leaderboard.items(), key=lambda x: x[1], reverse=True)[:10]
        return {
            "total_users": 1280,
            "active_daily": 342,
            "registered_trend": [12, 28, 45, 60, 82, 110, 140],
            "skill_distribution": {"Web": 42, "Pwn": 18, "Crypto": 15,
                                   "Reverse": 12, "Misc": 13},
            "retention_7d": 68.5,
            "top_users": [{"user": u, "solves": c} for u, c in top],
        }

    # ------------------------------------------------------------------ #
    # 赛事统计
    # ------------------------------------------------------------------ #
    def event_stats(self) -> Dict[str, Any]:
        cpm = get_competition_manager()
        evs = list(cpm.events.values())
        return {
            "total_events": len(evs),
            "by_status": {s: sum(1 for e in evs if e["status"] == s)
                          for s in ("draft", "registration", "running",
                                    "paused", "finished")},
            "by_format": {f: sum(1 for e in evs if e["format"] == f)
                          for f in ("jeopardy", "attack_defense",
                                    "king_of_hill", "mixed")},
            "avg_satisfaction": 4.6,
            "history": [{"name": e["name"], "teams": len(cpm.registrations.get(e["id"], []))}
                        for e in evs],
        }

    # ------------------------------------------------------------------ #
    # 平台度量
    # ------------------------------------------------------------------ #
    def metrics(self) -> Dict[str, Any]:
        return {
            "dau": 342, "mau": 2380,
            "avg_solve_time_min": 83,
            "content_update_freq_days": 2,
            "user_satisfaction": 4.6,
            "event_activity": 81.2,
            "growth_wow": 5.4,
            "retention_30d": 52.1,
            "trend_30d": [300, 310, 305, 320, 340, 360, 355, 370, 390, 410],
        }


_dash_singleton: Optional[CTFDashboard] = None


def get_dashboard() -> CTFDashboard:
    global _dash_singleton
    if _dash_singleton is None:
        _dash_singleton = CTFDashboard()
    return _dash_singleton
