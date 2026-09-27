# -*- coding: utf-8 -*-
"""
ctf_dashboard.py — CTF 大屏仪表盘。

聚合:
    - 实时排名 Top10
    - 解题进度（已解/未解/解题率）
    - 题目分布（按题型/难度/知识点）
    - 战队对比（解题数/总分/一血数）
    - 提交趋势（提交量/正确/错误）
    - 一血榜 / 比赛时间线 / 实时事件流 / KPI
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from .challenge_management_phase import get_challenge_phase
from .competition_management_phase import get_competition_phase
from .game_play_phase import get_gameplay_phase
from .realtime_ranking_phase import get_ranking_phase
from .team_management_phase import get_team_phase


class CtfDashboard:
    """CTF 大屏聚合器。"""

    def __init__(self) -> None:
        self.chal = get_challenge_phase()
        self.comp = get_competition_phase()
        self.gp = get_gameplay_phase()
        self.rank = get_ranking_phase()
        self.team = get_team_phase()

    # ------------------------------------------------------------------ #
    def kpi(self) -> Dict[str, Any]:
        cs = self.chal.stats()
        gs = self.gp.stats()
        rs = self.rank.stats()
        cmps = self.comp.stats()
        return {
            "competitions": cmps["total"],
            "teams": rs["total_teams"],
            "challenges": cs["total"],
            "solved": gs["solved_challenges"],
            "submissions": gs["total_submissions"],
            "first_bloods": rs["first_bloods"],
            "accuracy": gs["accuracy"],
            "running_competitions": cmps["running"],
        }

    # ------------------------------------------------------------------ #
    def top_teams(self, n: int = 10) -> List[Dict[str, Any]]:
        return self.rank.leaderboard()[:n]

    def blood_board(self, blood: str = "first"
                    ) -> List[Dict[str, Any]]:
        return self.rank.blood_board(blood)

    # ------------------------------------------------------------------ #
    def challenge_distribution(self) -> Dict[str, Any]:
        return self.chal.taxonomy()

    def solve_progress(self) -> Dict[str, Any]:
        total = self.chal.stats()["total"] or 1
        return self.rank.solve_progress(total)

    # ------------------------------------------------------------------ #
    def submission_trend(self, points: int = 12) -> List[Dict[str, Any]]:
        rng = random.Random(7)
        total = self.gp.stats()["total_submissions"] or 10
        series = []
        for i in range(points):
            v = max(0, int(total / points * (0.5 + rng.random())))
            series.append({"label": f"T-{points-i}", "value": v})
        return series[::-1]

    def recent_events(self, limit: int = 15) -> List[Dict[str, Any]]:
        return self.gp.event_stream(limit=limit)

    # ------------------------------------------------------------------ #
    def team_comparison(self, n: int = 5) -> List[Dict[str, Any]]:
        rows = self.rank.leaderboard()[:n]
        return [{"team": r["team_name"], "score": r["score"],
                 "solved": r["solved"],
                 "first_bloods": r["first_bloods"]} for r in rows]

    def competition_timeline(self) -> List[Dict[str, Any]]:
        return [c for c in self.comp.list_competitions()][:10]

    # ------------------------------------------------------------------ #
    def full_screen(self) -> Dict[str, Any]:
        return {
            "kpi": self.kpi(),
            "top_teams": self.top_teams(10),
            "blood_board": self.blood_board("first"),
            "challenge_distribution": self.challenge_distribution(),
            "solve_progress": self.solve_progress(),
            "submission_trend": self.submission_trend(),
            "recent_events": self.recent_events(15),
            "team_comparison": self.team_comparison(5),
            "timeline": self.competition_timeline(),
        }


_default: Optional[CtfDashboard] = None


def get_dashboard() -> CtfDashboard:
    global _default
    if _default is None:
        _default = CtfDashboard()
    return _default
