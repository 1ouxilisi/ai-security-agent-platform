# -*- coding: utf-8 -*-
"""
realtime_ranking_phase.py — 阶段5：实时排名。

功能:
    - 实时积分榜（队伍/个人）
    - 解题进度（已解/未解/部分解）
    - 队伍排名（按总分/解题数/最后解题时间）
    - 一血榜 / 二血 / 三血榜
    - 排名变化趋势 / 实时排名推送 / 排名历史记录
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .game_play_phase import get_gameplay_phase


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class TeamScore:
    team_id: str = ""
    team_name: str = ""
    score: int = 0
    solved: int = 0
    first_bloods: int = 0
    second_bloods: int = 0
    third_bloods: int = 0
    last_solve_time: str = ""
    history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"team_id": self.team_id, "team_name": self.team_name,
                "score": self.score, "solved": self.solved,
                "first_bloods": self.first_bloods,
                "second_bloods": self.second_bloods,
                "third_bloods": self.third_bloods,
                "last_solve_time": self.last_solve_time,
                "history": self.history[-20:]}


class RealtimeRankingPhase:
    """阶段5：实时排名。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._teams: Dict[str, TeamScore] = {}

    # ------------------------------------------------------------------ #
    def ensure_team(self, team_id: str,
                    team_name: str = "") -> TeamScore:
        if team_id not in self._teams:
            self._teams[team_id] = TeamScore(
                team_id=team_id, team_name=team_name or team_id)
        elif team_name:
            self._teams[team_id].team_name = team_name
        return self._teams[team_id]

    # ------------------------------------------------------------------ #
    def rebuild(self) -> List[Dict[str, Any]]:
        """根据 gameplay 的解题记录重建积分榜。"""
        gp = get_gameplay_phase()
        # 重置但保留 team_name
        names = {tid: t.team_name for tid, t in self._teams.items()}
        self._teams.clear()
        # 汇总每个队伍的得分
        for chal_id, solves in gp._solves.items():
            for s in solves:
                t = self.ensure_team(s["team_id"],
                                     names.get(s["team_id"],
                                               s["team_id"]))
                t.score += int(s.get("score", 0))
                t.solved += 1
                blood = s.get("blood", "")
                if blood == "first":
                    t.first_bloods += 1
                elif blood == "second":
                    t.second_bloods += 1
                elif blood == "third":
                    t.third_bloods += 1
                t.last_solve_time = max(t.last_solve_time,
                                        s.get("timestamp", ""))
        return self.leaderboard()

    def leaderboard(self) -> List[Dict[str, Any]]:
        rows = list(self._teams.values())
        rows.sort(key=lambda t: (t.score, t.solved,
                                 t.last_solve_time),
                  reverse=True)
        out = []
        for rank, t in enumerate(rows, 1):
            d = t.to_dict()
            d["rank"] = rank
            out.append(d)
        return out

    # ------------------------------------------------------------------ #
    def blood_board(self, blood: str = "first"
                    ) -> List[Dict[str, Any]]:
        rows = self.leaderboard()
        key = {"first": "first_bloods",
               "second": "second_bloods",
               "third": "third_bloods"}.get(blood, "first_bloods")
        rows = [r for r in rows if r.get(key, 0) > 0]
        rows.sort(key=lambda r: r[key], reverse=True)
        return rows

    def solve_progress(self, total_challenges: int = 0
                       ) -> Dict[str, Any]:
        gp = get_gameplay_phase()
        solved = len(gp._solves)
        return {"solved": solved,
                "total": total_challenges or solved,
                "solve_rate": round(
                    solved / max(1, total_challenges or solved), 2)}

    def rank_history_snapshot(self) -> Dict[str, Any]:
        lb = self.leaderboard()
        snap = {"ts": _now(),
                "top10": [{"rank": r["rank"],
                           "team": r["team_name"],
                           "score": r["score"]} for r in lb[:10]]}
        # 写入每个队伍历史
        for r in lb:
            t = self._teams[r["team_id"]]
            t.history.append({"ts": snap["ts"], "rank": r["rank"],
                              "score": r["score"]})
        return snap

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        lb = self.leaderboard()
        total_teams = len(lb)
        return {"total_teams": total_teams,
                "top_score": lb[0]["score"] if lb else 0,
                "avg_score": round(
                    sum(r["score"] for r in lb) / max(1, total_teams),
                    1),
                "first_bloods": sum(r["first_bloods"] for r in lb)}


_default: Optional[RealtimeRankingPhase] = None


def get_ranking_phase() -> RealtimeRankingPhase:
    global _default
    if _default is None:
        _default = RealtimeRankingPhase()
    return _default
