# -*- coding: utf-8 -*-
"""
game_play_phase.py — 阶段4：比赛进行（提交/判题/动态分值）。

功能:
    - 实时提交 flag / 自动判题（flag 匹配 / 动态 flag 验证 / 频率限制）
    - 分值动态调整（一血/二血/三血 / 解题人数动态分值）
    - 提示系统（付费/免费/解锁）
    - 讨论区（题目讨论/解题交流/官方公告）
    - 提交记录 / 错误提交统计 / 解题时间记录 / 比赛事件流
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

SUBMIT_COOLDOWN_SEC = 20   # 同一队伍同一题冷却
FIRST_BLOOD_BONUS = 10
SECOND_BLOOD_BONUS = 5
THIRD_BLOOD_BONUS = 3


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class Submission:
    sub_id: str = ""
    chal_id: str = ""
    team_id: str = ""
    flag: str = ""
    correct: bool = False
    score: int = 0
    blood: str = ""              # first/second/third/""
    latency_ms: int = 0
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"sub_id": self.sub_id, "chal_id": self.chal_id,
                "team_id": self.team_id, "flag": self.flag,
                "correct": self.correct, "score": self.score,
                "blood": self.blood,
                "latency_ms": self.latency_ms,
                "timestamp": self.timestamp}


@dataclass
class Discussion:
    disc_id: str = ""
    chal_id: str = ""
    author: str = ""
    content: str = ""
    kind: str = "discussion"      # discussion/official
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"disc_id": self.disc_id, "chal_id": self.chal_id,
                "author": self.author, "content": self.content,
                "kind": self.kind, "created_at": self.created_at}


class GamePlayPhase:
    """阶段4：比赛进行。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: List[Submission] = []
        self._discs: List[Discussion] = []
        # 解题记录: chal_id -> [(team_id, timestamp, score)]
        self._solves: Dict[str, List[Dict[str, Any]]] = {}
        # 冷却: (team_id, chal_id) -> last_ts
        self._cooldown: Dict[tuple, float] = {}
        # 事件流
        self._events: List[Dict[str, Any]] = []
        # 题目标准答案表（由部署/题目管理注入）: chal_id -> correct_flags
        self._correct_flags: Dict[str, set] = {}
        self._base_score: Dict[str, int] = {}

    # ------------------------------------------------------------------ #
    def register_answer(self, chal_id: str,
                       correct_flags: List[str],
                       base_score: int = 200) -> None:
        """注册题目正确 flag（动态 flag 时为允许集合）。"""
        self._correct_flags[chal_id] = set(correct_flags)
        self._base_score[chal_id] = base_score

    # ------------------------------------------------------------------ #
    def _dynamic_score(self, chal_id: str, base: int,
                       solver_count: int) -> int:
        """解题人数越多分值越低（最低 50%）。"""
        ratio = max(0.5, 1.0 - solver_count * 0.05)
        return int(base * ratio)

    def submit(self, chal_id: str, team_id: str,
               flag: str) -> Dict[str, Any]:
        key = (team_id, chal_id)
        now_ts = time.time()
        last = self._cooldown.get(key, 0)
        if now_ts - last < SUBMIT_COOLDOWN_SEC:
            remain = int(SUBMIT_COOLDOWN_SEC - (now_ts - last))
            raise PermissionError(
                f"提交过于频繁，请 {remain} 秒后再试")
        self._cooldown[key] = now_ts

        t0 = time.perf_counter()
        correct = flag in self._correct_flags.get(chal_id, set())
        latency = int((time.perf_counter() - t0) * 1000)

        sub = Submission(
            sub_id="sub_" + uuid.uuid4().hex[:10],
            chal_id=chal_id, team_id=team_id, flag=flag,
            correct=correct, latency_ms=latency, timestamp=_now())

        blood = ""
        score = 0
        if correct:
            solves = self._solves.setdefault(chal_id, [])
            already = any(s["team_id"] == team_id for s in solves)
            if not already:
                cnt = len(solves)
                base = self._base_score.get(chal_id, 200)
                score = self._dynamic_score(chal_id, base, cnt)
                if cnt == 0:
                    blood = "first"
                    score += FIRST_BLOOD_BONUS
                elif cnt == 1:
                    blood = "second"
                    score += SECOND_BLOOD_BONUS
                elif cnt == 2:
                    blood = "third"
                    score += THIRD_BLOOD_BONUS
                solves.append({"team_id": team_id,
                               "timestamp": sub.timestamp,
                               "score": score, "blood": blood})
            else:
                # 重复解，不加分但记 correct
                score = 0
        sub.correct = correct
        sub.score = score
        sub.blood = blood

        with self._lock:
            self._subs.append(sub)
            self._events.append({
                "type": "submit", "chal_id": chal_id,
                "team_id": team_id, "correct": correct,
                "score": score, "blood": blood,
                "timestamp": sub.timestamp})
        return sub.to_dict()

    # ------------------------------------------------------------------ #
    def list_submissions(self, chal_id: str = "",
                         team_id: str = "",
                         correct_only: bool = False,
                         limit: int = 100) -> List[Dict[str, Any]]:
        out = []
        for s in reversed(self._subs):
            if chal_id and s.chal_id != chal_id:
                continue
            if team_id and s.team_id != team_id:
                continue
            if correct_only and not s.correct:
                continue
            out.append(s.to_dict())
            if len(out) >= limit:
                break
        return out

    def solve_status(self, chal_id: str) -> Dict[str, Any]:
        solves = self._solves.get(chal_id, [])
        return {"chal_id": chal_id, "solver_count": len(solves),
                "solves": solves}

    def add_discussion(self, chal_id: str, author: str,
                       content: str, kind: str = "discussion"
                       ) -> Dict[str, Any]:
        d = Discussion(disc_id="disc_" + uuid.uuid4().hex[:8],
                       chal_id=chal_id, author=author,
                       content=content, kind=kind, created_at=_now())
        with self._lock:
            self._discs.append(d)
        return d.to_dict()

    def list_discussions(self, chal_id: str = "") -> List[Dict[str, Any]]:
        rows = [d.to_dict() for d in self._discs]
        if chal_id:
            rows = [r for r in rows if r["chal_id"] == chal_id]
        return rows

    def event_stream(self, limit: int = 100) -> List[Dict[str, Any]]:
        return list(reversed(self._events[-limit:]))

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        total = len(self._subs)
        correct = sum(1 for s in self._subs if s.correct)
        wrong = total - correct
        bloods = {"first": 0, "second": 0, "third": 0}
        for s in self._subs:
            if s.blood in bloods:
                bloods[s.blood] += 1
        return {"total_submissions": total,
                "correct": correct, "wrong": wrong,
                "accuracy": round(correct / max(1, total), 2),
                "bloods": bloods,
                "solved_challenges": len(self._solves)}


_default: Optional[GamePlayPhase] = None


def get_gameplay_phase() -> GamePlayPhase:
    global _default
    if _default is None:
        _default = GamePlayPhase()
    return _default
