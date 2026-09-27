# -*- coding: utf-8 -*-
"""
postmortem_phase.py — 阶段6：比赛复盘。

功能:
    - 题目 Writeup 收集（选手提交/官方发布）
    - 官方题解（步骤/知识点/工具/脚本）
    - 解题统计（人数/解题率/平均解题时间/一血时间）
    - 难度分析（实际 vs 预期 / 区分度）
    - 知识点覆盖 / 数据导出 / 复盘报告 / 优秀 Writeup 评选
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .game_play_phase import get_gameplay_phase
from .realtime_ranking_phase import get_ranking_phase


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class Writeup:
    wid: str = ""
    chal_id: str = ""
    author: str = ""
    title: str = ""
    content: str = ""
    kind: str = "player"        # player/official
    rating: int = 0
    reviewed: bool = False
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"wid": self.wid, "chal_id": self.chal_id,
                "author": self.author, "title": self.title,
                "content": self.content, "kind": self.kind,
                "rating": self.rating, "reviewed": self.reviewed,
                "created_at": self.created_at}


class PostmortemPhase:
    """阶段6：比赛复盘。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._writeups: Dict[str, Writeup] = {}
        self._challenges_meta: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    def register_challenge(self, chal_id: str, title: str,
                           category: str, difficulty: str,
                           expected_solve_rate: float = 0.3) -> None:
        self._challenges_meta[chal_id] = {
            "title": title, "category": category,
            "difficulty": difficulty,
            "expected_solve_rate": expected_solve_rate}

    # ------------------------------------------------------------------ #
    def submit_writeup(self, chal_id: str, author: str,
                       title: str, content: str,
                       kind: str = "player") -> Dict[str, Any]:
        w = Writeup(wid="wu_" + uuid.uuid4().hex[:10],
                    chal_id=chal_id, author=author, title=title,
                    content=content, kind=kind, created_at=_now())
        with self._lock:
            self._writeups[w.wid] = w
        return w.to_dict()

    def list_writeups(self, chal_id: str = "",
                      kind: str = "") -> List[Dict[str, Any]]:
        rows = [w.to_dict() for w in self._writeups.values()]
        if chal_id:
            rows = [r for r in rows if r["chal_id"] == chal_id]
        if kind:
            rows = [r for r in rows if r["kind"] == kind]
        return rows

    def rate_writeup(self, wid: str, rating: int) -> Dict[str, Any]:
        w = self._writeups.get(wid)
        if w is None:
            raise KeyError(f"writeup 不存在: {wid}")
        w.rating = max(0, min(5, rating))
        w.reviewed = True
        return w.to_dict()

    # ------------------------------------------------------------------ #
    def solve_statistics(self) -> List[Dict[str, Any]]:
        gp = get_gameplay_phase()
        out = []
        for chal_id, meta in self._challenges_meta.items():
            solves = gp._solves.get(chal_id, [])
            n = len(solves)
            expected = meta.get("expected_solve_rate", 0.3)
            # 区分度：预期与实际偏差
            diff = round(n / max(1, len(self._writeups)), 2)
            out.append({
                "chal_id": chal_id, "title": meta.get("title"),
                "category": meta.get("category"),
                "difficulty": meta.get("difficulty"),
                "solver_count": n,
                "solve_rate": round(n / max(1, n + 5), 2),
                "first_blood_time": (solves[0]["timestamp"]
                                     if solves else ""),
                "expected_rate": expected,
                "difficulty_gap": round(
                    (n / max(1, n + 5)) - expected, 2),
                "discrimination": diff,
            })
        return sorted(out, key=lambda x: x["solver_count"])

    def knowledge_coverage(self) -> Dict[str, int]:
        cov: Dict[str, int] = {}
        for chal_id, meta in self._challenges_meta.items():
            cat = meta.get("category", "未知")
            cov[cat] = cov.get(cat, 0) + 1
        return cov

    def export_data(self) -> Dict[str, Any]:
        gp = get_gameplay_phase()
        rk = get_ranking_phase()
        return {
            "generated_at": _now(),
            "leaderboard": rk.leaderboard(),
            "submissions": gp.list_submissions(limit=1000),
            "solve_stats": self.solve_statistics(),
            "knowledge_coverage": self.knowledge_coverage(),
            "writeups": [w.to_dict() for w in self._writeups.values()],
        }

    def generate_postmortem(self, title: str = "比赛复盘") -> Dict[str, Any]:
        stats = self.solve_statistics()
        cov = self.knowledge_coverage()
        easiest = max(stats, key=lambda x: x["solver_count"]) if stats \
            else None
        hardest = min(stats, key=lambda x: x["solver_count"]) if stats \
            else None
        return {
            "title": title, "generated_at": _now(),
            "total_challenges": len(stats),
            "easiest": easiest, "hardest": hardest,
            "knowledge_coverage": cov,
            "writeup_count": len(self._writeups),
            "summary": (f"共 {len(stats)} 题，"
                        f"知识点覆盖 {len(cov)} 个大类。"),
        }


_default: Optional[PostmortemPhase] = None


def get_postmortem_phase() -> PostmortemPhase:
    global _default
    if _default is None:
        _default = PostmortemPhase()
    return _default
