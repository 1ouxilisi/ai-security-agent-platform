# -*- coding: utf-8 -*-
"""
training_mode_phase.py — 阶段7：训练模式。

功能:
    - 单人训练（自由/按题型/按难度/按知识点）
    - 知识点专项突破 / 难度递进
    - 学习路径（Web/Reverse/Pwn 等）
    - 能力评估（各题型评分/短板/建议）
    - 训练记录 / 统计 / 目标管理
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

CATEGORIES = ("Web", "Reverse", "Pwn", "Crypto", "Misc",
             "Forensics", "Mobile", "Blockchain")

LEARNING_PATHS: Dict[str, Dict[str, Any]] = {
    "web_path": {
        "name": "Web 安全学习路径",
        "steps": ["HTTP协议", "SQL注入", "XSS", "文件上传",
                  "命令注入", "SSRF", "反序列化", "逻辑漏洞"],
    },
    "pwn_path": {
        "name": "Pwn 学习路径",
        "steps": ["栈基础", "栈溢出", "格式化字符串", "ROP",
                  "堆管理", "堆溢出", "UAF", "堆风水"],
    },
    "reverse_path": {
        "name": "逆向学习路径",
        "steps": ["汇编基础", "动态调试", "静态分析", "脱壳",
                  "算法还原", "反对抗", "SO层逆向"],
    },
}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class TrainingRecord:
    rec_id: str = ""
    user: str = ""
    mode: str = "free"          # free/category/difficulty/knowledge/path
    ref: str = ""               # 题目/知识点/路径 id
    started_at: str = ""
    finished_at: str = ""
    solved: bool = False
    score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"rec_id": self.rec_id, "user": self.user,
                "mode": self.mode, "ref": self.ref,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "solved": self.solved, "score": self.score}


class TrainingModePhase:
    """阶段7：训练模式。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: List[TrainingRecord] = []
        # 各题型能力分: user -> {cat: score 0-100}
        self._ability: Dict[str, Dict[str, float]] = {}
        self._goals: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    def start_training(self, user: str, mode: str = "free",
                       ref: str = "") -> Dict[str, Any]:
        r = TrainingRecord(rec_id="tr_" + uuid.uuid4().hex[:10],
                           user=user, mode=mode, ref=ref,
                           started_at=_now())
        with self._lock:
            self._records.append(r)
        return r.to_dict()

    def finish_training(self, rec_id: str, solved: bool,
                        score: int = 0,
                        category: str = "") -> Dict[str, Any]:
        for r in self._records:
            if r.rec_id == rec_id:
                r.finished_at = _now()
                r.solved = solved
                r.score = score
                if solved and category:
                    self._update_ability(r.user, category, score)
                return r.to_dict()
        raise KeyError(f"训练记录不存在: {rec_id}")

    def _update_ability(self, user: str, category: str,
                       score: int) -> None:
        ab = self._ability.setdefault(user, {})
        prev = ab.get(category, 30.0)
        ab[category] = min(100.0, prev + score / 20.0)

    # ------------------------------------------------------------------ #
    def list_records(self, user: str = "") -> List[Dict[str, Any]]:
        rows = [r.to_dict() for r in self._records]
        if user:
            rows = [r for r in rows if r["user"] == user]
        return rows

    def learning_paths(self) -> Dict[str, Any]:
        return LEARNING_PATHS

    def ability_assessment(self, user: str) -> Dict[str, Any]:
        ab = self._ability.get(user, {c: 30.0 for c in CATEGORIES})
        for c in CATEGORIES:
            ab.setdefault(c, 30.0)
        weak = sorted(ab.items(), key=lambda x: x[1])[:3]
        suggestions = [
            f"加强 {c} 方向练习，当前 {v:.0f} 分" for c, v in weak]
        return {"user": user, "scores": ab,
                "weakness": [{"category": c, "score": round(v, 1)}
                             for c, v in weak],
                "suggestions": suggestions}

    # ------------------------------------------------------------------ #
    def set_goal(self, user: str, goal: str,
                 target: str, deadline: str) -> Dict[str, Any]:
        g = {"user": user, "goal": goal, "target": target,
             "deadline": deadline, "created_at": _now()}
        self._goals[f"{user}:{goal}"] = g
        return g

    def list_goals(self, user: str = "") -> List[Dict[str, Any]]:
        rows = list(self._goals.values())
        if user:
            rows = [g for g in rows if g["user"] == user]
        return rows

    def stats(self, user: str = "") -> Dict[str, Any]:
        rows = self.list_records(user)
        solved = sum(1 for r in rows if r["solved"])
        return {"total": len(rows), "solved": solved,
                "accuracy": round(solved / max(1, len(rows)), 2),
                "paths": len(LEARNING_PATHS)}


_default: Optional[TrainingModePhase] = None


def get_training_phase() -> TrainingModePhase:
    global _default
    if _default is None:
        _default = TrainingModePhase()
    return _default
