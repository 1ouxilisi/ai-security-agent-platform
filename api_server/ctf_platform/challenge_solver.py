# -*- coding: utf-8 -*-
"""ctf_platform.challenge_solver — 解题与 Flag 验证模块。

Flag 提交、解题记录、提示系统、Writeup、讨论区、作弊检测。
"""

from __future__ import annotations

import re
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional


FLAG_PATTERN = re.compile(r"^flag\{[A-Za-z0-9_\-!@#$%^&*]+}$")
RATE_LIMIT_WINDOW = 60  # 秒
RATE_LIMIT_MAX = 10


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


class ChallengeSolver:
    def __init__(self) -> None:
        # user -> challenge -> list of submit records
        self.submissions: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(dict)
        self.solve_records: List[Dict[str, Any]] = []
        self.writeups: Dict[str, Dict[str, Any]] = {}
        self.discussions: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.cheat_alerts: List[Dict[str, Any]] = []
        self.hint_usage: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._seed()

    def _seed(self) -> None:
        # 示例 Writeup
        self.writeups["wp_001"] = {
            "id": "wp_001", "challenge_id": "chal_1000",
            "author": "alice", "title": "登录绕过复盘",
            "content": "万能密码 admin' or '1'='1 直接绕过。",
            "status": "published", "rating": 5, "views": 128,
            "tags": ["SQL 注入"], "created_at": _now(),
        }
        self.discussions["chal_1000"].append({
            "id": _uid("post"), "author": "bob", "content": "请问 flag 在哪一层？",
            "is_answer": False, "hidden": False, "at": _now(),
        })

    # ------------------------------------------------------------------ #
    # Flag 提交
    # ------------------------------------------------------------------ #
    def submit_flag(self, user: str, challenge_id: str, flag: str,
                    expected_flag: str = "", dynamic_flag: str = "",
                    client_ip: str = "") -> Dict[str, Any]:
        # 频率限制
        history = self.submissions[user].setdefault(challenge_id, [])
        now_ts = time.time()
        recent = [h for h in history if now_ts - h["ts"] < RATE_LIMIT_WINDOW]
        if len(recent) >= RATE_LIMIT_MAX:
            return {"ok": False, "reason": "rate_limited",
                    "message": "提交过于频繁，请稍后再试"}

        norm = (flag or "").strip().replace(" ", "").lower()
        expected = (dynamic_flag or expected_flag or "").strip().lower()
        correct = False
        if expected:
            correct = norm == expected.lower()
        record = {
            "id": _uid("sub"), "user": user, "challenge_id": challenge_id,
            "flag_preview": (flag or "")[:6] + "...",
            "correct": correct, "ip": client_ip,
            "at": _now(), "ts": now_ts,
        }
        history.append(record)

        if correct:
            first = not any(s["user"] == user and s["challenge_id"] == challenge_id
                           for s in self.solve_records)
            self.solve_records.append({
                "user": user, "challenge_id": challenge_id,
                "at": _now(), "attempts": len(history),
                "first_solve": first, "device": "web",
            })
        # 作弊检测：相同 Flag 多用户
        if correct:
            same = [s for s in self.solve_records
                    if s["challenge_id"] == challenge_id and s["user"] != user]
            if len(same) > 0 and not dynamic_flag:
                # 静态 Flag 多人复用，提示但不阻断
                self.cheat_alerts.append({
                    "type": "shared_static_flag", "user": user,
                    "challenge_id": challenge_id, "at": _now(),
                    "detail": "静态 Flag 被多个用户提交，建议启用动态 Flag",
                })
        return {"ok": correct, "attempts": len(history),
                "first_solve": correct and
                len([s for s in self.solve_records
                     if s["user"] == user and s["challenge_id"] == challenge_id]) == 1}

    def validate_flag_format(self, flag: str) -> bool:
        return bool(FLAG_PATTERN.match(flag or ""))

    # ------------------------------------------------------------------ #
    # 解题记录
    # ------------------------------------------------------------------ #
    def my_solves(self, user: str) -> List[Dict[str, Any]]:
        return [s for s in self.solve_records if s["user"] == user]

    def challenge_solve_stats(self, challenge_id: str) -> Dict[str, Any]:
        items = [s for s in self.solve_records if s["challenge_id"] == challenge_id]
        return {
            "challenge_id": challenge_id,
            "total_solves": len(items),
            "first_solve_at": items[0]["at"] if items else None,
            "average_attempts": (sum(s["attempts"] for s in items) / len(items)) if items else 0,
        }

    # ------------------------------------------------------------------ #
    # 提示系统
    # ------------------------------------------------------------------ #
    def unlock_hint(self, user: str, challenge_id: str, order: int,
                    hint_content: str, penalty: int = 20) -> Dict[str, Any]:
        used = self.hint_usage[user].get(challenge_id, 0)
        if order <= used:
            return {"ok": False, "reason": "already_unlocked"}
        self.hint_usage[user][challenge_id] = max(used, order)
        return {"ok": True, "order": order, "content": hint_content,
                "score_penalty": penalty * order}

    # ------------------------------------------------------------------ #
    # Writeup
    # ------------------------------------------------------------------ #
    def submit_writeup(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        wid = _uid("wp")
        wp = {
            "id": wid,
            "challenge_id": payload.get("challenge_id", ""),
            "author": payload.get("author", "anonymous"),
            "title": payload.get("title", "未命名 Writeup"),
            "content": payload.get("content", ""),
            "status": "pending",
            "rating": 0, "views": 0,
            "tags": payload.get("tags", []),
            "created_at": _now(),
        }
        self.writeups[wid] = wp
        return wp

    def list_writeups(self, challenge_id: Optional[str] = None,
                      status: str = "published") -> List[Dict[str, Any]]:
        items = list(self.writeups.values())
        if challenge_id:
            items = [w for w in items if w["challenge_id"] == challenge_id]
        if status:
            items = [w for w in items if w["status"] == status]
        return items

    def moderate_writeup(self, wid: str, action: str) -> Optional[Dict[str, Any]]:
        wp = self.writeups.get(wid)
        if not wp:
            return None
        wp["status"] = "published" if action == "approve" else "hidden"
        return wp

    # ------------------------------------------------------------------ #
    # 讨论区
    # ------------------------------------------------------------------ #
    def post_discussion(self, challenge_id: str, author: str,
                        content: str) -> Dict[str, Any]:
        post = {"id": _uid("post"), "author": author, "content": content,
                "is_answer": False, "hidden": False, "at": _now()}
        self.discussions[challenge_id].append(post)
        return post

    def list_discussions(self, challenge_id: str) -> List[Dict[str, Any]]:
        return [p for p in self.discussions.get(challenge_id, [])
                if not p["hidden"]]

    # ------------------------------------------------------------------ #
    # 作弊检测
    # ------------------------------------------------------------------ #
    def detect_cheat(self) -> Dict[str, Any]:
        alerts: List[Dict[str, Any]] = list(self.cheat_alerts)
        # 相同 IP 多账号
        ip_users: Dict[str, set] = defaultdict(set)
        for u, chs in self.submissions.items():
            for ch, recs in chs.items():
                for r in recs:
                    if r.get("ip"):
                        ip_users[r["ip"]].add(u)
        for ip, users in ip_users.items():
            if len(users) >= 3:
                alerts.append({"type": "multi_account_same_ip", "ip": ip,
                               "users": sorted(users), "at": _now()})
        return {"total_alerts": len(alerts), "alerts": alerts[-50:]}


_solver_singleton: Optional[ChallengeSolver] = None


def get_challenge_solver() -> ChallengeSolver:
    global _solver_singleton
    if _solver_singleton is None:
        _solver_singleton = ChallengeSolver()
    return _solver_singleton
