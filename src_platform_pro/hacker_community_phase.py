# -*- coding: utf-8 -*-
"""
hacker_community_phase.py — 阶段5：白帽社区。

功能:
    - 白帽个人主页 / 提交历史 / 能力标签
    - 等级体系（积分升级）/ 荣誉墙
    - 讨论区 / 私信 / 关注 / 行为分析
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

LEVELS = ["新手", "入门", "进阶", "高级", "专家", "大师"]
LEVEL_POINTS = [0, 200, 1000, 3000, 8000, 20000]


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class HackerCommunityPhase:
    """阶段5：白帽社区。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._posts: Dict[str, Dict[str, Any]] = {}
        self._messages: Dict[str, Dict[str, Any]] = {}
        self._follows: Dict[str, set] = {}
        self._honor: List[Dict[str, Any]] = []
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        for i, (title, body, cat) in enumerate([
                ("聊聊今年最火的 SSRF 利用", "从云元数据讲到内网绕过",
                 "技术讨论"),
                ("求大佬带带 SQL 注入", "复现卡住了，附 PoC", "求助"),
                ("分享一次漂亮的越权链", "从找回密码打到任意账号",
                 "分享")]):
            pid = "post_" + uuid.uuid4().hex[:10]
            self._posts[pid] = {
                "post_id": pid, "title": title, "body": body,
                "category": cat, "author": "0xC0FFEE",
                "likes": i * 7, "created_at": _now(),
            }
        self._honor = [
            {"month": "2026-08", "title": "月度之星", "hacker": "0xC0FFEE"},
            {"month": "2026-08", "title": "一血达人", "hacker": "0dayHunter"},
            {"month": "2026-08", "title": "质量之星", "hacker": "slowmist"},
        ]

    # ------------------------------------------------------------------ #
    def profile(self, hacker_id: str) -> Dict[str, Any]:
        from .platform_management_phase import \
            get_platform_management_phase
        pm = get_platform_management_phase()
        h = None
        for x in pm.list_hackers():
            if x["hacker_id"] == hacker_id:
                h = x
                break
        if h is None:
            return {"error": "not_found"}
        pts = h.get("points", 0)
        level_idx = max(i for i, p in enumerate(LEVEL_POINTS) if pts >= p)
        return {
            "hacker_id": hacker_id,
            "nickname": h["nickname"], "bio": h["bio"],
            "skills": h["skills"], "level": LEVELS[level_idx],
            "points": pts,
            "next_level": (LEVELS[level_idx + 1]
                           if level_idx + 1 < len(LEVELS) else "满级"),
            "next_points": (LEVEL_POINTS[level_idx + 1] - pts
                            if level_idx + 1 < len(LEVEL_POINTS) else 0),
        }

    def upgrade_level(self, hacker_id: str,
                      add_points: int) -> Dict[str, Any]:
        from .platform_management_phase import \
            get_platform_management_phase
        pm = get_platform_management_phase()
        with self._lock:
            for h in pm.list_hackers():
                if h["hacker_id"] == hacker_id:
                    h["points"] = h.get("points", 0) + add_points
                    return {"hacker_id": hacker_id,
                            "points": h["points"]}
        return {"error": "not_found"}

    # ------------------------------------------------------------------ #
    def create_post(self, title: str, body: str, category: str,
                    author: str) -> Dict[str, Any]:
        pid = "post_" + uuid.uuid4().hex[:10]
        with self._lock:
            self._posts[pid] = {
                "post_id": pid, "title": title, "body": body,
                "category": category, "author": author,
                "likes": 0, "created_at": _now(),
            }
            return self._posts[pid]

    def list_posts(self, category: Optional[str] = None
                   ) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._posts.values())[::-1]
        if category:
            out = [p for p in out if p["category"] == category]
        return out

    def send_message(self, sender: str, receiver: str,
                     content: str) -> Dict[str, Any]:
        mid = "msg_" + uuid.uuid4().hex[:10]
        with self._lock:
            self._messages[mid] = {
                "msg_id": mid, "sender": sender,
                "receiver": receiver, "content": content,
                "read": False, "created_at": _now(),
            }
            return self._messages[mid]

    def list_messages(self, hacker: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [m for m in self._messages.values()
                    if m["receiver"] == hacker][::-1]

    def follow(self, follower: str, target: str) -> Dict[str, Any]:
        with self._lock:
            self._follows.setdefault(follower, set()).add(target)
            return {"follower": follower, "target": target,
                    "followers": len(self._follows.get(target, set()))}

    def honor_wall(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._honor)

    # ------------------------------------------------------------------ #
    def behavior_analysis(self) -> Dict[str, Any]:
        from .bounty_management_phase import get_bounty_phase
        bm = get_bounty_phase()
        lb = bm.leaderboard("bounty", limit=5)
        return {
            "active_hackers": len({p["hacker_id"]
                                  for p in bm.list_payments()}),
            "top": lb,
            "total_posts": len(self._posts),
            "total_messages": len(self._messages),
            "level_catalog": [
                {"level": l, "points": p}
                for l, p in zip(LEVELS, LEVEL_POINTS)],
        }


_default: Optional[HackerCommunityPhase] = None


def get_community_phase() -> HackerCommunityPhase:
    global _default
    if _default is None:
        _default = HackerCommunityPhase()
    return _default
