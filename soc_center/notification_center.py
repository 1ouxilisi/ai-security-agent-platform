# -*- coding: utf-8 -*-
"""
notification_center.py — 统一通知中心（WebSocket 统一推送 + 通知铃铛/未读计数）。

消息格式: {"type", "source", "domain", "data", "timestamp"}
消息类型: alert/task/vuln/asset/event/notification/system
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional, Set

from .data_aggregator import get_aggregator


class NotificationCenter:
    """统一通知中心（单例）。"""

    MAX_HISTORY = 100

    def __init__(self) -> None:
        self._history: List[Dict[str, Any]] = []
        self._subscribers: Set[Any] = set()
        self._notifications: List[Dict[str, Any]] = []
        self._unread = 0

    # ------------------------------------------------------------------ #
    def publish(self, msg_type: str, domain: str, data: Any,
                source: str = "system") -> Dict[str, Any]:
        msg = {
            "type": msg_type,
            "source": source,
            "domain": domain,
            "data": data,
            "timestamp": time.time(),
        }
        self._history.append(msg)
        if len(self._history) > self.MAX_HISTORY:
            self._history = self._history[-self.MAX_HISTORY:]
        # 铃铛通知
        self._notifications.insert(0, {
            "id": f"ntf-{int(time.time()*1000)}",
            "type": msg_type,
            "domain": domain,
            "title": self._title_for(msg_type, data),
            "data": data,
            "read": False,
            "created_at": time.time(),
        })
        if len(self._notifications) > 200:
            self._notifications = self._notifications[:200]
        self._unread += 1
        return msg

    @staticmethod
    def _title_for(msg_type: str, data: Any) -> str:
        if isinstance(data, dict):
            title = data.get("title") or data.get("name") or ""
            if title:
                return f"[{msg_type}] {title}"
        return f"[{msg_type}] 新通知"

    # ------------------------------------------------------------------ #
    def history(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._history[-limit:]

    def notifications(self, limit: int = 50) -> Dict[str, Any]:
        items = self._notifications[:limit]
        return {"items": items, "unread": self._unread}

    def mark_read(self, nid: Optional[str] = None) -> Dict[str, Any]:
        if nid is None:
            for n in self._notifications:
                n["read"] = True
            self._unread = 0
        else:
            for n in self._notifications:
                if n["id"] == nid:
                    n["read"] = True
            self._unread = sum(1 for n in self._notifications if not n["read"])
        return {"unread": self._unread}

    # ------------------------------------------------------------------ #
    async def broadcast(self, msg: Dict[str, Any]) -> None:
        dead = []
        for ws in list(self._subscribers):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._subscribers.discard(ws)

    def add(self, ws: Any) -> None:
        self._subscribers.add(ws)

    def remove(self, ws: Any) -> None:
        self._subscribers.discard(ws)

    def subscriber_count(self) -> int:
        return len(self._subscribers)


_default: Optional[NotificationCenter] = None


def get_notification_center() -> NotificationCenter:
    global _default
    if _default is None:
        _default = NotificationCenter()
    return _default
