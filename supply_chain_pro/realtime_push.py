# -*- coding: utf-8 -*-
"""
realtime_push.py — 方向2 供应链安全 Pro：WebSocket 实时推送。

功能:
    - WebSocket 实时推送扫描进度
    - 进度条（整体进度 + 单步 + ETA）
    - 日志流（8 级颜色）
    - 思考过程可视化
    - 依赖树实时可视化
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect


LEVEL_COLORS = {
    "debug": "#95a5a6",
    "info": "#4fc3f7",
    "ok": "#2ecc71",
    "warn": "#f1c40f",
    "error": "#e74c3c",
    "crit": "#ff5252",
    "think": "#bb86fc",
    "step": "#4fc3f7",
}


class ConnectionManager:
    """WebSocket 连接管理器（按 channel=task_id 分组）。"""

    def __init__(self) -> None:
        self._conns: Dict[str, Set[WebSocket]] = defaultdict(set)

    async def connect(self, ws: WebSocket, channel: str) -> None:
        await ws.accept()
        self._conns[channel].add(ws)

    def disconnect(self, ws: WebSocket, channel: str) -> None:
        self._conns.get(channel, set()).discard(ws)

    async def broadcast(self, channel: str, message: Dict[str, Any]
                        ) -> None:
        dead: List[WebSocket] = []
        for ws in list(self._conns.get(channel, set())):
            try:
                await ws.send_json(message)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, channel)


# 单例
manager = ConnectionManager()

# 每个任务的事件缓冲（即使没有 WS 连接也保留最近事件）
EVENT_BUFFER: Dict[str, Deque[Dict[str, Any]]] = defaultdict(
    lambda: deque(maxlen=500))


async def push_event(task_id: str, etype: str, data: Dict[str, Any],
                     level: str = "info") -> None:
    """向某任务频道推送一个事件。"""
    evt = {
        "type": etype,
        "task_id": task_id,
        "ts": time.time(),
        "level": level,
        "color": LEVEL_COLORS.get(level, "#e6e8ee"),
        "data": data,
    }
    EVENT_BUFFER[task_id].append(evt)
    await manager.broadcast(task_id, evt)


def push_event_sync(task_id: str, etype: str, data: Dict[str, Any],
                    level: str = "info") -> None:
    """同步线程中调用：把协程调度到事件循环。"""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(
            push_event(task_id, etype, data, level), loop)
    else:
        # 后台线程：直接缓冲，不广播
        evt = {
            "type": etype, "task_id": task_id,
            "ts": time.time(), "level": level,
            "color": LEVEL_COLORS.get(level, "#e6e8ee"),
            "data": data,
        }
        EVENT_BUFFER[task_id].append(evt)


def snapshot(task_id: str) -> Dict[str, Any]:
    return {
        "task_id": task_id,
        "events": list(EVENT_BUFFER.get(task_id, [])),
    }


async def ws_chain(websocket: WebSocket, task_id: str) -> None:
    """WebSocket 主循环。"""
    conn_id = "conn_" + uuid.uuid4().hex[:8]
    await manager.connect(websocket, task_id)
    try:
        await websocket.send_json({
            "type": "connected", "task_id": task_id,
            "conn_id": conn_id, "ts": time.time(),
            "data": {"msg": "供应链安全 WebSocket 已连接"},
        })
        # 推送历史缓冲
        for evt in list(EVENT_BUFFER.get(task_id, []))[-200:]:
            await websocket.send_json(evt)
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket, task_id)
    except Exception:  # noqa: BLE001
        manager.disconnect(websocket, task_id)


__all__ = [
    "manager", "push_event", "push_event_sync", "snapshot",
    "ws_chain", "LEVEL_COLORS", "ConnectionManager",
]
