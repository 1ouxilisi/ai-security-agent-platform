# -*- coding: utf-8 -*-
"""
realtime_push.py — 方向2 威胁情报 Pro：WebSocket 实时推送。

负责:
    - 维护按 channel 分组的 WebSocket 连接；
    - 实时推送新 IOC / 新威胁 / 匹配告警 / 阶段进度 / 日志流 / AI 思考；
    - 同步线程里也能调用（线程安全广播）。
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

try:
    from fastapi import WebSocket, WebSocketDisconnect
    _WS = True
except Exception:  # pragma: no cover
    WebSocket = Any  # type: ignore
    WebSocketDisconnect = Exception  # type: ignore
    _WS = False

# 8 级日志颜色
LEVEL_COLORS = {
    "DEBUG": "#7f8c8d",
    "INFO": "#4fc3f7",
    "NOTICE": "#9b59b6",
    "WARNING": "#f1c40f",
    "SUCCESS": "#2ecc71",
    "ERROR": "#e67e22",
    "CRITICAL": "#e74c3c",
    "ALERT": "#ff1493",
}


class RealtimePushManager:
    """按 channel 管理 WebSocket 连接并广播事件。"""

    def __init__(self) -> None:
        self._channels: Dict[str, Dict[str, WebSocket]] = defaultdict(dict)
        self._events: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    async def connect(self, ws: WebSocket, channel: str,
                      conn_id: str) -> None:
        await ws.accept()
        self._channels[channel][conn_id] = ws

    def disconnect(self, channel: str, conn_id: str) -> None:
        self._channels.get(channel, {}).pop(conn_id, None)

    # ------------------------------------------------------------------ #
    async def broadcast(self, channel: str,
                        message: Dict[str, Any]) -> int:
        conns = dict(self._channels.get(channel, {}))
        ok = 0
        for cid, ws in conns.items():
            try:
                await ws.send_json(message)
                ok += 1
            except Exception:
                self.disconnect(channel, cid)
        return ok

    async def broadcast_all(self, message: Dict[str, Any]) -> int:
        total = 0
        for ch in list(self._channels.keys()):
            total += await self.broadcast(ch, message)
        return total

    # ------------------------------------------------------------------ #
    # 供后台线程调用
    def push_threadsafe(self, channel: str,
                        event_type: str, data: Dict[str, Any]) -> None:
        msg = {"type": event_type, "ts": time.time(),
               "data": data}
        self._events.append(msg)
        if len(self._events) > 500:
            self._events = self._events[-500:]
        try:
            loop = asyncio.get_running_loop()
            asyncio.create_task(self.broadcast(channel, msg))
        except RuntimeError:
            try:
                asyncio.run(self.broadcast(channel, msg))
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    def snapshot(self) -> List[Dict[str, Any]]:
        return list(self._events[-100:])

    def stats(self) -> Dict[str, Any]:
        return {
            "channels": len(self._channels),
            "total_connections": sum(
                len(v) for v in self._channels.values()),
            "events_buffered": len(self._events),
            "ws_available": _WS,
        }


manager = RealtimePushManager()
