# -*- coding: utf-8 -*-
"""
websocket_manager.py — WebSocket 连接管理器。

负责：
    - 维护按 channel 分组的 WebSocket 连接（支持广播 / 单播）；
    - 安全地发送 JSON 消息，断线自动清理；
    - 记录每个 channel 的在线连接数，供仪表盘展示。

使用 FastAPI 的 WebSocket；所有发送都包 try/except，避免单连接异常影响整体。
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

try:
    from fastapi import WebSocket, WebSocketDisconnect
    _WS_AVAILABLE = True
except Exception:  # pragma: no cover
    WebSocket = Any  # type: ignore
    WebSocketDisconnect = Exception  # type: ignore
    _WS_AVAILABLE = False


class WebSocketManager:
    """按 channel 管理 WebSocket 连接。"""

    def __init__(self) -> None:
        # channel -> {conn_id: websocket}
        self._channels: Dict[str, Dict[str, WebSocket]] = defaultdict(dict)
        self._meta: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    async def connect(self, websocket: WebSocket, channel: str,
                      conn_id: str) -> None:
        await websocket.accept()
        self._channels[channel][conn_id] = websocket
        self._meta[conn_id] = {
            "channel": channel, "connected_at": time.time(),
        }

    def disconnect(self, channel: str, conn_id: str) -> None:
        if channel in self._channels and conn_id in self._channels[channel]:
            del self._channels[channel][conn_id]
        self._meta.pop(conn_id, None)

    # ------------------------------------------------------------------ #
    async def send_personal(self, conn_id: str, message: Dict[str, Any]) -> bool:
        for ch, conns in self._channels.items():
            if conn_id in conns:
                try:
                    await conns[conn_id].send_json(message)
                    return True
                except Exception:
                    self.disconnect(ch, conn_id)
                    return False
        return False

    async def broadcast(self, channel: str,
                        message: Dict[str, Any]) -> int:
        """向某 channel 广播；返回成功发送的连接数。"""
        conns = dict(self._channels.get(channel, {}))
        ok = 0
        for conn_id, ws in conns.items():
            try:
                await ws.send_json(message)
                ok += 1
            except Exception:
                self.disconnect(channel, conn_id)
        return ok

    async def broadcast_all(self, message: Dict[str, Any]) -> int:
        total = 0
        for ch in list(self._channels.keys()):
            total += await self.broadcast(ch, message)
        return total

    # ------------------------------------------------------------------ #
    # 同步线程里也能安全调用：把协程调度到事件循环
    def broadcast_threadsafe(self, channel: str,
                             message: Dict[str, Any]) -> None:
        """供后台线程（非 asyncio 上下文）调用。"""
        try:
            loop = asyncio.get_running_loop()
            # 已经在事件循环里，直接创建任务
            asyncio.create_task(self.broadcast(channel, message))
        except RuntimeError:
            # 没有运行中的循环（后台线程），找全局循环
            try:
                loops = [a for a in map(asyncio._get_running_loop, [])]  # no-op
            except Exception:
                pass
            # 退化为：直接投递到一个新循环（简单兜底）
            try:
                asyncio.run(self.broadcast(channel, message))
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        return {
            "channels": len(self._channels),
            "total_connections": sum(len(v) for v in self._channels.values()),
            "channel_detail": {
                ch: len(conns) for ch, conns in self._channels.items()
            },
            "ws_available": _WS_AVAILABLE,
        }


manager = WebSocketManager()
