# -*- coding: utf-8 -*-
"""
realtime_push.py — 云安全 Pro 实时推送（WebSocket）。

功能:
    - 管理 WebSocket 连接池
    - 推送进度（整体 + 单步 + ETA）
    - 推送日志流（8 级颜色：TRACE/DEBUG/INFO/NOTICE/WARNING/ERROR/CRITICAL/SUCCESS）
    - 推送思考过程（AI 推理步骤可视化）
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional, Set


# 8 级日志颜色
LOG_LEVEL_COLORS = {
    "TRACE": "#8a90a0",
    "DEBUG": "#7f8c8d",
    "INFO": "#4fc3f7",
    "NOTICE": "#9b59b6",
    "SUCCESS": "#2ecc71",
    "WARNING": "#f1c40f",
    "ERROR": "#e67e22",
    "CRITICAL": "#e74c3c",
}


class RealtimePushManager:
    """WebSocket 推送管理器（内存连接池）。"""

    def __init__(self) -> None:
        self._conns: Set[Any] = set()
        self._task_logs: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ------------------------------------------------------------------ #
    async def connect(self, ws: Any) -> None:
        await ws.accept()
        # 记录主事件循环，供后台线程调度推送
        self._loop = asyncio.get_running_loop()
        async with self._lock:
            self._conns.add(ws)

    async def disconnect(self, ws: Any) -> None:
        async with self._lock:
            self._conns.discard(ws)

    # ------------------------------------------------------------------ #
    async def broadcast(self, msg: Dict[str, Any]) -> None:
        dead = []
        for ws in list(self._conns):
            try:
                await ws.send_json(msg)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._conns.discard(ws)

    # ------------------------------------------------------------------ #
    # 推送原语
    # ------------------------------------------------------------------ #
    async def push_log(self, task_id: str, level: str,
                       message: str, stage: str = "") -> None:
        entry = {
            "type": "log",
            "task_id": task_id,
            "level": level.upper(),
            "color": LOG_LEVEL_COLORS.get(level.upper(), "#fff"),
            "stage": stage,
            "message": message,
            "ts": time.strftime("%H:%M:%S"),
        }
        self._task_logs.setdefault(task_id, []).append(entry)
        await self.broadcast(entry)

    async def push_progress(self, task_id: str, percent: int,
                            stage: str, stage_label: str,
                            eta_sec: Optional[int] = None) -> None:
        await self.broadcast({
            "type": "progress",
            "task_id": task_id,
            "percent": percent,
            "stage": stage,
            "stage_label": stage_label,
            "eta_sec": eta_sec,
            "ts": time.strftime("%H:%M:%S"),
        })

    async def push_thought(self, task_id: str, thought: str,
                           stage: str = "") -> None:
        await self.broadcast({
            "type": "thought",
            "task_id": task_id,
            "stage": stage,
            "thought": thought,
            "ts": time.strftime("%H:%M:%S"),
        })

    async def push_stage(self, task_id: str, stage: str,
                         status: str, summary: str = "") -> None:
        await self.broadcast({
            "type": "stage",
            "task_id": task_id,
            "stage": stage,
            "status": status,
            "summary": summary,
            "ts": time.strftime("%H:%M:%S"),
        })

    # ------------------------------------------------------------------ #
    # 同步接口（供后台线程调用 asyncio 事件循环）
    # ------------------------------------------------------------------ #
    def sync_log(self, task_id: str, level: str, message: str,
                 stage: str = "") -> None:
        # 先落内存日志（即使无 WS 连接也可通过 /logs 拉取）
        entry = {
            "type": "log", "task_id": task_id,
            "level": level.upper(),
            "color": LOG_LEVEL_COLORS.get(level.upper(), "#fff"),
            "stage": stage, "message": message,
            "ts": time.strftime("%H:%M:%S"),
        }
        self._task_logs.setdefault(task_id, []).append(entry)
        self._run_coro(lambda: self.push_log(
            task_id, level, message, stage))

    def sync_progress(self, task_id: str, percent: int, stage: str,
                      stage_label: str,
                      eta_sec: Optional[int] = None) -> None:
        self._run_coro(lambda: self.push_progress(
            task_id, percent, stage, stage_label, eta_sec))

    def sync_thought(self, task_id: str, thought: str,
                     stage: str = "") -> None:
        self._run_coro(lambda: self.push_thought(task_id, thought, stage))

    def sync_stage(self, task_id: str, stage: str, status: str,
                   summary: str = "") -> None:
        self._run_coro(lambda: self.push_stage(
            task_id, stage, status, summary))

    def _run_coro(self, factory) -> None:
        """仅在主事件循环存活时调度；否则丢弃（不产生未 await 警告）。"""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            asyncio.run_coroutine_threadsafe(factory(), loop)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ #
    def get_logs(self, task_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        return self._task_logs.get(task_id, [])[-limit:]

    def connection_count(self) -> int:
        return len(self._conns)


_default_push: Optional[RealtimePushManager] = None


def get_push_manager() -> RealtimePushManager:
    global _default_push
    if _default_push is None:
        _default_push = RealtimePushManager()
    return _default_push
