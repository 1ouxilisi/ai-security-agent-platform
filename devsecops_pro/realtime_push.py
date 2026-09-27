# -*- coding: utf-8 -*-
"""
realtime_push.py — WebSocket 实时推送。

功能:
    - WebSocket 实时推送扫描进度
    - 进度条（整体进度 + 单步 + ETA）
    - 日志流（8 级颜色）
    - 思考过程可视化
    - 扫描结果实时更新

内存字典维护连接与事件队列。FastAPI WebSocket 在路由层挂载。
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Set


@dataclass
class ProgressEvent:
    task_id: str = ""
    stage: str = ""
    stage_label: str = ""
    overall: int = 0
    stage_progress: int = 0
    eta_seconds: int = 0
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "progress",
            "task_id": self.task_id,
            "stage": self.stage, "stage_label": self.stage_label,
            "overall": self.overall,
            "stage_progress": self.stage_progress,
            "eta_seconds": self.eta_seconds,
            "timestamp": self.timestamp,
        }


LOG_LEVEL_COLORS = {
    "DEBUG": "#95a5a6",
    "INFO": "#4fc3f7",
    "OK": "#2ecc71",
    "WARN": "#f1c40f",
    "ERROR": "#e74c3c",
    "FATAL": "#ff1744",
    "AI": "#ce93d8",
    "THINK": "#b39ddb",
}


class RealtimePush:
    """实时推送中心。"""

    def __init__(self) -> None:
        # task_id -> set of websockets
        self._subscribers: Dict[str, Set[Any]] = {}
        # task_id -> deque of recent events
        self._history: Dict[str, Deque[Dict[str, Any]]] = {}
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ #
    def subscribe(self, task_id: str, ws: Any) -> None:
        self._subscribers.setdefault(task_id, set()).add(ws)

    def unsubscribe(self, task_id: str, ws: Any) -> None:
        if task_id in self._subscribers:
            self._subscribers.discard(ws)

    # ------------------------------------------------------------------ #
    async def _broadcast(self, task_id: str,
                         event: Dict[str, Any]) -> None:
        self._history.setdefault(task_id, deque(maxlen=500)).append(event)
        dead: List[Any] = []
        for ws in list(self._subscribers.get(task_id, set())):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.unsubscribe(task_id, ws)

    # ------------------------------------------------------------------ #
    def emit_progress(self, task_id: str, stage: str,
                      stage_label: str, overall: int,
                      stage_progress: int,
                      eta_seconds: int = 0) -> None:
        ev = ProgressEvent(
            task_id=task_id, stage=stage, stage_label=stage_label,
            overall=overall, stage_progress=stage_progress,
            eta_seconds=eta_seconds,
            timestamp=time.strftime("%H:%M:%S"),
        ).to_dict()
        self._tasks.setdefault(task_id, {})["progress"] = ev
        # 后台线程中不直接 await websocket；事件进入队列，
        # WebSocket 协程通过 poll_history 拉取。
        self._history.setdefault(task_id, deque(maxlen=500)).append(ev)
        self._tasks.setdefault(task_id, {})["last_event"] = ev

    # ------------------------------------------------------------------ #
    def emit_log(self, task_id: str, level: str, message: str) -> None:
        color = LOG_LEVEL_COLORS.get(level.upper(), "#4fc3f7")
        ev = {
            "type": "log",
            "task_id": task_id,
            "level": level.upper(),
            "color": color,
            "message": message,
            "timestamp": time.strftime("%H:%M:%S"),
        }
        self._history.setdefault(task_id, deque(maxlen=500)).append(ev)
        self._tasks.setdefault(task_id, {})["last_event"] = ev

    def emit_thought(self, task_id: str, thought: str) -> None:
        ev = {
            "type": "thought",
            "task_id": task_id,
            "thought": thought,
            "timestamp": time.strftime("%H:%M:%S"),
        }
        self._history.setdefault(task_id, deque(maxlen=500)).append(ev)

    def emit_result(self, task_id: str, stage: str,
                    data: Dict[str, Any]) -> None:
        ev = {
            "type": "result",
            "task_id": task_id,
            "stage": stage,
            "data": data,
            "timestamp": time.strftime("%H:%M:%S"),
        }
        self._history.setdefault(task_id, deque(maxlen=500)).append(ev)

    # ------------------------------------------------------------------ #
    def poll_history(self, task_id: str,
                     after: int = 0) -> List[Dict[str, Any]]:
        hist = list(self._history.get(task_id, []))
        return hist[after:]

    def history(self, task_id: str) -> List[Dict[str, Any]]:
        return list(self._history.get(task_id, []))

    # ------------------------------------------------------------------ #
    def task_state(self, task_id: str) -> Dict[str, Any]:
        return self._tasks.get(task_id, {})


_default: Optional[RealtimePush] = None


def get_realtime_push() -> RealtimePush:
    global _default
    if _default is None:
        _default = RealtimePush()
    return _default
