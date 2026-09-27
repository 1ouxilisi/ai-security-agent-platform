# -*- coding: utf-8 -*-
"""
realtime_push.py — 合规 Pro 实时推送（WebSocket）。

- WebSocket 实时推送检查进度 + 合规状态变化
- 进度条（整体进度 + 单步 + ETA）
- 日志流（8 级颜色）
- 思考过程可视化
- 实时合规状态流
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Set

LOG_LEVEL_COLORS = {
    "DEBUG": "#95a5a6",
    "INFO": "#4fc3f7",
    "OK": "#2ecc71",
    "WARN": "#f1c40f",
    "ERROR": "#e74c3c",
    "FATAL": "#ff1744",
    "AI": "#ce93d8",
    "THINK": "#b39ddb",
    "GAP": "#ff5252",
    "COMPLY": "#2ecc71",
}


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


class RealtimePush:
    """实时推送中心（线程安全，后台线程写入，WS 协程轮询）。"""

    def __init__(self) -> None:
        self._subscribers: Dict[str, Set[Any]] = {}
        self._history: Dict[str, Deque[Dict[str, Any]]] = {}
        self._tasks: Dict[str, Dict[str, Any]] = {}

    def subscribe(self, task_id: str, ws: Any) -> None:
        self._subscribers.setdefault(task_id, set()).add(ws)

    def unsubscribe(self, task_id: str, ws: Any) -> None:
        if task_id in self._subscribers:
            self._subscribers[task_id].discard(ws)

    def _append(self, task_id: str, event: Dict[str, Any]) -> None:
        self._history.setdefault(task_id, deque(maxlen=800)).append(event)
        self._tasks.setdefault(task_id, {})["last_event"] = event

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
        self._append(task_id, ev)

    def emit_log(self, task_id: str, level: str, message: str) -> None:
        color = LOG_LEVEL_COLORS.get(level.upper(), "#4fc3f7")
        ev = {"type": "log", "task_id": task_id, "level": level.upper(),
              "color": color, "message": message,
              "timestamp": time.strftime("%H:%M:%S")}
        self._append(task_id, ev)

    def emit_thought(self, task_id: str, thought: str) -> None:
        ev = {"type": "thought", "task_id": task_id, "thought": thought,
              "timestamp": time.strftime("%H:%M:%S")}
        self._append(task_id, ev)

    def emit_gap(self, task_id: str, gap: Dict[str, Any]) -> None:
        ev = {"type": "gap", "task_id": task_id, "gap": gap,
              "timestamp": time.strftime("%H:%M:%S")}
        self._append(task_id, ev)

    def emit_comply(self, task_id: str,
                    snapshot: Dict[str, Any]) -> None:
        ev = {"type": "comply", "task_id": task_id, "snapshot": snapshot,
              "timestamp": time.strftime("%H:%M:%S")}
        self._append(task_id, ev)

    def emit_result(self, task_id: str, result: Dict[str, Any]) -> None:
        ev = {"type": "result", "task_id": task_id, "result": result,
              "timestamp": time.strftime("%H:%M:%S")}
        self._append(task_id, ev)

    def history(self, task_id: str) -> List[Dict[str, Any]]:
        return list(self._history.get(task_id, deque()))

    def task_state(self, task_id: str) -> Dict[str, Any]:
        return self._tasks.get(task_id, {})


_default: Optional[RealtimePush] = None


def get_realtime_push() -> RealtimePush:
    global _default
    if _default is None:
        _default = RealtimePush()
    return _default
