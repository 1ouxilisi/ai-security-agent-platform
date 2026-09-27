# -*- coding: utf-8 -*-
"""
log_streamer.py — 实时日志流。

按日志级别（debug/info/warn/error/vuln/tool/thinking）分类缓存最近日志，
支持暂停 / 继续 / 清空，并可按级别过滤。日志条目带颜色建议，供前端渲染。
纯内存环形缓冲。
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass, asdict
from typing import Any, Deque, Dict, List, Optional


# 日志级别 → 前端颜色
LEVEL_COLORS: Dict[str, str] = {
    "debug": "#8b949e",
    "info": "#58a6ff",
    "tool": "#a371f7",
    "thinking": "#d2a8ff",
    "warn": "#d29922",
    "vuln": "#f85149",
    "error": "#ff7b72",
    "ok": "#3fb950",
}


@dataclass
class LogEntry:
    """一条日志。"""

    log_id: str
    task_id: str
    level: str
    message: str
    source: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["color"] = LEVEL_COLORS.get(self.level, "#e6edf3")
        return d


class LogStreamer:
    """按 task 缓存最近日志，支持暂停/清空/过滤。"""

    def __init__(self, maxlen: int = 500) -> None:
        self._maxlen = maxlen
        # task_id -> deque[LogEntry]
        self._bufs: Dict[str, Deque[LogEntry]] = {}
        # task_id -> 是否暂停（暂停时不推送，但仍缓存）
        self._paused: Dict[str, bool] = {}
        self._listeners: List[Any] = []

    # ------------------------------------------------------------------ #
    def log(self, task_id: str, level: str, message: str,
            source: str = "") -> LogEntry:
        entry = LogEntry(
            log_id=f"log_{uuid.uuid4().hex[:8]}",
            task_id=task_id,
            level=level,
            message=message,
            source=source,
            timestamp=time.time(),
        )
        buf = self._bufs.setdefault(task_id, deque(maxlen=self._maxlen))
        buf.append(entry)
        return entry

    # 便捷方法
    def info(self, task_id: str, msg: str, src: str = "") -> LogEntry:
        return self.log(task_id, "info", msg, src)

    def tool(self, task_id: str, msg: str, src: str = "") -> LogEntry:
        return self.log(task_id, "tool", msg, src)

    def thinking(self, task_id: str, msg: str, src: str = "") -> LogEntry:
        return self.log(task_id, "thinking", msg, src)

    def vuln(self, task_id: str, msg: str, src: str = "") -> LogEntry:
        return self.log(task_id, "vuln", msg, src)

    def warn(self, task_id: str, msg: str, src: str = "") -> LogEntry:
        return self.log(task_id, "warn", msg, src)

    def error(self, task_id: str, msg: str, src: str = "") -> LogEntry:
        return self.log(task_id, "error", msg, src)

    def ok(self, task_id: str, msg: str, src: str = "") -> LogEntry:
        return self.log(task_id, "ok", msg, src)

    # ------------------------------------------------------------------ #
    def set_paused(self, task_id: str, paused: bool) -> None:
        self._paused[task_id] = paused

    def is_paused(self, task_id: str) -> bool:
        return self._paused.get(task_id, False)

    def clear(self, task_id: str) -> int:
        n = len(self._bufs.get(task_id, []))
        self._bufs[task_id] = deque(maxlen=self._maxlen)
        return n

    # ------------------------------------------------------------------ #
    def tail(self, task_id: str, limit: int = 200,
             level: str = "") -> List[Dict[str, Any]]:
        buf = self._bufs.get(task_id, [])
        items = list(buf)
        if level:
            items = [e for e in items if e.level == level]
        return [e.to_dict() for e in items[-limit:]]

    def stats(self) -> Dict[str, Any]:
        total = sum(len(b) for b in self._bufs.values())
        by_level: Dict[str, int] = {}
        for buf in self._bufs.values():
            for e in buf:
                by_level[e.level] = by_level.get(e.level, 0) + 1
        return {
            "streams": len(self._bufs),
            "total_logs": total,
            "by_level": by_level,
            "colors": LEVEL_COLORS,
        }


streamer = LogStreamer()
