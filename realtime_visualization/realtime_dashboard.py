# -*- coding: utf-8 -*-
"""
realtime_dashboard.py — 实时可视化仪表盘聚合。

把 websocket_manager / progress_tracker / log_streamer / realtime_pusher
聚合成前端一次渲染所需的快照。
"""

from __future__ import annotations

from typing import Any, Dict, List

from .websocket_manager import manager
from .progress_tracker import tracker
from .log_streamer import streamer
from .realtime_pusher import pusher


class RealtimeDashboard:
    """聚合实时可视化各模块状态。"""

    def overview(self) -> Dict[str, Any]:
        return {
            "websocket": manager.stats(),
            "progress": tracker.stats(),
            "logs": streamer.stats(),
            "pusher": pusher.stats(),
        }

    def task_snapshot(self, task_id: str) -> Dict[str, Any]:
        return {
            "task_id": task_id,
            "progress": tracker.snapshot(task_id),
            "logs": streamer.tail(task_id, limit=100),
            "ws": manager.stats()["channel_detail"],
        }

    def tasks_list(self) -> List[Dict[str, Any]]:
        return tracker.list_tasks()

    def log_panel(self, task_id: str, limit: int = 200,
                  level: str = "") -> Dict[str, Any]:
        return {
            "task_id": task_id,
            "paused": streamer.is_paused(task_id),
            "entries": streamer.tail(task_id, limit=limit, level=level),
            "colors": streamer.stats()["colors"],
        }


dashboard = RealtimeDashboard()
