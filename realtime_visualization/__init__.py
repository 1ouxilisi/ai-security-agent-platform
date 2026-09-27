# -*- coding: utf-8 -*-
"""
realtime_visualization — WebSocket 实时可视化。

模块组成：
    - websocket_manager  : WebSocket 连接管理（按 channel 广播/单播）
    - realtime_pusher    : 实时推送器（步骤/工具/发现/AI分析/进度/日志）
    - progress_tracker   : 进度跟踪（整体进度/单步/ETA）
    - log_streamer       : 日志流（分级/暂停/继续/清空）
    - realtime_dashboard : 仪表盘聚合
"""

from __future__ import annotations

from .websocket_manager import manager, WebSocketManager
from .progress_tracker import tracker, ProgressTracker, TaskProgress, StepProgress
from .log_streamer import streamer, LogStreamer, LogEntry, LEVEL_COLORS
from .realtime_pusher import pusher, RealtimePusher
from .realtime_dashboard import dashboard, RealtimeDashboard

__all__ = [
    "manager", "WebSocketManager",
    "tracker", "ProgressTracker", "TaskProgress", "StepProgress",
    "streamer", "LogStreamer", "LogEntry", "LEVEL_COLORS",
    "pusher", "RealtimePusher",
    "dashboard", "RealtimeDashboard",
]

__version__ = "1.0.0"
