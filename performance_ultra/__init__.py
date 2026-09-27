# -*- coding: utf-8 -*-
"""performance_ultra — 方向4：性能极致优化（延迟加载 / 响应缓存 / 异步队列 / DB优化 / 监控）。"""

from __future__ import annotations

__version__ = "4.0.0"
__direction__ = "D4-性能极致优化"

from .lazy_loader import get_lazy_loader, LazyModule
from .response_cache import ResponseCache, get_response_cache
from .async_queue import AsyncQueue, get_async_queue
from .db_optimizer import DbOptimizer, get_db_optimizer
from .perf_monitor import PerfMonitor, get_perf_monitor
from .perf_dashboard import get_perf_dashboard

__all__ = [
    "get_lazy_loader", "LazyModule",
    "ResponseCache", "get_response_cache",
    "AsyncQueue", "get_async_queue",
    "DbOptimizer", "get_db_optimizer",
    "PerfMonitor", "get_perf_monitor",
    "get_perf_dashboard",
]
