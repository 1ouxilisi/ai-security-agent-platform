#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_ultra/perf_monitor.py — 性能监控。

记录每个请求的耗时，计算 P50/P95/P99，统计启动耗时、并发、错误率。
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List


def _percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * p
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return round(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f), 2)


class PerfMonitor:
    """进程级性能监控单例。"""

    def __init__(self, window: int = 500) -> None:
        self._lock = threading.RLock()
        self._window = window
        self._latencies: Deque[float] = deque(maxlen=window)
        self._by_route: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=window))
        self._start_ts = time.time()
        self._startup_ms = 0.0
        self._requests = 0
        self._errors = 0
        self._cache_hits = 0

    def mark_startup(self, ms: float) -> None:
        with self._lock:
            self._startup_ms = ms

    def record(self, route: str, ms: float, is_error: bool = False,
               cache_hit: bool = False) -> None:
        with self._lock:
            self._latencies.append(ms)
            self._by_route[route].append(ms)
            self._requests += 1
            if is_error:
                self._errors += 1
            if cache_hit:
                self._cache_hits += 1

    def pct(self) -> Dict[str, float]:
        with self._lock:
            vals = sorted(self._latencies)
            return {
                "p50": _percentile(vals, 0.50),
                "p95": _percentile(vals, 0.95),
                "p99": _percentile(vals, 0.99),
                "avg": round(sum(vals) / len(vals), 2) if vals else 0.0,
                "max": round(vals[-1], 2) if vals else 0.0,
                "samples": len(vals),
            }

    def top_slow_routes(self, n: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            rows = []
            for route, dq in self._by_route.items():
                vals = sorted(dq)
                rows.append({
                    "route": route,
                    "p95": _percentile(vals, 0.95),
                    "avg": round(sum(vals) / len(vals), 2) if vals else 0.0,
                    "count": len(vals),
                })
            rows.sort(key=lambda r: r["p95"], reverse=True)
            return rows[:n]

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            uptime = round(time.time() - self._start_ts, 1)
            return {
                "uptime_sec": uptime,
                "startup_ms": self._startup_ms,
                "total_requests": self._requests,
                "errors": self._errors,
                "error_rate": round(self._errors / self._requests * 100, 2) if self._requests else 0.0,
                "cache_hits": self._cache_hits,
                "latency": self.pct(),
                "target_p95_ms": 50,
                "p95_meets_target": self.pct()["p95"] < 50,
            }


_mon: PerfMonitor | None = None


def get_perf_monitor() -> PerfMonitor:
    global _mon
    if _mon is None:
        _mon = PerfMonitor()
    return _mon
