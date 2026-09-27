#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_pro/response_optimizer.py — API 响应优化。

- 分位统计（P50 / P95 / P99），目标 P95 < 50ms
- 响应缓存 LRU + TTL
- 批量接口合并（一次请求取多个资源，减少往返）
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple


class ResponseOptimizer:
    """响应优化：缓存 + 分位 + 批量合并。"""

    def __init__(self, max_cache: int = 2048, default_ttl: float = 15.0) -> None:
        self._lock = threading.RLock()
        self._store: "OrderedDict[str, Tuple[float, Any]]" = OrderedDict()
        self._max = max_cache
        self._ttl = default_ttl
        self._hits = 0
        self._misses = 0
        # 每路由最近 200 次延迟
        self._lat: Dict[str, List[float]] = {}

    # ---------------- LRU + TTL ---------------- #
    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._store:
                self._misses += 1
                return None
            exp, val = self._store[key]
            if exp < time.time():
                self._store.pop(key, None)
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            return val

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        with self._lock:
            ttl = self._ttl if ttl is None else ttl
            self._store[key] = (time.time() + ttl, value)
            self._store.move_to_end(key)
            while len(self._store) > self._max:
                self._store.popitem(last=False)

    def get_or_set(self, key: str, producer: Callable[[], Any],
                   ttl: Optional[float] = None) -> Tuple[Any, bool]:
        cached = self.get(key)
        if cached is not None:
            return cached, True
        val = producer()
        self.set(key, val, ttl)
        return val, False

    def invalidate(self, key: str) -> bool:
        with self._lock:
            return self._store.pop(key, None) is not None

    def clear(self) -> int:
        with self._lock:
            n = len(self._store)
            self._store.clear()
            return n

    # ---------------- 分位统计 ---------------- #
    def record(self, route: str, ms: float) -> None:
        with self._lock:
            arr = self._lat.setdefault(route, [])
            arr.append(ms)
            if len(arr) > 200:
                del arr[:len(arr) - 200]

    @staticmethod
    def _pct(sorted_vals: List[float], p: float) -> float:
        if not sorted_vals:
            return 0.0
        idx = min(len(sorted_vals) - 1, int(len(sorted_vals) * p))
        return round(sorted_vals[idx], 2)

    def overall_pct(self) -> Dict[str, float]:
        with self._lock:
            allv = [v for arr in self._lat.values() for v in arr]
            allv.sort()
            return {
                "p50": self._pct(allv, 0.50),
                "p95": self._pct(allv, 0.95),
                "p99": self._pct(allv, 0.99),
                "samples": len(allv),
                "target_p95": 50.0,
                "meets_target": self._pct(allv, 0.95) < 50.0,
            }

    # ---------------- 批量合并 ---------------- #
    def batch_merge(self, items: Dict[str, Callable[[], Any]]) -> Dict[str, Any]:
        """一次调用合并多个资源：每个资源走 get_or_set。"""
        out: Dict[str, Any] = {}
        for key, producer in items.items():
            val, hit = self.get_or_set(f"batch::{key}", producer)
            out[key] = {"value": val, "from_cache": hit}
        return out

    # ---------------- 统计 ---------------- #
    def cache_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            return {"size": len(self._store), "max_size": self._max,
                    "hits": self._hits, "misses": self._misses,
                    "hit_rate": round(self._hits / total * 100, 1) if total else 0.0,
                    "default_ttl": self._ttl}


_opt: ResponseOptimizer | None = None


def get_response_optimizer() -> ResponseOptimizer:
    global _opt
    if _opt is None:
        _opt = ResponseOptimizer()
    return _opt
