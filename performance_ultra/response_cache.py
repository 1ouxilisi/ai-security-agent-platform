#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_ultra/response_cache.py — 响应缓存层（LRU + TTL）。

相同请求直接返回缓存；目标 P95 < 50ms。
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Optional, Tuple


class ResponseCache:
    """线程安全的 LRU + TTL 响应缓存。"""

    def __init__(self, max_size: int = 1024, default_ttl: float = 30.0) -> None:
        self._lock = threading.RLock()
        self._store: "OrderedDict[str, Tuple[float, Any]]" = OrderedDict()
        self._max = max_size
        self._ttl = default_ttl
        self._hits = 0
        self._misses = 0

    def _evict_expired_locked(self) -> None:
        now = time.time()
        expired = [k for k, (exp, _) in self._store.items() if exp < now]
        for k in expired:
            self._store.pop(k, None)

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
        """返回 (value, from_cache)。"""
        cached = self.get(key)
        if cached is not None:
            return cached, True
        val = producer()
        self.set(key, val, ttl)
        return val, False

    def invalidate(self, key: str) -> bool:
        with self._lock:
            return self._store.pop(key, None) is not None

    def invalidate_prefix(self, prefix: str) -> int:
        with self._lock:
            keys = [k for k in self._store if k.startswith(prefix)]
            for k in keys:
                self._store.pop(k, None)
            return len(keys)

    def clear(self) -> int:
        with self._lock:
            n = len(self._store)
            self._store.clear()
            return n

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            return {
                "size": len(self._store),
                "max_size": self._max,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(self._hits / total * 100, 1) if total else 0.0,
                "default_ttl": self._ttl,
            }


_cache: ResponseCache | None = None


def get_response_cache() -> ResponseCache:
    global _cache
    if _cache is None:
        _cache = ResponseCache()
    return _cache
