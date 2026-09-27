# -*- coding: utf-8 -*-
"""
performance/response_cache.py — 进程内响应缓存（单例）

适用于漏洞库查询、知识库查询、工具状态、统计数据等查询类 API：
    - TTL 过期自动失效（惰性删除）；
    - 支持按 key 前缀批量失效；
    - 提供装饰器 cache_decorator 直接缓存函数返回值；
    - 命中率 / 条目数 / 内存占用估算统计。
"""
import hashlib
import threading
import time
from functools import wraps
from typing import Any, Callable, Dict, Optional


class ResponseCache:
    """响应缓存单例：dict + 过期时间戳。"""

    _instance: Optional["ResponseCache"] = None
    _instance_lock = threading.Lock()

    def __new__(cls, ttl: int = 60) -> "ResponseCache":
        # 单例：首次创建后忽略后续 ttl 参数（但允许通过 configure 调整）
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    obj = super().__new__(cls)
                    obj._init(ttl)
                    cls._instance = obj
        return cls._instance

    def _init(self, ttl: int) -> None:
        self.default_ttl = ttl
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------
    # 基础读写
    # ------------------------------------------------------------------
    def get(self, key: str) -> Any:
        """获取缓存，过期返回 None（顺带惰性清理该 key）。"""
        now = time.time()
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self._misses += 1
                return None
            if entry["expire_at"] < now:
                del self._data[key]
                self._misses += 1
                return None
            self._hits += 1
            return entry["value"]

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """写入缓存。"""
        expire = time.time() + (ttl if ttl is not None else self.default_ttl)
        with self._lock:
            self._data[key] = {"value": value, "expire_at": expire}

    def invalidate(self, pattern: Optional[str] = None) -> int:
        """按 key 前缀失效；pattern 为 None 时清空全部。返回失效条数。"""
        with self._lock:
            if pattern is None:
                n = len(self._data)
                self._data.clear()
                return n
            keys = [k for k in self._data if k.startswith(pattern)]
            for k in keys:
                del self._data[k]
            return len(keys)

    def clear(self) -> int:
        """清空所有缓存。"""
        return self.invalidate(None)

    # ------------------------------------------------------------------
    # 统计
    # ------------------------------------------------------------------
    def get_stats(self) -> Dict[str, Any]:
        """缓存统计：命中率、请求数、条目数、内存占用估算。"""
        with self._lock:
            total = self._hits + self._misses
            # 惰性清理过期条目
            now = time.time()
            alive = {k: v for k, v in self._data.items() if v["expire_at"] >= now}
            expired = len(self._data) - len(alive)
            self._data = alive
            # 内存估算：粗估每 key+value 256B
            mem_est_kb = sum(len(str(k)) + len(str(v["value"]))
                             for k, v in alive.items()) // 1024
            return {
                "entries": len(alive),
                "expired_removed": expired,
                "hits": self._hits,
                "misses": self._misses,
                "total_requests": total,
                "hit_rate": round(self._hits / total, 4) if total else 0.0,
                "memory_estimate_kb": mem_est_kb,
            }

    # ------------------------------------------------------------------
    # 装饰器
    # ------------------------------------------------------------------
    def cache_decorator(self, ttl: int = 60,
                        key_func: Optional[Callable[..., str]] = None) -> Callable:
        """函数级缓存装饰器。key_func 缺省时基于函数名+参数 hash。"""

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                if key_func is not None:
                    key = key_func(*args, **kwargs)
                else:
                    raw = f"{func.__module__}.{func.__name__}:{args}:{kwargs}"
                    key = "fn:" + hashlib.md5(raw.encode("utf-8")).hexdigest()
                cached = self.get(key)
                if cached is not None:
                    return cached
                result = func(*args, **kwargs)
                self.set(key, result, ttl=ttl)
                return result

            return wrapper

        return decorator
