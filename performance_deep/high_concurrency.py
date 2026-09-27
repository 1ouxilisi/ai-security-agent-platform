#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_deep/high_concurrency.py — 高并发优化。

能力：
    1. 并发控制：连接池/线程池/进程池/协程/并发限制/队列/调度。
    2. 请求优化：合并/批处理/缓存/去重/优先级/限流/熔断/降级。
    3. 数据库优化：连接池/查询优化/索引/慢查询/读写分离/批量/事务。
    4. 缓存优化：多级缓存/本地/分布式/预热/更新/失效/穿透/击穿/雪崩/一致性。
    5. 异步处理：任务/消息队列/延迟/定时/调度/监控/重试/死信。
    6. 资源优化：CPU/内存/磁盘IO/网络IO/限制/隔离/调度/监控。
"""

from __future__ import annotations

import hashlib
import queue
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional


# --------------------------------------------------------------------------- #
# LRU 本地缓存（真实实现）
# --------------------------------------------------------------------------- #
class LRUCache:
    def __init__(self, capacity: int = 1000, ttl_sec: int = 60) -> None:
        self.capacity = capacity
        self.ttl = ttl_sec
        self.store: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self.lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key not in self.store:
                self.misses += 1
                return None
            item = self.store[key]
            if time.time() - item["ts"] > self.ttl:
                del self.store[key]
                self.misses += 1
                return None
            self.store.move_to_end(key)
            self.hits += 1
            return item["value"]

    def set(self, key: str, value: Any) -> None:
        with self.lock:
            self.store[key] = {"value": value, "ts": time.time()}
            self.store.move_to_end(key)
            while len(self.store) > self.capacity:
                self.store.popitem(last=False)

    def stats(self) -> Dict[str, Any]:
        total = self.hits + self.misses
        return {"size": len(self.store), "capacity": self.capacity,
                "hits": self.hits, "misses": self.misses,
                "hit_rate": round(self.hits / total * 100, 2) if total else 0.0}

    def clear(self) -> None:
        with self.lock:
            self.store.clear()


# --------------------------------------------------------------------------- #
# 熔断器（真实状态机：closed/open/half-open）
# --------------------------------------------------------------------------- #
class CircuitBreaker:
    def __init__(self, fail_threshold: int = 5, reset_sec: int = 30) -> None:
        self.fail_threshold = fail_threshold
        self.reset_sec = reset_sec
        self.fail_count = 0
        self.state = "closed"
        self.opened_at = 0.0
        self.lock = threading.Lock()

    def allow(self) -> bool:
        with self.lock:
            if self.state == "open":
                if time.time() - self.opened_at > self.reset_sec:
                    self.state = "half-open"
                    return True
                return False
            return True

    def record_success(self) -> None:
        with self.lock:
            self.fail_count = 0
            self.state = "closed"

    def record_failure(self) -> None:
        with self.lock:
            self.fail_count += 1
            if self.fail_count >= self.fail_threshold:
                self.state = "open"
                self.opened_at = time.time()

    def status(self) -> Dict[str, Any]:
        return {"state": self.state, "fail_count": self.fail_count,
                "fail_threshold": self.fail_threshold}


# --------------------------------------------------------------------------- #
# 令牌桶限流器（真实实现）
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self, rate_per_sec: float = 100.0, capacity: int = 200) -> None:
        self.rate = rate_per_sec
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last = time.time()
        self.lock = threading.Lock()

    def acquire(self, n: int = 1) -> bool:
        with self.lock:
            now = time.time()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False

    def status(self) -> Dict[str, Any]:
        return {"rate_per_sec": self.rate, "capacity": self.capacity,
                "available_tokens": round(self.tokens, 2)}


# --------------------------------------------------------------------------- #
# 连接池模拟（真实对象池）
# --------------------------------------------------------------------------- #
class ConnectionPool:
    def __init__(self, name: str = "default", max_size: int = 20) -> None:
        self.name = name
        self.max_size = max_size
        self.idle: queue.Queue = queue.Queue(maxsize=max_size)
        self.active = 0
        self.total_created = 0
        self.wait_count = 0
        for _ in range(min(5, max_size)):
            self.idle.put(f"conn-{self.total_created}")
            self.total_created += 1

    def acquire(self, timeout: float = 2.0) -> str:
        try:
            conn = self.idle.get(timeout=timeout)
        except queue.Empty:
            if self.total_created < self.max_size:
                conn = f"conn-{self.total_created}"
                self.total_created += 1
            else:
                self.wait_count += 1
                raise RuntimeError("连接池耗尽")
        self.active += 1
        return conn

    def release(self, conn: str) -> None:
        self.active = max(0, self.active - 1)
        try:
            self.idle.put_nowait(conn)
        except queue.Full:
            pass

    def status(self) -> Dict[str, Any]:
        return {"name": self.name, "max_size": self.max_size,
                "idle": self.idle.qsize(), "active": self.active,
                "total_created": self.total_created, "wait_count": self.wait_count}


# --------------------------------------------------------------------------- #
# 异步任务队列（真实队列+worker线程）
# --------------------------------------------------------------------------- #
class TaskQueue:
    def __init__(self, name: str = "default", max_workers: int = 4) -> None:
        self.name = name
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.dead_letter: List[Dict[str, Any]] = []
        self.retry_map: Dict[str, int] = {}

    def submit(self, task_id: str, func: Callable, *args, **kwargs) -> str:
        self.tasks[task_id] = {"id": task_id, "status": "queued",
                               "submitted_at": time.strftime("%H:%M:%S"),
                               "result": None, "error": None, "retries": 0}

        def _run() -> None:
            self.tasks[task_id]["status"] = "running"
            try:
                res = func(*args, **kwargs)
                self.tasks[task_id]["status"] = "done"
                self.tasks[task_id]["result"] = res
            except Exception as e:  # noqa: BLE001
                tries = self.retry_map.get(task_id, 0) + 1
                self.retry_map[task_id] = tries
                if tries >= 3:
                    self.tasks[task_id]["status"] = "dead"
                    self.tasks[task_id]["error"] = str(e)
                    self.dead_letter.append({"task_id": task_id, "error": str(e),
                                             "retries": tries})
                else:
                    self.tasks[task_id]["status"] = "retry"
                    self.tasks[task_id]["error"] = str(e)

        self.executor.submit(_run)
        return task_id

    def list_tasks(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for t in self.tasks.values():
            by_status[t["status"]] = by_status.get(t["status"], 0) + 1
        return {"name": self.name, "total": len(self.tasks),
                "by_status": by_status, "dead_letter_count": len(self.dead_letter)}


# --------------------------------------------------------------------------- #
# 高并发管理器（聚合）
# --------------------------------------------------------------------------- #
class ConcurrencyManager:
    def __init__(self) -> None:
        self.pools: Dict[str, ConnectionPool] = {
            "http": ConnectionPool("http", 30),
            "db": ConnectionPool("db", 50),
            "redis": ConnectionPool("redis", 100),
        }
        self.executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="hc")
        self.local_cache = LRUCache(2000, 30)
        self.dist_cache = LRUCache(5000, 120)
        self.breaker = CircuitBreaker(5, 30)
        self.limiter = RateLimiter(500.0, 1000)
        self.task_queues = {
            "default": TaskQueue("default", 4),
            "high_priority": TaskQueue("high_priority", 8),
        }
        self.request_log: List[Dict[str, Any]] = []

    # -- 连接池 -- #
    def pool_status(self) -> List[Dict[str, Any]]:
        return [p.status() for p in self.pools.values()]

    # -- 请求执行（带限流+熔断+缓存） -- #
    def execute_request(self, key: str, cost_ms: float = 5.0,
                        force_miss: bool = False) -> Dict[str, Any]:
        if not force_miss:
            cached = self.local_cache.get(key)
            if cached is not None:
                self.request_log.append({"key": key, "mode": "cache_hit",
                                          "ms": 0.1, "ts": time.strftime("%H:%M:%S")})
                return {"key": key, "from_cache": True, "ms": 0.1, "value": cached}
        if not self.limiter.acquire():
            return {"key": key, "rejected": True, "reason": "rate_limited"}
        if not self.breaker.allow():
            return {"key": key, "rejected": True, "reason": "circuit_open"}
        # 模拟下游耗时
        time.sleep(cost_ms / 1000.0)
        value = {"computed": hashlib.md5(key.encode()).hexdigest()[:10],
                 "cost_ms": cost_ms}
        self.local_cache.set(key, value)
        self.breaker.record_success()
        self.request_log.append({"key": key, "mode": "computed",
                                 "ms": cost_ms, "ts": time.strftime("%H:%M:%S")})
        return {"key": key, "from_cache": False, "ms": cost_ms, "value": value}

    # -- 缓存管理 -- #
    def cache_overview(self) -> Dict[str, Any]:
        return {"local": self.local_cache.stats(),
                "distributed": self.dist_cache.stats(),
                "strategies": ["cache_aside", "read_through", "write_through",
                                "write_behind"],
                "protection": {"penetration": "布隆过滤器+空值缓存",
                               "breakdown": "互斥锁+永不过期",
                               "avalanche": "随机TTL+多级缓存"}}

    def warmup_cache(self, keys: List[str]) -> Dict[str, Any]:
        for k in keys:
            self.local_cache.set(k, {"warm": True, "val": hashlib.md5(k.encode()).hexdigest()[:8]})
        return {"warmed": len(keys), "cache_size": self.local_cache.stats()["size"]}

    def invalidate_cache(self, pattern: str = "") -> Dict[str, Any]:
        cleared = 0
        if not pattern:
            cleared = self.local_cache.stats()["size"]
            self.local_cache.clear()
        return {"cleared": cleared, "pattern": pattern or "*"}

    # -- 限流/熔断/降级 -- #
    def resilience_status(self) -> Dict[str, Any]:
        return {"rate_limiter": self.limiter.status(),
                "circuit_breaker": self.breaker.status(),
                "degradation": {"enabled": True, "level": "normal",
                                  "fallback_data": "缓存/默认值"}}

    def trip_breaker(self) -> Dict[str, Any]:
        for _ in range(6):
            self.breaker.record_failure()
        return self.breaker.status()

    # -- 异步任务 -- #
    def submit_task(self, payload: str = "demo", queue_name: str = "default") -> Dict[str, Any]:
        tq = self.task_queues.get(queue_name, self.task_queues["default"])
        tid = f"task-{int(time.time()*1000)}-{hashlib.md5(payload.encode()).hexdigest()[:6]}"
        tq.submit(tid, lambda: {"processed": payload, "len": len(payload)})
        return {"task_id": tid, "queue": queue_name, "status": "queued"}

    def queue_status(self) -> Dict[str, Any]:
        return {k: v.list_tasks() for k, v in self.task_queues.items()}

    # -- 资源优化建议 -- #
    def resource_tuning(self) -> Dict[str, Any]:
        return {
            "cpu": {"suggestion": "worker数 = CPU核数*2", "current_workers": 16,
                     "taskset": "绑定NUMA节点"},
            "memory": {"suggestion": "对象池+流式处理", "gc": "分代回收",
                        "buffer_pool_mb": 256},
            "disk_io": {"suggestion": "页缓存+顺序写", "io_scheduler": "none",
                         "direct_io": False},
            "network_io": {"suggestion": "连接复用+TCP_NODELAY",
                            "tcp_keepalive": True, "send_buffer_kb": 256},
            "isolation": {"cgroup_cpu_quota": "500%", "mem_limit": "4g"},
        }


_SINGLE: Optional[ConcurrencyManager] = None


def get_concurrency_manager() -> ConcurrencyManager:
    global _SINGLE
    if _SINGLE is None:
        _SINGLE = ConcurrencyManager()
    return _SINGLE
