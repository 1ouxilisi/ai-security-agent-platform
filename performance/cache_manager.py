# -*- coding: utf-8 -*-
"""
performance/cache_manager.py — 多级缓存管理器（单例，不依赖 Redis）

功能：
    - 多级缓存：L1 内存缓存（dict）+ 文件缓存持久化（JSON）；
    - 缓存策略：可配置 TTL / LRU / LFU / FIFO，默认 LRU + TTL；
    - 缓存预热：启动时预热热点数据（常用 key/配置/字典表）；
    - 缓存失效：TTL 过期 / 手动失效 / 按前缀批量失效 / 清空；
    - 缓存统计：命中率 / miss 率 / 大小 / 条目数 / 淘汰次数；
    - 实时监控：命中率 / 内存估算 / 淘汰次数。

仅依赖标准库，持久化到 data/performance/cache/ 目录。
"""
import json
import os
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Optional


class CacheManager:
    """多级缓存管理器：L1 内存（LRU/LFU/FIFO+TTL）+ L2 文件持久化。单例。"""

    _instance: Optional["CacheManager"] = None
    _lock = threading.Lock()

    def __new__(cls,
                strategy: str = "LRU",
                default_ttl: int = 60,
                max_entries: int = 1000) -> "CacheManager":
        """线程安全单例构造。"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    obj = super().__new__(cls)
                    obj._init(strategy, default_ttl, max_entries)
                    cls._instance = obj
        return cls._instance

    def _init(self, strategy: str, default_ttl: int, max_entries: int) -> None:
        """初始化缓存存储、策略与统计计数器。"""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(root, "data", "performance", "cache")
        os.makedirs(self.data_dir, exist_ok=True)
        self.strategy = strategy.upper()
        self.default_ttl = default_ttl
        self.max_entries = max_entries

        # L1 内存缓存：key -> {"value", "expire_at", "freq", "insert_at"}
        self._store: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        # 统计
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._lock = threading.RLock()
        # 预热钩子（可选）
        self._warmup_provider: Optional[Callable[[], Dict[str, Any]]] = None

    # ------------------------------------------------------------------
    # 基础读写
    # ------------------------------------------------------------------
    def get(self, key: str) -> Any:
        """读取缓存；命中且未过期返回 value，否则返回 None。"""
        now = time.time()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return self._read_l2(key, now)
            if entry["expire_at"] < now:
                del self._store[key]
                self._misses += 1
                return None
            # 命中
            self._hits += 1
            entry["freq"] += 1
            # LRU：移到末尾表示最近使用
            if self.strategy == "LRU":
                self._store.move_to_end(key)
            return entry["value"]

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """写入缓存，并按需淘汰。"""
        expire = time.time() + (ttl if ttl is not None else self.default_ttl)
        with self._lock:
            self._store[key] = {
                "value": value, "expire_at": expire,
                "freq": 1, "insert_at": time.time(),
            }
            # 新元素放末尾（LRU/FIFO 语义一致）
            self._store.move_to_end(key)
            self._write_l2(key, self._store[key])
            # 容量淘汰
            while len(self._store) > self.max_entries:
                self._evict()

    def delete(self, key: str) -> bool:
        """删除指定 key，返回是否删除成功。"""
        with self._lock:
            existed = self._store.pop(key, None) is not None
            self._delete_l2(key)
            return existed

    def clear(self, pattern: Optional[str] = None) -> int:
        """清空缓存。pattern 为 None 清空全部；否则按前缀批量失效。"""
        with self._lock:
            if pattern is None:
                n = len(self._store)
                self._store.clear()
                self._clear_l2_all()
                return n
            keys = [k for k in self._store if k.startswith(pattern)]
            for k in keys:
                del self._store[k]
                self._delete_l2(k)
            return len(keys)

    # ------------------------------------------------------------------
    # 淘汰策略
    # ------------------------------------------------------------------
    def _evict(self) -> None:
        """根据策略选择淘汰项（调用方持锁）。"""
        if not self._store:
            return
        if self.strategy == "FIFO":
            key, _ = next(iter(self._store.items()))
        elif self.strategy == "LFU":
            key = min(self._store, key=lambda k: self._store[k]["freq"])
        else:  # LRU（默认）
            key, _ = next(iter(self._store.items()))
        removed = self._store.pop(key, None)
        if removed is not None:
            self._evictions += 1
            self._delete_l2(key)

    # ------------------------------------------------------------------
    # L2 文件持久化
    # ------------------------------------------------------------------
    def _l2_path(self, key: str) -> str:
        """根据 key 生成文件缓存路径（安全文件名）。"""
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in key)
        return os.path.join(self.data_dir, f"{safe}.json")

    def _write_l2(self, key: str, entry: Dict[str, Any]) -> None:
        """将 entry 写入文件缓存（容错）。"""
        try:
            with open(self._l2_path(key), "w", encoding="utf-8") as f:
                json.dump({"key": key, **entry}, f, ensure_ascii=False)
        except Exception:
            pass

    def _read_l2(self, key: str, now: float) -> Any:
        """从文件缓存读取（容错），命中后回填 L1。"""
        try:
            path = self._l2_path(key)
            if not os.path.exists(path):
                return None
            with open(path, "r", encoding="utf-8") as f:
                entry = json.load(f)
            if entry.get("expire_at", 0) < now:
                return None
            with self._lock:
                self._store[key] = entry
            self._hits += 1
            return entry.get("value")
        except Exception:
            return None

    def _delete_l2(self, key: str) -> None:
        """删除文件缓存（容错）。"""
        try:
            p = self._l2_path(key)
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass

    def _clear_l2_all(self) -> None:
        """清空文件缓存目录（容错）。"""
        try:
            for name in os.listdir(self.data_dir):
                if name.endswith(".json"):
                    os.remove(os.path.join(self.data_dir, name))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 预热
    # ------------------------------------------------------------------
    def warmup(self, hot_keys: Optional[Dict[str, Any]] = None) -> int:
        """预热缓存：写入热点 key。

        Args:
            hot_keys: {key: value}；为空时尝试调用预热钩子。

        Returns:
            int: 预热写入条数。
        """
        try:
            data: Dict[str, Any] = dict(hot_keys or {})
            if not data and self._warmup_provider is not None:
                try:
                    data = dict(self._warmup_provider() or {})
                except Exception:
                    data = {}
            # 默认预热项
            if not data:
                data = {
                    "config:default": {"ttl": self.default_ttl, "strategy": self.strategy},
                    "dict:system": {"cache": True, "level": "warmup"},
                }
            for k, v in data.items():
                self.set(k, v)
            return len(data)
        except Exception:
            return 0

    def register_warmup_provider(self, provider: Callable[[], Dict[str, Any]]) -> None:
        """注册启动期预热数据来源函数。"""
        self._warmup_provider = provider

    # ------------------------------------------------------------------
    # 统计与监控
    # ------------------------------------------------------------------
    def get_hit_rate(self) -> float:
        """返回缓存命中率（0~1）。"""
        with self._lock:
            total = self._hits + self._misses
            return round(self._hits / total, 4) if total else 0.0

    def get_stats(self) -> Dict[str, Any]:
        """缓存统计：命中率/miss率/条目数/大小/淘汰次数/策略。"""
        with self._lock:
            now = time.time()
            # 惰性清理过期
            expired = [k for k, v in self._store.items() if v["expire_at"] < now]
            for k in expired:
                del self._store[k]
            total = self._hits + self._misses
            mem_est = sum(len(str(k)) + len(str(v["value"]))
                          for k, v in self._store.items()) // 1024
            return {
                "strategy": self.strategy,
                "entries": len(self._store),
                "max_entries": self.max_entries,
                "hits": self._hits,
                "misses": self._misses,
                "total_requests": total,
                "hit_rate": self.get_hit_rate(),
                "miss_rate": round(self._misses / total, 4) if total else 0.0,
                "evictions": self._evictions,
                "expired_removed": len(expired),
                "memory_estimate_kb": mem_est,
                "default_ttl": self.default_ttl,
            }

    def get_status(self) -> Dict[str, Any]:
        """实时监控状态：命中率、内存、淘汰次数、L2 文件数。"""
        try:
            l2_files = 0
            if os.path.isdir(self.data_dir):
                l2_files = len([f for f in os.listdir(self.data_dir) if f.endswith(".json")])
            stats = self.get_stats()
            return {
                "running": True,
                "strategy": self.strategy,
                "hit_rate": stats["hit_rate"],
                "entries": stats["entries"],
                "memory_estimate_kb": stats["memory_estimate_kb"],
                "evictions": stats["evictions"],
                "l2_file_count": l2_files,
                "timestamp": time.time(),
            }
        except Exception as e:
            return {"running": False, "error": str(e)}


# 模块级单例
cache_manager = CacheManager()
