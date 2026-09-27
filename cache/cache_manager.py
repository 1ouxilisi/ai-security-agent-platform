"""
cache_manager模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import time
import hashlib
from typing import Any, Dict, Optional, Tuple
from pathlib import Path
from collections import OrderedDict
from utils.logger import log


class LRUCache:
    """LRU内存缓存"""

    def __init__(self, max_size: int = 1000, ttl: int = 300):
        """初始化LRUCache实例。

        Args:
            self: 类实例。
        """
        self.cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl  # 生存时间（秒）
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        """获取缓存"""
        if key not in self.cache:
            self.misses += 1
            return None

        value, expire_at = self.cache[key]

        # 检查是否过期
        if time.time() > expire_at:
            del self.cache[key]
            self.misses += 1
            return None

        # 移动到末尾（最近使用）
        self.cache.move_to_end(key)
        self.hits += 1
        return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """设置缓存"""
        expire_at = time.time() + (ttl or self.ttl)
        self.cache[key] = (value, expire_at)
        self.cache.move_to_end(key)

        # 淘汰最旧的
        while len(self.cache) > self.max_size:
            self.cache.popitem(last=False)

    def delete(self, key: str):
        """删除缓存"""
        if key in self.cache:
            del self.cache[key]

    def clear(self):
        """清空缓存"""
        self.cache.clear()
        self.hits = 0
        self.misses = 0

    def cleanup_expired(self):
        """清理过期缓存"""
        now = time.time()
        expired_keys = [k for k, (_, expire_at) in self.cache.items() if now > expire_at]
        for k in expired_keys:
            del self.cache[k]
        if expired_keys:
            log.debug(f"清理过期缓存: {len(expired_keys)}条")

    def get_stats(self) -> Dict:
        """获取缓存统计"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(hit_rate, 2),
        }


class DiskCache:
    """磁盘缓存（JSON文件）"""

    def __init__(self, cache_dir: str = "data/cache", ttl: int = 3600):
        """初始化DiskCache实例。

        Args:
            self: 类实例。
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl

    def _get_filepath(self, key: str) -> Path:
        """获取缓存文件路径"""
        safe_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str) -> Optional[Any]:
        """获取磁盘缓存"""
        filepath = self._get_filepath(key)
        if not filepath.exists():
            return None

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            if time.time() > data.get("expire_at", 0):
                filepath.unlink()
                return None

            return data.get("value")
        except Exception as e:
            log.debug(f"读取磁盘缓存失败: {e}")
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """设置磁盘缓存"""
        filepath = self._get_filepath(key)
        data = {
            "value": value,
            "expire_at": time.time() + (ttl or self.ttl),
            "created_at": time.time(),
        }
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, default=str)
        except Exception as e:
            log.debug(f"写入磁盘缓存失败: {e}")

    def delete(self, key: str):
        """删除磁盘缓存"""
        filepath = self._get_filepath(key)
        if filepath.exists():
            filepath.unlink()

    def clear(self):
        """清空磁盘缓存"""
        for f in self.cache_dir.glob("*.json"):
            f.unlink()

    def cleanup_expired(self):
        """清理过期磁盘缓存"""
        now = time.time()
        count = 0
        for f in self.cache_dir.glob("*.json"):
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                if now > data.get("expire_at", 0):
                    f.unlink()
                    count += 1
            except Exception:
                f.unlink()
                count += 1
        if count:
            log.debug(f"清理过期磁盘缓存: {count}个文件")


class CacheManager:
    """多级缓存管理器"""

    def __init__(self, memory_size: int = 1000, memory_ttl: int = 300,
                 disk_dir: str = "data/cache", disk_ttl: int = 3600):
        """初始化CacheManager实例。

        Args:
            self: 类实例。
        """
        self.memory = LRUCache(max_size=memory_size, ttl=memory_ttl)
        self.disk = DiskCache(cache_dir=disk_dir, ttl=disk_ttl)
        log.info(f"缓存管理器初始化: 内存({memory_size}条/{memory_ttl}s) + 磁盘({disk_dir}/{disk_ttl}s)")

    def get(self, key: str, use_disk: bool = True) -> Optional[Any]:
        """多级获取缓存"""
        # 先查内存
        value = self.memory.get(key)
        if value is not None:
            return value

        # 再查磁盘
        if use_disk:
            value = self.disk.get(key)
            if value is not None:
                # 回填到内存
                self.memory.set(key, value)
                return value

        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None,
            persist: bool = True):
        """多级设置缓存"""
        self.memory.set(key, value, ttl)
        if persist:
            self.disk.set(key, value, ttl)

    def delete(self, key: str):
        """删除缓存"""
        self.memory.delete(key)
        self.disk.delete(key)

    def clear(self):
        """清空所有缓存"""
        self.memory.clear()
        self.disk.clear()

    def cleanup(self):
        """清理过期缓存"""
        self.memory.cleanup_expired()
        self.disk.cleanup_expired()

    def get_stats(self) -> Dict:
        """获取缓存统计"""
        return {
            "memory": self.memory.get_stats(),
            "disk": {
                "files": len(list(self.disk.cache_dir.glob("*.json"))),
                "directory": str(self.disk.cache_dir),
            },
        }


# 全局缓存管理器实例
cache_manager = CacheManager()

# 专用缓存
dns_cache = LRUCache(max_size=500, ttl=600)  # DNS缓存10分钟
http_cache = LRUCache(max_size=200, ttl=120)  # HTTP缓存2分钟
tool_result_cache = LRUCache(max_size=300, ttl=300)  # 工具结果缓存5分钟
