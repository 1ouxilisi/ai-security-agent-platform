"""性能优化模块。

包含：内存缓存装饰器、LRU缓存、异步任务队列、连接池、
请求去重、批量处理、性能监控等性能优化功能。
"""
import time
import asyncio
import hashlib
import threading
from typing import Dict, List, Optional, Any, Callable, Tuple
from collections import OrderedDict
from dataclasses import dataclass, field
from functools import wraps
from utils.logger import log


class LRUCache:
    """LRU（最近最少使用）缓存"""
    
    def __init__(self, max_size: int = 1000, ttl: int = 300):
        self.max_size = max_size
        self.ttl = ttl  # 生存时间（秒）
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存"""
        with self._lock:
            if key in self._cache:
                value, expire_time = self._cache[key]
                if time.time() < expire_time:
                    self._cache.move_to_end(key)
                    self._hits += 1
                    return value
                else:
                    del self._cache[key]
            self._misses += 1
            return None
    
    def set(self, key: str, value: Any, ttl: int = None):
        """设置缓存"""
        with self._lock:
            expire_time = time.time() + (ttl or self.ttl)
            self._cache[key] = (value, expire_time)
            self._cache.move_to_end(key)
            
            # 淘汰过期和超出限制的条目
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)
    
    def delete(self, key: str):
        """删除缓存"""
        with self._lock:
            self._cache.pop(key, None)
    
    def clear(self):
        """清空缓存"""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(hit_rate, 2),
                "ttl": self.ttl
            }


# 全局缓存实例
global_cache = LRUCache(max_size=2000, ttl=600)


def cached(max_size: int = 500, ttl: int = 300):
    """缓存装饰器
    
    用法:
        @cached(ttl=300)
        def expensive_function(arg1, arg2):
            ...
    """
    def decorator(func: Callable):
        cache = LRUCache(max_size=max_size, ttl=ttl)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 生成缓存键
            key_parts = [func.__module__, func.__name__]
            key_parts.extend([str(a) for a in args])
            key_parts.extend([f"{k}={v}" for k, v in sorted(kwargs.items())])
            cache_key = hashlib.md5("|".join(key_parts).encode()).hexdigest()
            
            # 尝试从缓存获取
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # 执行函数并缓存结果
            result = func(*args, **kwargs)
            cache.set(cache_key, result)
            return result
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            key_parts = [func.__module__, func.__name__]
            key_parts.extend([str(a) for a in args])
            key_parts.extend([f"{k}={v}" for k, v in sorted(kwargs.items())])
            cache_key = hashlib.md5("|".join(key_parts).encode()).hexdigest()
            
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            result = await func(*args, **kwargs)
            cache.set(cache_key, result)
            return result
        
        wrapper.cache = cache
        wrapper.async_wrapper = async_wrapper
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
    
    return decorator


class AsyncTaskQueue:
    """异步任务队列"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self._queue: asyncio.Queue = None
        self._workers: List[asyncio.Task] = []
        self._results: Dict[str, Any] = {}
        self._running = False
    
    async def start(self):
        """启动任务队列"""
        if self._running:
            return
        
        self._queue = asyncio.Queue(maxsize=1000)
        self._running = True
        
        for i in range(self.max_workers):
            worker = asyncio.create_task(self._worker(i))
            self._workers.append(worker)
        
        log.info(f"异步任务队列已启动，{self.max_workers}个工作线程")
    
    async def stop(self):
        """停止任务队列"""
        self._running = False
        for worker in self._workers:
            worker.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        log.info("异步任务队列已停止")
    
    async def _worker(self, worker_id: int):
        """工作协程"""
        while self._running:
            try:
                task_id, func, args, kwargs = await self._queue.get()
                try:
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = func(*args, **kwargs)
                    self._results[task_id] = {"status": "completed", "result": result}
                except Exception as e:
                    self._results[task_id] = {"status": "failed", "error": str(e)}
                    log.warning(f"任务 {task_id} 执行失败: {e}")
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.warning(f"工作线程 {worker_id} 异常: {e}")
    
    async def submit(self, func: Callable, *args, **kwargs) -> str:
        """提交任务"""
        import uuid
        task_id = str(uuid.uuid4())[:8]
        await self._queue.put((task_id, func, args, kwargs))
        return task_id
    
    async def get_result(self, task_id: str, timeout: float = 30) -> Optional[Dict]:
        """获取任务结果"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if task_id in self._results:
                return self._results.pop(task_id)
            await asyncio.sleep(0.1)
        return {"status": "timeout", "task_id": task_id}
    
    def get_queue_size(self) -> int:
        """获取队列大小"""
        return self._queue.qsize() if self._queue else 0


class ConnectionPool:
    """通用连接池（用于HTTP/数据库等连接复用）"""
    
    def __init__(self, max_connections: int = 10, timeout: int = 30):
        self.max_connections = max_connections
        self.timeout = timeout
        self._pool: List[Any] = []
        self._in_use: int = 0
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(max_connections)
    
    def acquire(self) -> Any:
        """获取连接"""
        self._semaphore.acquire(timeout=self.timeout)
        with self._lock:
            if self._pool:
                conn = self._pool.pop()
                self._in_use += 1
                return conn
            self._in_use += 1
            return None  # 调用方需要创建新连接
    
    def release(self, conn: Any):
        """释放连接"""
        with self._lock:
            self._pool.append(conn)
            self._in_use -= 1
        self._semaphore.release()
    
    def get_stats(self) -> Dict[str, Any]:
        """获取连接池统计"""
        with self._lock:
            return {
                "max_connections": self.max_connections,
                "in_use": self._in_use,
                "idle": len(self._pool),
                "available": self.max_connections - self._in_use
            }


class RequestDeduplicator:
    """请求去重器（防止重复扫描/请求）"""
    
    def __init__(self, ttl: int = 300):
        self.ttl = ttl
        self._requests: Dict[str, float] = {}
        self._lock = threading.Lock()
    
    def is_duplicate(self, key: str) -> bool:
        """检查是否为重复请求"""
        with self._lock:
            now = time.time()
            
            # 清理过期请求
            expired_keys = [k for k, t in self._requests.items() if now - t > self.ttl]
            for k in expired_keys:
                del self._requests[k]
            
            if key in self._requests:
                return True
            
            self._requests[key] = now
            return False
    
    def clear(self):
        """清空去重记录"""
        with self._lock:
            self._requests.clear()


class PerformanceMonitor:
    """性能监控器"""
    
    def __init__(self):
        self._metrics: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._start_time = time.time()
    
    def record(self, metric_name: str, value: float):
        """记录指标"""
        with self._lock:
            if metric_name not in self._metrics:
                self._metrics[metric_name] = []
            self._metrics[metric_name].append(value)
            # 只保留最近1000个数据点
            if len(self._metrics[metric_name]) > 1000:
                self._metrics[metric_name] = self._metrics[metric_name][-1000:]
    
    def get_metric_stats(self, metric_name: str) -> Dict[str, Any]:
        """获取指标统计"""
        with self._lock:
            values = self._metrics.get(metric_name, [])
            if not values:
                return {"count": 0}
            
            return {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "avg": sum(values) / len(values),
                "p50": sorted(values)[len(values) // 2],
                "p95": sorted(values)[int(len(values) * 0.95)],
                "p99": sorted(values)[int(len(values) * 0.99)]
            }
    
    def get_all_stats(self) -> Dict[str, Any]:
        """获取所有指标统计"""
        with self._lock:
            return {
                "uptime_seconds": round(time.time() - self._start_time, 2),
                "metrics": {
                    name: self.get_metric_stats(name)
                    for name in self._metrics
                }
            }
    
    def reset(self):
        """重置监控"""
        with self._lock:
            self._metrics.clear()
            self._start_time = time.time()


# 全局性能监控器实例
performance_monitor = PerformanceMonitor()


def monitor_performance(metric_name: str = None):
    """性能监控装饰器
    
    用法:
        @monitor_performance("scan_execution")
        def scan_target(target):
            ...
    """
    def decorator(func: Callable):
        name = metric_name or f"{func.__module__}.{func.__name__}"
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = (time.time() - start_time) * 1000  # 毫秒
                performance_monitor.record(f"{name}_duration_ms", duration)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = (time.time() - start_time) * 1000
                performance_monitor.record(f"{name}_duration_ms", duration)
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
    
    return decorator


class BatchProcessor:
    """批量处理器"""
    
    def __init__(self, batch_size: int = 100, max_workers: int = 10):
        self.batch_size = batch_size
        self.max_workers = max_workers
    
    def process(self, items: List[Any], processor: Callable) -> List[Any]:
        """批量处理"""
        results = []
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                batch_results = list(executor.map(processor, batch))
            results.extend(batch_results)
        return results
    
    async def process_async(self, items: List[Any], processor: Callable) -> List[Any]:
        """异步批量处理"""
        results = []
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            tasks = [processor(item) for item in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            results.extend(batch_results)
        return results


# 导入ThreadPoolExecutor（放在文件末尾避免循环导入）
from concurrent.futures import ThreadPoolExecutor
