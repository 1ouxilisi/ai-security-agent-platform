# -*- coding: utf-8 -*-
"""
performance/concurrent_handler.py — 并发处理优化

基于 ThreadPoolExecutor 的统一并发入口：
    - 全局任务提交；
    - 扫描子任务并发执行；
    - 长任务异步化（立即返回 task_id）；
    - 线程池统计与优雅关闭。
所有任务都有 try-except，单个任务异常不影响其他任务。
"""
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional


class ConcurrentHandler:
    """并发处理器：线程池封装 + 任务记账。"""

    def __init__(self, max_workers: int = 10) -> None:
        """初始化线程池，全局并发上限默认 10。"""
        self.max_workers = max_workers
        self.pool = ThreadPoolExecutor(max_workers=max_workers,
                                       thread_name_prefix="sec-agent")
        self._lock = threading.Lock()
        self._active = 0
        self._queued = 0
        self._completed = 0
        self._failed = 0
        self._bg_tasks: Dict[str, Future] = {}

    # ------------------------------------------------------------------
    # 基础提交
    # ------------------------------------------------------------------
    def submit_task(self, func: Callable, *args: Any, **kwargs: Any) -> Future:
        """提交任务到线程池，返回 Future。"""
        with self._lock:
            self._queued += 1
        return self.pool.submit(self._wrap(func), *args, **kwargs)

    def _wrap(self, func: Callable) -> Callable:
        """包装任务：记账 + 异常隔离。"""

        def runner(*args: Any, **kwargs: Any) -> Any:
            with self._lock:
                self._queued = max(0, self._queued - 1)
                self._active += 1
            try:
                return func(*args, **kwargs)
            except Exception as e:
                with self._lock:
                    self._failed += 1
                return {"__error__": str(e)}
            finally:
                with self._lock:
                    self._active = max(0, self._active - 1)
                    self._completed += 1

        return runner

    # ------------------------------------------------------------------
    # 扫描子任务并发
    # ------------------------------------------------------------------
    def run_scan_subtasks(self, subtasks: List[Dict[str, Any]],
                          concurrency: int = 5) -> List[Dict[str, Any]]:
        """并发执行扫描子任务列表。

        subtasks 形如 [{"func": callable, "args": (...), "kwargs": {...}}, ...]
        """
        workers = min(concurrency, len(subtasks) or 1)
        local_pool = ThreadPoolExecutor(max_workers=workers,
                                       thread_name_prefix="scan")
        futures = {}
        try:
            for i, st in enumerate(subtasks):
                fn = st.get("func")
                args = st.get("args") or ()
                kwargs = st.get("kwargs") or {}
                if not callable(fn):
                    continue
                fut = local_pool.submit(self._safe_run, fn, i, *args, **kwargs)
                futures[fut] = i
            results: List[Dict[str, Any]] = []
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    results.append({"index": futures[fut], "error": str(e)})
            results.sort(key=lambda x: x.get("index", 0))
            return results
        finally:
            local_pool.shutdown(wait=False)

    @staticmethod
    def _safe_run(func: Callable, index: int, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """单个子任务安全执行。"""
        try:
            return {"index": index, "ok": True, "result": func(*args, **kwargs)}
        except Exception as e:
            return {"index": index, "ok": False, "error": str(e)}

    # ------------------------------------------------------------------
    # 异步 API 处理装饰器
    # ------------------------------------------------------------------
    def run_async_api_handler(self, func: Callable) -> Callable:
        """把长函数放到后台线程执行，API 立即返回 task_id。"""

        def wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
            task_id = "task_" + uuid.uuid4().hex[:12]
            fut = self.pool.submit(self._safe_bg, func, task_id, *args, **kwargs)
            self._bg_tasks[task_id] = fut
            return {"task_id": task_id, "status": "submitted",
                    "poll_hint": f"可用任务查询接口轮询 {task_id}"}

        return wrapper

    def _safe_bg(self, func: Callable, task_id: str,
                 *args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            return {"task_id": task_id, "error": str(e)}

    # ------------------------------------------------------------------
    # 统计与关闭
    # ------------------------------------------------------------------
    def get_pool_stats(self) -> Dict[str, Any]:
        """线程池统计：活跃/排队/完成/失败。"""
        with self._lock:
            return {
                "max_workers": self.max_workers,
                "active": self._active,
                "queued": self._queued,
                "completed": self._completed,
                "failed": self._failed,
                "background_tasks": len(self._bg_tasks),
                "timestamp": time.time(),
            }

    def shutdown(self) -> None:
        """关闭线程池。"""
        self.pool.shutdown(wait=False)
