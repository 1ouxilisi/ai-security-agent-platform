#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_ultra/async_queue.py — 异步请求队列 / 并发控制。

支持 100 并发不崩：信号量限流 + 后台 worker 消费 + 任务回执。
"""

from __future__ import annotations

import queue
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional


class AsyncQueue:
    """带并发上限的任务队列。"""

    def __init__(self, max_workers: int = 8, max_concurrent: int = 100,
                 queue_size: int = 1000) -> None:
        self._task_q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=queue_size)
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._max_concurrent = max_concurrent
        self._max_workers = max_workers
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._workers: List[threading.Thread] = []
        self._started = False
        self._enqueued = 0
        self._completed = 0
        self._failed = 0

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        for i in range(self._max_workers):
            t = threading.Thread(target=self._worker_loop, name=f"pq-{i}", daemon=True)
            t.start()
            self._workers.append(t)

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._task_q.get(timeout=0.2)
            except queue.Empty:
                continue
            tid = item["task_id"]
            fn: Callable[[], Any] = item["func"]
            with self._sem:
                try:
                    result = fn()
                    self._finish(tid, result)
                except Exception as e:  # pragma: no cover
                    self._finish(tid, error=str(e))
                finally:
                    self._task_q.task_done()

    def enqueue(self, func: Callable[[], Any], kind: str = "task",
                meta: Optional[Dict[str, Any]] = None) -> str:
        self.start()
        tid = uuid.uuid4().hex[:12]
        rec = {
            "task_id": tid, "kind": kind, "status": "queued",
            "meta": meta or {},
            "enqueued_at": time.strftime("%H:%M:%S"),
            "started_at": None, "finished_at": None,
            "result": None, "error": None,
        }
        with self._lock:
            self._tasks[tid] = rec
            self._enqueued += 1
        self._task_q.put({"task_id": tid, "func": func})
        return tid

    def _finish(self, tid: str, result: Any = None,
                error: Optional[str] = None) -> None:
        with self._lock:
            rec = self._tasks.get(tid)
            if not rec:
                return
            rec["finished_at"] = time.strftime("%H:%M:%S")
            rec["status"] = "error" if error else "done"
            rec["result"] = result
            rec["error"] = error
            if error:
                self._failed += 1
            else:
                self._completed += 1

    def get(self, tid: str) -> Optional[Dict[str, Any]]:
        return self._tasks.get(tid)

    def list_tasks(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._tasks.values())
        items.sort(key=lambda r: r["enqueued_at"], reverse=True)
        return items[:limit]

    def health(self) -> Dict[str, Any]:
        with self._lock:
            queued = self._task_q.qsize()
            running = self._enqueued - self._completed - self._failed
            return {
                "max_concurrent": self._max_concurrent,
                "max_workers": self._max_workers,
                "queued": queued,
                "running": max(0, running),
                "enqueued": self._enqueued,
                "completed": self._completed,
                "failed": self._failed,
                "started": self._started,
            }

    def stop(self) -> None:
        self._stop.set()


_q: AsyncQueue | None = None


def get_async_queue() -> AsyncQueue:
    global _q
    if _q is None:
        _q = AsyncQueue()
    return _q
