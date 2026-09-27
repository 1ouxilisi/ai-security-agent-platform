# -*- coding: utf-8 -*-
"""
performance/concurrency_optimizer.py — 并发与异步优化。

能力：
- 异步任务队列（优先级 / 重试 / 死信队列 / 状态追踪 / Worker / 调度）
- 并发控制（并发数 / 信号量 / 锁 / 竞态条件 / 分布式锁 / 并发安全）
- 批量处理（批量插入/更新/查询/导出，减少往返）
- 后台任务（长任务异步化 / 进度 / 取消 / 通知 / 依赖 / 编排）
- 事件驱动（事件总线 / 发布订阅 / 事件溯源 / 最终一致 / 事件日志）
- 分析项目中的同步阻塞点，识别可异步化长任务

设计：内存队列 + threading.Semaphore，不依赖外部 Broker。
"""

from __future__ import annotations

import glob
import os
import queue
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TaskQueue:
    """优先级异步任务队列（模拟）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._q: "queue.PriorityQueue" = queue.PriorityQueue(maxsize=10000)
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._dlq: Deque[Dict[str, Any]] = deque(maxlen=200)
        self.workers = 3
        self.max_retries = 3

    def submit(self, name: str, payload: Optional[Dict[str, Any]] = None,
               priority: int = 5) -> str:
        tid = uuid.uuid4().hex[:12]
        rec = {"task_id": tid, "name": name, "priority": priority,
               "status": "queued", "retries": 0, "progress": 0,
               "payload": payload or {}, "result": None, "error": None,
               "created_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        with self._lock:
            self._tasks[tid] = rec
        # PriorityQueue 元组 (priority, seq, tid)
        self._q.put((priority, time.time(), tid))
        return tid

    def _simulate_run(self, rec: Dict[str, Any]) -> None:
        rec["status"] = "running"
        steps = max(1, int(rec["payload"].get("steps", 5)))
        for i in range(1, steps + 1):
            rec["progress"] = round(i / steps * 100, 1)
            time.sleep(0)  # 让出 GIL，模拟异步进度
        if rec["payload"].get("fail"):
            raise RuntimeError("模拟任务失败")
        rec["result"] = {"processed": rec["payload"].get("count", steps)}

    def run_next(self) -> Dict[str, Any]:
        try:
            _, _, tid = self._q.get_nowait()
        except queue.Empty:
            return {"queued": 0}
        with self._lock:
            rec = self._tasks.get(tid)
        if not rec:
            return {"note": "task missing"}
        try:
            self._simulate_run(rec)
            rec["status"] = "done"
            rec["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:  # noqa: BLE001
            rec["retries"] += 1
            if rec["retries"] >= self.max_retries:
                rec["status"] = "dead_letter"
                rec["error"] = str(e)
                self._dlq.append(dict(rec))
            else:
                rec["status"] = "queued"
                self._q.put((rec["priority"], time.time(), tid))
        return {"task_id": tid, "status": rec["status"],
                "progress": rec["progress"]}

    def status(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> Dict[str, Any]:
        with self._lock:
            rows = sorted(self._tasks.values(),
                          key=lambda r: r["created_at"], reverse=True)
        c: Dict[str, int] = defaultdict(int)
        for r in rows:
            c[r["status"]] += 1
        return {"tasks": rows[:60], "counts": dict(c),
                "queued": self._q.qsize(), "workers": self.workers,
                "dead_letter": list(self._dlq)}

    def retry_dead_letter(self) -> Dict[str, Any]:
        moved = 0
        with self._lock:
            for rec in list(self._dlq):
                rec["status"] = "queued"
                rec["retries"] = 0
                rec["error"] = None
                self._tasks[rec["task_id"]] = rec
                self._q.put((rec["priority"], time.time(), rec["task_id"]))
                moved += 1
            self._dlq.clear()
        return {"requeued": moved}


class ConcurrencyControl:
    """信号量 / 锁 / 分布式锁模拟。"""

    def __init__(self, max_concurrency: int = 8) -> None:
        self.sem = threading.Semaphore(max_concurrency)
        self.max_concurrency = max_concurrency
        self._locks: Dict[str, bool] = {}
        self._dl_locks: Dict[str, float] = {}
        self.active = 0
        self.wait_peak = 0

    def acquire(self, key: str = "default") -> bool:
        ok = self.sem.acquire(blocking=False)
        if ok:
            self.active += 1
        return ok

    def release(self) -> None:
        self.sem.release()
        self.active = max(0, self.active - 1)

    def lock(self, name: str) -> bool:
        if self._locks.get(name):
            return False
        self._locks[name] = True
        return True

    def unlock(self, name: str) -> None:
        self._locks.pop(name, None)

    def distributed_lock(self, key: str, ttl: float = 10.0) -> bool:
        now = time.time()
        exp = self._dl_locks.get(key)
        if exp and exp > now:
            return False
        self._dl_locks[key] = now + ttl
        return True

    def release_distributed(self, key: str) -> None:
        self._dl_locks.pop(key, None)

    def status(self) -> Dict[str, Any]:
        return {"max_concurrency": self.max_concurrency,
                "active": self.active,
                "held_locks": list(self._locks.keys()),
                "distributed_locks": list(self._dl_locks.keys()),
                "race_risk": "对共享计数器/缓存写操作使用锁或原子 CAS，"
                             "避免 read-modify-write 竞态"}


class BatchProcessor:
    """批处理优化。"""

    def __init__(self) -> None:
        self.batch_size = 500
        self.stats = {"batches": 0, "rows": 0, "round_trips": 0,
                      "saved_round_trips": 0}

    def plan(self, total_rows: int, kind: str = "insert") -> Dict[str, Any]:
        bs = self.batch_size
        batches = (total_rows + bs - 1) // bs
        return {
            "kind": kind, "total_rows": total_rows, "batch_size": bs,
            "batches": batches,
            "round_trips_if_batch": batches,
            "round_trips_if_row_by_row": total_rows,
            "saved_round_trips": total_rows - batches,
            "tip": f"使用 executemany 或多行 VALUES，每批 {bs} 行，"
                   "减少网络/解析往返",
        }

    def simulate(self, total_rows: int) -> Dict[str, Any]:
        plan = self.plan(total_rows)
        self.stats["batches"] += plan["batches"]
        self.stats["rows"] += total_rows
        self.stats["round_trips"] += plan["round_trips_if_batch"]
        self.stats["saved_round_trips"] += plan["saved_round_trips"]
        return {"plan": plan, "stats": dict(self.stats)}


class EventBus:
    """事件总线：发布订阅 + 事件溯源日志。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._subs: Dict[str, List[str]] = defaultdict(list)
        self._log: Deque[Dict[str, Any]] = deque(maxlen=1000)

    def subscribe(self, topic: str, handler: str) -> None:
        with self._lock:
            if handler not in self._subs[topic]:
                self._subs[topic].append(handler)

    def publish(self, topic: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            handlers = list(self._subs.get(topic, []))
            evt = {"id": uuid.uuid4().hex[:10], "topic": topic,
                   "payload": payload, "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "delivered": len(handlers)}
            self._log.appendleft(evt)
        return {"event": evt, "handlers": handlers}

    def history(self, topic: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            rows = list(self._log)
        if topic:
            rows = [r for r in rows if r["topic"] == topic]
        return {"events": rows[:100], "subscriptions":
                {k: len(v) for k, v in self._subs.items()},
                "pattern": "发布-订阅 + 事件溯源，消费失败可重放，保证最终一致"}


class ConcurrencyOptimizer:
    def __init__(self) -> None:
        self.queue = TaskQueue()
        self.cc = ConcurrencyControl()
        self.batch = BatchProcessor()
        self.events = EventBus()
        self._bg: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    # 后台任务
    # ------------------------------------------------------------------ #
    def start_background(self, name: str, steps: int = 10) -> str:
        bid = uuid.uuid4().hex[:12]
        self._bg[bid] = {"id": bid, "name": name, "status": "running",
                         "progress": 0.0, "cancelled": False,
                         "created_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        # 立即推进一小步，模拟异步进行
        self._bg[bid]["progress"] = min(100.0, 100.0 / max(steps, 1))
        return bid

    def background_status(self, bid: str) -> Optional[Dict[str, Any]]:
        return self._bg.get(bid)

    def background_cancel(self, bid: str) -> Dict[str, Any]:
        rec = self._bg.get(bid)
        if not rec:
            return {"found": False}
        rec["cancelled"] = True
        rec["status"] = "cancelled"
        return {"found": True, "id": bid, "status": "cancelled"}

    def list_background(self) -> Dict[str, Any]:
        return {"tasks": list(self._bg.values())[:60], "total": len(self._bg)}

    # ------------------------------------------------------------------ #
    # 同步阻塞点分析（真实扫描源码）
    # ------------------------------------------------------------------ #
    def analyze_blocking(self) -> Dict[str, Any]:
        files = glob.glob(os.path.join(ROOT, "api_server", "*_routes.py"))
        blocking_re = re.compile(
            r"(time\.sleep|requests\.get|requests\.post|urllib\.request|"
            r"\.run\(|subprocess\.run|subprocess\.Popen|sync_scan|"
            r"for .+ in .*:.*(fetch|query|request))")
        findings: List[Dict[str, Any]] = []
        for path in files[:80]:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f):
                        if blocking_re.search(line):
                            findings.append({
                                "file": os.path.basename(path), "line": i + 1,
                                "snippet": line.strip()[:120],
                                "suggestion": "长耗时操作改为后台任务 + "
                                              "轮询/Webhook 回调，避免阻塞请求线程",
                            })
            except Exception:  # noqa: BLE001
                continue
            if len(findings) >= 50:
                break
        return {"findings": findings, "total": len(findings),
                "async_pattern": "@router.post 提交任务立即返回 task_id；"
                                 "前端轮询 /{task_id}/status 获取结果"}


optimizer = ConcurrencyOptimizer()
