# -*- coding: utf-8 -*-
"""
execution_tracker.py — 端到端工作流执行追踪（第16轮升级·方向1）。

职责：
    - 任务状态队列（等待 pending / 执行中 running / 完成 done / 失败 failed / 已取消 cancelled）
    - 每一步骤的输入输出记录（步骤名 / 开始时间 / 结束时间 / 耗时 / 输入参数 / 输出摘要 / 状态）
    - 进度百分比实时计算（已完成步骤数 / 总步骤数）
    - 失败步骤的错误信息与堆栈追踪
    - 可重试失败步骤（从失败步骤继续，无需从头开始）
    - 可取消执行中任务（设置取消标志，当前步骤完成后停止）
    - 执行日志（每一步详细日志，支持按步骤筛选）

设计：纯内存字典，无数据库。线程安全用一把可重入锁。
"""

from __future__ import annotations

import threading
import time
import traceback
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 状态常量
# --------------------------------------------------------------------------- #
STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_SKIPPED = "skipped"

STEP_STATUSES = {STATUS_PENDING, STATUS_RUNNING, STATUS_DONE,
                 STATUS_FAILED, STATUS_CANCELLED, STATUS_SKIPPED}


def _now_ts() -> float:
    return time.time()


def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


class StepRecord:
    """单个执行步骤的记录。"""

    def __init__(self, step_id: str, name: str, description: str = "",
                 timeout: int = 60, depends_on: Optional[List[str]] = None):
        self.step_id = step_id
        self.name = name
        self.description = description
        self.timeout = timeout
        self.depends_on: List[str] = list(depends_on or [])
        self.status = STATUS_PENDING
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.started_at_str: Optional[str] = None
        self.finished_at_str: Optional[str] = None
        self.duration_ms: Optional[int] = None
        self.input_summary: Any = None
        self.output_summary: Any = None
        self.error: Optional[str] = None
        self.traceback: Optional[str] = None
        self.logs: List[str] = []

    # -- 生命周期 ----------------------------------------------------------- #
    def start(self, input_summary: Any = None) -> None:
        self.status = STATUS_RUNNING
        self.started_at = _now_ts()
        self.started_at_str = _now_str()
        self.input_summary = input_summary
        self.error = None
        self.traceback = None

    def finish(self, output_summary: Any = None) -> None:
        self.finished_at = _now_ts()
        self.finished_at_str = _now_str()
        if self.started_at:
            self.duration_ms = int((self.finished_at - self.started_at) * 1000)
        self.output_summary = output_summary
        self.status = STATUS_DONE

    def fail(self, error: str, tb: Optional[str] = None) -> None:
        self.finished_at = _now_ts()
        self.finished_at_str = _now_str()
        if self.started_at:
            self.duration_ms = int((self.finished_at - self.started_at) * 1000)
        self.error = error
        self.traceback = tb or traceback.format_exc()
        self.status = STATUS_FAILED

    def skip(self, reason: str = "") -> None:
        self.status = STATUS_SKIPPED
        self.log(f"[SKIP] {reason}")

    def cancel(self) -> None:
        if self.status == STATUS_RUNNING:
            self.status = STATUS_CANCELLED
        elif self.status == STATUS_PENDING:
            self.status = STATUS_CANCELLED
        self.finished_at_str = _now_str()

    def log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S", time.localtime())
        self.logs.append(f"[{ts}] {msg}")

    # -- 序列化 ------------------------------------------------------------- #
    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "name": self.name,
            "description": self.description,
            "timeout": self.timeout,
            "depends_on": self.depends_on,
            "status": self.status,
            "started_at": self.started_at_str,
            "finished_at": self.finished_at_str,
            "duration_ms": self.duration_ms,
            "input_summary": self.input_summary,
            "output_summary": self.output_summary,
            "error": self.error,
            "traceback": self.traceback,
            "logs": list(self.logs),
        }


class TaskRecord:
    """一个工作流执行任务的记录。"""

    def __init__(self, task_id: str, target: str, scenario_id: str,
                 scenario_name: str, steps: List[StepRecord],
                 options: Optional[Dict[str, Any]] = None):
        self.task_id = task_id
        self.target = target
        self.scenario_id = scenario_id
        self.scenario_name = scenario_name
        self.options = options or {}
        self.status = STATUS_PENDING
        self.created_at = _now_str()
        self.created_ts = _now_ts()
        self.finished_at: Optional[str] = None
        self.finished_ts: Optional[float] = None
        self.elapsed_ms: Optional[int] = None
        self.steps: Dict[str, StepRecord] = {s.step_id: s for s in steps}
        self.step_order: List[str] = [s.step_id for s in steps]
        self.cancel_flag = False
        self.result: Dict[str, Any] = {}
        self.error: Optional[str] = None
        self.global_logs: List[str] = []
        self._lock = threading.RLock()

    # -- 进度 --------------------------------------------------------------- #
    def progress(self) -> float:
        total = max(len(self.step_order), 1)
        done = sum(1 for sid in self.step_order
                   if self.steps[sid].status in (STATUS_DONE, STATUS_FAILED,
                                                 STATUS_SKIPPED, STATUS_CANCELLED))
        return round(done / total * 100, 1)

    def log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S", time.localtime())
        self.global_logs.append(f"[{ts}] {msg}")

    def mark_running(self) -> None:
        self.status = STATUS_RUNNING

    def mark_done(self, result: Dict[str, Any]) -> None:
        self.status = STATUS_DONE
        self.result = result
        self.finished_at = _now_str()
        self.finished_ts = _now_ts()
        self.elapsed_ms = int((self.finished_ts - self.created_ts) * 1000)

    def mark_failed(self, error: str) -> None:
        self.status = STATUS_FAILED
        self.error = error
        self.finished_at = _now_str()
        self.finished_ts = _now_ts()
        self.elapsed_ms = int((self.finished_ts - self.created_ts) * 1000)

    def mark_cancelled(self) -> None:
        self.status = STATUS_CANCELLED
        self.cancel_flag = True
        self.finished_at = _now_str()
        self.finished_ts = _now_ts()
        self.elapsed_ms = int((self.finished_ts - self.created_ts) * 1000)
        for s in self.steps.values():
            if s.status in (STATUS_PENDING, STATUS_RUNNING):
                s.cancel()

    def reset_failed_steps(self) -> List[str]:
        """把失败步骤重置为 pending，供从失败处重试。"""
        reset: List[str] = []
        for sid in self.step_order:
            s = self.steps[sid]
            if s.status in (STATUS_FAILED, STATUS_CANCELLED):
                s.status = STATUS_PENDING
                s.started_at = s.finished_at = None
                s.started_at_str = s.finished_at_str = None
                s.duration_ms = None
                s.error = s.traceback = None
                s.output_summary = None
                s.logs = []
                reset.append(sid)
        self.error = None
        self.status = STATUS_PENDING
        self.cancel_flag = False
        return reset

    def to_dict(self, include_steps: bool = True,
                step_filter: Optional[str] = None) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "task_id": self.task_id,
            "target": self.target,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "options": self.options,
            "status": self.status,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "elapsed_ms": self.elapsed_ms,
            "progress": self.progress(),
            "total_steps": len(self.step_order),
            "done_steps": sum(1 for sid in self.step_order
                              if self.steps[sid].status == STATUS_DONE),
            "failed_steps": sum(1 for sid in self.step_order
                                if self.steps[sid].status == STATUS_FAILED),
            "error": self.error,
            "result": self.result,
            "global_logs": list(self.global_logs),
        }
        if include_steps:
            steps_out = []
            for sid in self.step_order:
                sd = self.steps[sid].to_dict()
                if step_filter and step_filter not in sd["name"] \
                        and step_filter not in (sd["error"] or ""):
                    continue
                steps_out.append(sd)
            d["steps"] = steps_out
        return d


class ExecutionTracker:
    """全局任务注册表（单例）。"""

    def __init__(self) -> None:
        self._tasks: Dict[str, TaskRecord] = {}
        self._lock = threading.RLock()

    # -- 增删查 ------------------------------------------------------------- #
    def create_task(self, target: str, scenario_id: str, scenario_name: str,
                    step_defs: List[Dict[str, Any]],
                    options: Optional[Dict[str, Any]] = None) -> TaskRecord:
        task_id = uuid.uuid4().hex[:16]
        steps = [
            StepRecord(
                step_id=sd["id"],
                name=sd["name"],
                description=sd.get("description", ""),
                timeout=sd.get("timeout", 60),
                depends_on=sd.get("depends_on", []),
            )
            for sd in step_defs
        ]
        task = TaskRecord(task_id, target, scenario_id, scenario_name,
                          steps, options)
        with self._lock:
            self._tasks[task_id] = task
        return task

    def get(self, task_id: str) -> Optional[TaskRecord]:
        return self._tasks.get(task_id)

    def list_tasks(self, status: Optional[str] = None,
                   limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            tasks = list(self._tasks.values())
        tasks.sort(key=lambda t: t.created_ts, reverse=True)
        out = []
        for t in tasks:
            if status and t.status != status:
                continue
            out.append(t.to_dict(include_steps=False))
            if len(out) >= limit:
                break
        return out

    def count_by_status(self) -> Dict[str, int]:
        with self._lock:
            tasks = list(self._tasks.values())
        c: Dict[str, int] = {STATUS_PENDING: 0, STATUS_RUNNING: 0,
                             STATUS_DONE: 0, STATUS_FAILED: 0,
                             STATUS_CANCELLED: 0}
        for t in tasks:
            c[t.status] = c.get(t.status, 0) + 1
        return c

    # -- 取消 --------------------------------------------------------------- #
    def cancel(self, task_id: str) -> bool:
        t = self.get(task_id)
        if not t:
            return False
        if t.status in (STATUS_DONE, STATUS_FAILED, STATUS_CANCELLED):
            return False
        t.mark_cancelled()
        return True

    # -- 统计 --------------------------------------------------------------- #
    def purge(self, keep: int = 200) -> int:
        """只保留最近 keep 个任务，返回清理数量。"""
        with self._lock:
            tasks = sorted(self._tasks.values(), key=lambda t: t.created_ts,
                           reverse=True)
            keep_ids = {t.task_id for t in tasks[:keep]}
            removed = 0
            for tid in list(self._tasks.keys()):
                if tid not in keep_ids:
                    del self._tasks[tid]
                    removed += 1
            return removed


# 全局单例
TRACKER = ExecutionTracker()


__all__ = [
    "ExecutionTracker", "StepRecord", "TaskRecord", "TRACKER",
    "STATUS_PENDING", "STATUS_RUNNING", "STATUS_DONE",
    "STATUS_FAILED", "STATUS_CANCELLED", "STATUS_SKIPPED",
]
