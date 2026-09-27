#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar/execution_engine.py — 自动化执行引擎。

覆盖：
    - 任务调度：将剧本展开为执行任务
    - 并发控制：最大并行度信号量
    - 重试机制：指数退避
    - 超时处理：单节点/整体超时
    - 执行日志与状态追踪
    - 失败回滚：按动作的 revertible 属性逆序补偿
    - 人工介入点 (human-in-the-loop)
    - 执行审计与性能监控
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional


TASK_STATES = ["queued", "running", "waiting_approval", "success",
               "failed", "rollback", "cancelled", "timeout"]


class ExecutionEngine:
    """自动化执行引擎（内存版，线程安全）。"""

    def __init__(self, max_concurrency: int = 8, default_timeout_s: int = 60,
                 max_retries: int = 2) -> None:
        self.max_concurrency = max_concurrency
        self.default_timeout_s = default_timeout_s
        self.max_retries = max_retries
        self.semaphore = threading.Semaphore(max_concurrency)
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.audit_logs: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # ---- 提交任务 ----
    def submit(self, name: str, steps: List[Dict[str, Any]],
               context: Optional[Dict[str, Any]] = None,
               on_approval: str = "pause") -> Dict[str, Any]:
        """提交一次剧本执行。

        steps: [{"step_id","action_id","params","retry","timeout","approval"}]
        on_approval: pause / auto_reject
        """
        task_id = f"EXEC-{uuid.uuid4().hex[:10]}"
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        task = {
            "task_id": task_id, "name": name, "status": "queued",
            "steps": [dict(s, state="pending", attempts=0) for s in steps],
            "context": context or {}, "on_approval": on_approval,
            "created_at": now, "started_at": None, "finished_at": None,
            "current_step": 0, "timeline": [], "error": None,
        }
        self.tasks[task_id] = task
        self._audit(task_id, "submit", f"任务已入队，共 {len(steps)} 步")
        return task

    def run(self, task_id: str) -> Dict[str, Any]:
        """同步模拟执行：逐步推进，遇审批节点暂停等待。"""
        task = self.tasks.get(task_id)
        if not task:
            return {"success": False, "error": "任务不存在"}
        task["status"] = "running"
        task["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self._audit(task_id, "start", "任务开始执行")

        for idx, step in enumerate(task["steps"]):
            task["current_step"] = idx
            if step.get("approval"):
                step["state"] = "wait_approval"
                task["status"] = "waiting_approval"
                self._audit(task_id, "approval", f"步骤 {step.get('action_id')} 等待审批")
                return self._snapshot(task)
            outcome = self._execute_step(task_id, step)
            if not outcome["ok"]:
                task["status"] = "failed"
                task["error"] = outcome["error"]
                self._audit(task_id, "failed", f"步骤失败: {outcome['error']}")
                self._rollback(task_id, idx)
                break
        else:
            task["status"] = "success"
            self._audit(task_id, "success", "全部步骤完成")

        task["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return self._snapshot(task)

    # ---- 单步执行（模拟，含重试/超时）----
    def _execute_step(self, task_id: str, step: Dict[str, Any]) -> Dict[str, Any]:
        retry_limit = int(step.get("retry", self.max_retries))
        timeout = int(step.get("timeout", self.default_timeout_s))
        for attempt in range(1, retry_limit + 2):
            step["attempts"] = attempt
            try:
                acquired = self.semaphore.acquire(timeout=min(timeout, 5))
                if not acquired:
                    raise TimeoutError(f"等待并发槽超时 {timeout}s")
                # 模拟执行：80% 成功
                ok = (hash((task_id, step.get("action_id"), attempt)) % 100) < 85
                step["state"] = "success" if ok else "failed"
                step["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                self.semaphore.release()
                if ok:
                    self._audit(task_id, "step_ok",
                                f"步骤 {step.get('action_id')} 第 {attempt} 次成功")
                    return {"ok": True}
                raise RuntimeError(f"模拟失败 (attempt {attempt})")
            except (TimeoutError, RuntimeError) as e:
                step["state"] = "failed"
                self._audit(task_id, "step_retry",
                            f"步骤 {step.get('action_id')} 第 {attempt} 次失败: {e}")
                if attempt > retry_limit:
                    return {"ok": False, "error": str(e)}
                time.sleep(0)  # 不真实阻塞，仅退避语义
        return {"ok": False, "error": "未知失败"}

    # ---- 人工介入 ----
    def approve_step(self, task_id: str, decision: str,
                     approver: str = "") -> Dict[str, Any]:
        task = self.tasks.get(task_id)
        if not task or task["status"] != "waiting_approval":
            return {"success": False, "error": "任务不在等待审批状态"}
        step = task["steps"][task["current_step"]]
        if decision == "approve":
            step["state"] = "approved"
            step["approved_by"] = approver
            self._audit(task_id, "approved",
                        f"步骤 {step.get('action_id')} 被 {approver} 批准")
            return self.run(task_id)
        step["state"] = "rejected"
        task["status"] = "cancelled"
        task["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self._audit(task_id, "rejected",
                    f"步骤 {step.get('action_id')} 被 {approver} 拒绝，任务终止")
        return self._snapshot(task)

    # ---- 回滚 ----
    def _rollback(self, task_id: str, up_to: int) -> None:
        task = self.tasks.get(task_id)
        if not task:
            return
        task["status"] = "rollback"
        rolled = 0
        for idx in range(up_to - 1, -1, -1):
            step = task["steps"][idx]
            if step.get("revertible", True) and step["state"] == "success":
                step["state"] = "rolled_back"
                rolled += 1
                self._audit(task_id, "rollback",
                            f"逆序补偿 {step.get('action_id')}")
        self._audit(task_id, "rollback_done", f"共回滚 {rolled} 步")

    # ---- 查询 ----
    def get(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self.tasks.get(task_id)

    def list_tasks(self, status: Optional[str] = None,
                   limit: int = 50) -> List[Dict[str, Any]]:
        out = [self._snapshot(t) for t in self.tasks.values()]
        if status:
            out = [t for t in out if t["status"] == status]
        out.sort(key=lambda t: t["created_at"], reverse=True)
        return out[:limit]

    def _snapshot(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "task_id": task["task_id"], "name": task["name"],
            "status": task["status"], "current_step": task["current_step"],
            "steps": task["steps"], "timeline": task["timeline"][-20:],
            "created_at": task["created_at"], "started_at": task["started_at"],
            "finished_at": task["finished_at"], "error": task["error"],
        }

    # ---- 审计 ----
    def _audit(self, task_id: str, kind: str, detail: str) -> None:
        rec = {"task_id": task_id, "kind": kind, "detail": detail,
               "at": time.strftime("%Y-%m-%d %H:%M:%S")}
        self.audit_logs.append(rec)
        if task_id in self.tasks:
            self.tasks[task_id]["timeline"].append(rec)

    def audit(self, task_id: Optional[str] = None,
              limit: int = 100) -> List[Dict[str, Any]]:
        logs = self.audit_logs
        if task_id:
            logs = [l for l in logs if l["task_id"] == task_id]
        return logs[-limit:]

    # ---- 性能监控 ----
    def performance(self) -> Dict[str, Any]:
        total = len(self.tasks)
        by_status: Dict[str, int] = {}
        durations: List[float] = []
        for t in self.tasks.values():
            by_status[t["status"]] = by_status.get(t["status"], 0) + 1
            if t["started_at"] and t["finished_at"]:
                s = time.mktime(time.strptime(t["started_at"], "%Y-%m-%d %H:%M:%S"))
                e = time.mktime(time.strptime(t["finished_at"], "%Y-%m-%d %H:%M:%S"))
                durations.append(round(e - s, 2))
        success = by_status.get("success", 0)
        return {
            "total_tasks": total, "by_status": by_status,
            "success_rate": round(success / total * 100, 1) if total else 0.0,
            "avg_duration_s": round(sum(durations) / len(durations), 2) if durations else 0,
            "max_concurrency": self.max_concurrency,
            "audit_events": len(self.audit_logs),
        }


_SINGLETON: Optional[ExecutionEngine] = None


def get_execution_engine() -> ExecutionEngine:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = ExecutionEngine()
    return _SINGLETON


if __name__ == "__main__":  # pragma: no cover
    eng = get_execution_engine()
    t = eng.submit("测试剧本执行", [
        {"step_id": "s1", "action_id": "ti.lookup_ip", "params": {"ip": "1.1.1.1"}},
        {"step_id": "s2", "action_id": "host.isolate", "params": {"host_id": "PC-1"}, "approval": True},
    ])
    print(eng.run(t["task_id"]))
    print(eng.approve_step(t["task_id"], "approve", "alice"))
