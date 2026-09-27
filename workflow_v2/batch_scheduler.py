# -*- coding: utf-8 -*-
"""
batch_scheduler.py — 批量任务调度（第16轮升级·方向1）。

能力：
    - 批量提交多个目标（每行一个）
    - 并发控制（默认3，最大10）
    - 任务优先级（高/中/低，高优先级先执行）
    - 队列管理（等待/执行中/已完成/已失败）
    - 批量取消（取消所有等待中任务）
    - 批量导出结果（已完成任务报告打包为ZIP）
    - 批量重试（失败任务）
"""

from __future__ import annotations

import io
import json
import threading
import time
import zipfile
from typing import Any, Dict, List, Optional

from workflow_v2.execution_tracker import TRACKER, STATUS_FAILED, STATUS_DONE
from workflow_v2.workflow_engine import run_workflow, retry_failed


PRIORITY_WEIGHT = {"high": 0, "medium": 1, "low": 2}


class BatchScheduler:
    def __init__(self, max_concurrency: int = 3) -> None:
        self.max_concurrency = max(1, min(int(max_concurrency), 10))
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        # 队列元素: dict(batch_id, target, scenario_id, options, priority, task_id)
        self._queue: List[Dict[str, Any]] = []
        self._running: Dict[str, Dict[str, Any]] = {}
        self._batches: Dict[str, Dict[str, Any]] = {}
        self._stop = False
        self._worker = threading.Thread(target=self._loop, daemon=True,
                                        name="wfv2-batch-worker")
        self._worker.start()

    # -- 提交 --------------------------------------------------------------- #
    def submit(self, targets: List[str], scenario_id: str,
               options: Optional[Dict[str, Any]] = None,
               priority: str = "medium") -> Dict[str, Any]:
        batch_id = f"batch_{int(time.time())}_{len(self._batches)}"
        items = []
        for t in targets:
            t = (t or "").strip()
            if not t:
                continue
            item = {
                "batch_id": batch_id, "target": t,
                "scenario_id": scenario_id, "options": options or {},
                "priority": priority, "task_id": None, "status": "queued",
            }
            self._queue.append(item)
            items.append(item)
        with self._lock:
            self._batches[batch_id] = {
                "batch_id": batch_id,
                "scenario_id": scenario_id,
                "priority": priority,
                "submitted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "targets": [i["target"] for i in items],
                "items": items,
            }
        with self._cond:
            self._cond.notify_all()
        return {"batch_id": batch_id, "submitted": len(items)}

    # -- 工作循环 ----------------------------------------------------------- #
    def _loop(self) -> None:
        while not self._stop:
            with self._cond:
                # 等待直到有空闲槽位且队列非空
                while not self._stop and not self._pick():
                    self._cond.wait(timeout=1.0)
            # 取出待执行项（在锁外执行真实检测）
            item = self._claim_next()
            if item is None:
                continue
            try:
                task = run_workflow(item["target"], item["scenario_id"],
                                    options=item["options"])
                item["task_id"] = task.task_id
                item["status"] = "done" if task.status == STATUS_DONE else "failed"
            except Exception as e:  # noqa: BLE001
                item["status"] = "failed"
                item["error"] = str(e)
            finally:
                with self._lock:
                    self._running.pop(item["_qid"], None)
                    self._cond.notify_all()

    def _pick(self) -> bool:
        """返回是否有待执行且有空槽。"""
        if len(self._running) >= self.max_concurrency:
            return False
        return len(self._queue) > 0

    def _claim_next(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if len(self._running) >= self.max_concurrency or not self._queue:
                return None
            # 按优先级排序
            self._queue.sort(key=lambda x: PRIORITY_WEIGHT.get(x["priority"], 1))
            item = self._queue.pop(0)
            item["_qid"] = f"q_{id(item)}"
            self._running[item["_qid"]] = item
            return item

    # -- 查询 --------------------------------------------------------------- #
    def queue_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "max_concurrency": self.max_concurrency,
                "queued": len(self._queue),
                "running": len(self._running),
                "queued_items": [
                    {"target": i["target"], "scenario_id": i["scenario_id"],
                     "priority": i["priority"], "batch_id": i["batch_id"]}
                    for i in self._queue
                ],
                "running_items": [
                    {"target": i["target"], "priority": i["priority"],
                     "batch_id": i["batch_id"]}
                    for i in self._running.values()
                ],
            }

    def batch_detail(self, batch_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            b = self._batches.get(batch_id)
            if not b:
                return None
            items = []
            done = failed = queued = running = 0
            for i in b["items"]:
                st = i["status"]
                if st == "done":
                    done += 1
                elif st == "failed":
                    failed += 1
                elif st == "running":
                    running += 1
                else:
                    queued += 1
                items.append({
                    "target": i["target"], "status": st,
                    "task_id": i.get("task_id"), "error": i.get("error"),
                })
            return {
                "batch_id": batch_id,
                "scenario_id": b["scenario_id"],
                "submitted_at": b["submitted_at"],
                "summary": {"done": done, "failed": failed,
                            "queued": queued, "running": running,
                            "total": len(b["items"])},
                "items": items,
            }

    def list_batches(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [self.batch_detail(bid) or {}
                    for bid in list(self._batches.keys())]

    # -- 批量操作 ----------------------------------------------------------- #
    def cancel_pending(self) -> int:
        with self._lock:
            n = len(self._queue)
            for i in self._queue:
                i["status"] = "cancelled"
            self._queue.clear()
            return n

    def retry_failed_batch(self, batch_id: str) -> int:
        n = 0
        with self._lock:
            b = self._batches.get(batch_id)
            if not b:
                return 0
            for i in b["items"]:
                if i["status"] == "failed" and i.get("task_id"):
                    try:
                        retry_failed(i["task_id"])
                        i["status"] = "done"
                        n += 1
                    except Exception:  # noqa: BLE001
                        continue
        return n

    def export_zip(self, batch_id: Optional[str] = None) -> bytes:
        """导出已完成任务报告为 ZIP（内存字节）。"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            with self._lock:
                items = []
                if batch_id:
                    b = self._batches.get(batch_id)
                    if b:
                        items = b["items"]
                else:
                    for b in self._batches.values():
                        items.extend(b["items"])
            written = 0
            for i in items:
                if i["status"] != "done" or not i.get("task_id"):
                    continue
                task = TRACKER.get(i["task_id"])
                if not task:
                    continue
                fname = f"report_{i['task_id']}_{i['target']}.json"
                fname = "".join(c if c.isalnum() or c in "._-" else "_"
                                for c in fname)
                zf.writestr(fname, json.dumps(task.result, ensure_ascii=False,
                                              indent=2, default=str))
                written += 1
            zf.writestr("_manifest.json",
                        json.dumps({"exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "reports": written}, ensure_ascii=False))
        return buf.getvalue()

    def shutdown(self) -> None:
        self._stop = True
        with self._cond:
            self._cond.notify_all()


SCHEDULER = BatchScheduler(max_concurrency=3)


__all__ = ["BatchScheduler", "SCHEDULER"]
