# -*- coding: utf-8 -*-
"""
progress_tracker.py — 进度跟踪器。

跟踪一个渗透任务的整体进度、每一步进度，并根据已完成速率估算剩余时间（ETA）。
纯内存字典存储。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class StepProgress:
    """单步进度。"""

    step_id: str
    name: str
    stage: str
    status: str = "pending"   # pending/running/done/failed
    progress: float = 0.0
    started_at: Optional[float] = None
    finished_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TaskProgress:
    """整任务进度。"""

    task_id: str
    target: str
    steps: List[StepProgress] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @property
    def overall(self) -> float:
        if not self.steps:
            return 0.0
        return round(sum(s.progress for s in self.steps) / len(self.steps), 4)

    @property
    def eta_seconds(self) -> Optional[float]:
        """根据已完成步数的平均耗时估算剩余时间。"""
        done = [s for s in self.steps if s.status == "done" and s.finished_at and s.started_at]
        if not done:
            return None
        avg = sum(s.finished_at - s.started_at for s in done) / len(done)
        remaining = sum(1 for s in self.steps if s.status not in ("done", "failed"))
        return round(avg * remaining, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "target": self.target,
            "overall": self.overall,
            "overall_pct": round(self.overall * 100, 1),
            "eta_seconds": self.eta_seconds,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "steps": [s.to_dict() for s in self.steps],
            "counts": {
                "total": len(self.steps),
                "done": sum(1 for s in self.steps if s.status == "done"),
                "running": sum(1 for s in self.steps if s.status == "running"),
                "failed": sum(1 for s in self.steps if s.status == "failed"),
                "pending": sum(1 for s in self.steps if s.status == "pending"),
            },
        }


class ProgressTracker:
    """进度跟踪。"""

    def __init__(self) -> None:
        self._tasks: Dict[str, TaskProgress] = {}

    # ------------------------------------------------------------------ #
    def create_task(self, target: str,
                    steps: Optional[List[Dict[str, str]]] = None) -> TaskProgress:
        tid = "prog_" + uuid.uuid4().hex[:10]
        tp = TaskProgress(task_id=tid, target=target)
        for i, st in enumerate(steps or []):
            tp.steps.append(StepProgress(
                step_id=f"{tid}_{i+1:02d}",
                name=st.get("name", f"步骤{i+1}"),
                stage=st.get("stage", ""),
            ))
        self._tasks[tid] = tp
        return tp

    def start_step(self, task_id: str, step_id: str) -> None:
        tp = self._tasks.get(task_id)
        if not tp:
            return
        for s in tp.steps:
            if s.step_id == step_id:
                s.status = "running"
                s.started_at = time.time()
                s.progress = 0.05
        tp.updated_at = time.time()

    def update_step(self, task_id: str, step_id: str,
                    progress: float) -> None:
        tp = self._tasks.get(task_id)
        if not tp:
            return
        for s in tp.steps:
            if s.step_id == step_id:
                s.progress = max(0.0, min(1.0, progress))
                if s.progress >= 1.0 and s.status != "done":
                    self.finish_step(task_id, step_id)
        tp.updated_at = time.time()

    def finish_step(self, task_id: str, step_id: str,
                    status: str = "done") -> None:
        tp = self._tasks.get(task_id)
        if not tp:
            return
        for s in tp.steps:
            if s.step_id == step_id:
                s.status = status
                s.progress = 1.0 if status == "done" else s.progress
                s.finished_at = time.time()
        tp.updated_at = time.time()

    # ------------------------------------------------------------------ #
    def get(self, task_id: str) -> Optional[TaskProgress]:
        return self._tasks.get(task_id)

    def snapshot(self, task_id: str) -> Dict[str, Any]:
        t = self._tasks.get(task_id)
        return t.to_dict() if t else {}

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self._tasks.values()]

    def stats(self) -> Dict[str, Any]:
        return {
            "tasks": len(self._tasks),
            "avg_overall": round(
                sum(t.overall for t in self._tasks.values()) / max(1, len(self._tasks)), 3),
        }


tracker = ProgressTracker()
