# -*- coding: utf-8 -*-
"""
remediation_tracking_phase.py — 阶段5：整改跟踪。

- 整改任务 CRUD / 责任人 / 截止日期
- 进度（未开始/进行中/已完成/已延期）
- SLA 监控 / 优先级 / 依赖关系 / 证据 / 审批 / 报表
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

TASK_STATUS = ["not_started", "in_progress", "completed", "overdue"]


@dataclass
class RemediationTask:
    task_id: str = ""
    title: str = ""
    gap_id: str = ""
    severity: str = "medium"
    assignee: str = ""
    priority: str = "medium"
    status: str = "not_started"
    due_date: str = ""
    created_at: str = ""
    evidence: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    approved: bool = False
    progress_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["days_left"] = self._days_left()
        return d

    def _days_left(self) -> Optional[int]:
        if not self.due_date:
            return None
        try:
            due = datetime.fromisoformat(self.due_date)
            return (due - datetime.now()).days
        except Exception:  # noqa: BLE001
            return None


class RemediationTrackingPhase:
    """阶段5：整改跟踪。"""

    def __init__(self) -> None:
        self._tasks: Dict[str, RemediationTask] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def create_task(self, title: str, gap_id: str = "",
                    assignee: str = "", severity: str = "medium",
                    priority: str = "medium",
                    due_in_days: int = 30,
                    depends_on: Optional[List[str]] = None
                    ) -> Dict[str, Any]:
        tid = "rmt_" + uuid.uuid4().hex[:8]
        due = (datetime.now() + timedelta(days=due_in_days)).isoformat(
            timespec="seconds")
        t = RemediationTask(
            task_id=tid, title=title, gap_id=gap_id, assignee=assignee,
            severity=severity, priority=priority, due_date=due,
            created_at=datetime.now().isoformat(timespec="seconds"),
            depends_on=depends_on or [])
        with self._lock:
            self._tasks[tid] = t
        return t.to_dict()

    def list_tasks(self, status: Optional[str] = None,
                   assignee: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._tasks.values())
        out = [t.to_dict() for t in items]
        if status:
            out = [t for t in out if t["status"] == status]
        if assignee:
            out = [t for t in out if t["assignee"] == assignee]
        # SLA 自动更新
        for t in items:
            self._auto_overdue(t)
        out.sort(key=lambda x: (x["status"] == "completed",
                                -{"critical": 0, "high": 1,
                                  "medium": 2, "low": 3}.get(
                                    x["severity"], 9)))
        return out

    def _auto_overdue(self, t: RemediationTask) -> None:
        if t.status in ("completed",):
            return
        dl = t._days_left()
        if dl is not None and dl < 0:
            t.status = "overdue"

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            t = self._tasks.get(task_id)
            return t.to_dict() if t else None

    def update_task(self, task_id: str, **kw: Any) -> Optional[Dict[str, Any]]:
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                return None
            for k, v in kw.items():
                if hasattr(t, k) and v is not None:
                    setattr(t, k, v)
            self._auto_overdue(t)
            return t.to_dict()

    def delete_task(self, task_id: str) -> bool:
        with self._lock:
            return self._tasks.pop(task_id, None) is not None

    # ------------------------------------------------------------------ #
    def add_evidence(self, task_id: str, evidence: str) -> bool:
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                return False
            t.evidence.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] "
                              f"{evidence}")
            return True

    def approve(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                return None
            t.approved = True
            if t.status == "in_progress":
                t.status = "completed"
            return t.to_dict()

    # ------------------------------------------------------------------ #
    def sla_stats(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._tasks.values())
        overdue = sum(1 for t in items
                      if t.status == "overdue" or
                      (t._days_left() is not None and t._days_left() < 0
                       and t.status != "completed"))
        warn = sum(1 for t in items
                   if t.status not in ("completed", "overdue") and
                   t._days_left() is not None and 0 <= t._days_left() <= 3)
        return {"total": len(items),
                "not_started": sum(1 for t in items
                                   if t.status == "not_started"),
                "in_progress": sum(1 for t in items
                                   if t.status == "in_progress"),
                "completed": sum(1 for t in items
                                 if t.status == "completed"),
                "overdue": overdue, "sla_warning": warn}

    def progress_report(self) -> Dict[str, Any]:
        s = self.sla_stats()
        total = max(1, s["total"])
        return {"sla": s,
                "completion_rate": round(s["completed"] / total * 100, 1),
                "tasks": [t.to_dict() for t in self._tasks.values()]}


_default: Optional[RemediationTrackingPhase] = None


def get_remediation_tracking_phase() -> RemediationTrackingPhase:
    global _default
    if _default is None:
        _default = RemediationTrackingPhase()
    return _default
