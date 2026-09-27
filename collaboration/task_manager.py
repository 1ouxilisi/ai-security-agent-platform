#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collaboration/task_manager.py — 协作任务管理

提供任务的创建、分配、评论、状态流转、活动日志与 JSON 文件持久化。
数据存储于 data/collaboration/tasks.json。
"""
import os
import re
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging

    log = logging.getLogger("collaboration.task_manager")

# 数据目录（项目根下 data/collaboration）
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_BASE_DIR, "data", "collaboration")
TASKS_FILE = os.path.join(DATA_DIR, "tasks.json")

VALID_STATUS = {"pending", "in_progress", "completed", "closed"}
VALID_PRIORITY = {"low", "medium", "high", "critical"}


def _now() -> str:
    return datetime.now().isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------
class TaskComment:
    """任务评论"""

    def __init__(self, user: str, content: str,
                 mentions: Optional[List[str]] = None, comment_id: Optional[str] = None):
        self.comment_id: str = comment_id or _new_id("cmt")
        self.task_id: str = ""
        self.user: str = user
        self.content: str = content
        self.created_at: str = _now()
        self.mentions: List[str] = mentions or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "comment_id": self.comment_id,
            "task_id": self.task_id,
            "user": self.user,
            "content": self.content,
            "created_at": self.created_at,
            "mentions": self.mentions,
        }


class CollabTask:
    """协作任务"""

    def __init__(self, title: str, description: str, assignee: Optional[str] = None,
                 assigner: Optional[str] = None, priority: str = "medium",
                 due_date: Optional[str] = None, tags: Optional[List[str]] = None,
                 related_assessment_id: Optional[str] = None,
                 task_id: Optional[str] = None):
        self.task_id: str = task_id or _new_id("task")
        self.title: str = title
        self.description: str = description
        self.assignee: Optional[str] = assignee
        self.assigner: Optional[str] = assigner
        self.status: str = "pending"
        self.priority: str = priority if priority in VALID_PRIORITY else "medium"
        self.due_date: Optional[str] = due_date
        self.tags: List[str] = tags or []
        self.related_assessment_id: Optional[str] = related_assessment_id
        self.created_at: str = _now()
        self.updated_at: str = _now()
        self.completed_at: Optional[str] = None
        self.comments: List[TaskComment] = []
        self.attachments: List[Dict[str, Any]] = []
        self.activity_log: List[Dict[str, Any]] = []

    def log_activity(self, action: str, operator: str, detail: str = ""):
        """记录一条活动日志。"""
        self.activity_log.append({
            "action": action,
            "operator": operator,
            "detail": detail,
            "timestamp": _now(),
        })
        self.updated_at = _now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "description": self.description,
            "assignee": self.assignee,
            "assigner": self.assigner,
            "status": self.status,
            "priority": self.priority,
            "due_date": self.due_date,
            "tags": self.tags,
            "related_assessment_id": self.related_assessment_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "comments": [c.to_dict() for c in self.comments],
            "attachments": self.attachments,
            "activity_log": self.activity_log,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CollabTask":
        task = cls(
            title=data.get("title", ""),
            description=data.get("description", ""),
            assignee=data.get("assignee"),
            assigner=data.get("assigner"),
            priority=data.get("priority", "medium"),
            due_date=data.get("due_date"),
            tags=data.get("tags", []),
            related_assessment_id=data.get("related_assessment_id"),
            task_id=data.get("task_id"),
        )
        task.status = data.get("status", "pending")
        task.created_at = data.get("created_at", _now())
        task.updated_at = data.get("updated_at", _now())
        task.completed_at = data.get("completed_at")
        task.attachments = data.get("attachments", [])
        task.activity_log = data.get("activity_log", [])
        task.comments = []
        for c in data.get("comments", []):
            comment = TaskComment(
                user=c.get("user", ""),
                content=c.get("content", ""),
                mentions=c.get("mentions", []),
                comment_id=c.get("comment_id"),
            )
            comment.task_id = task.task_id
            comment.created_at = c.get("created_at", _now())
            task.comments.append(comment)
        return task


# ---------------------------------------------------------------------------
# 管理器
# ---------------------------------------------------------------------------
class TaskManager:
    """协作任务管理器（JSON 文件持久化）。"""

    def __init__(self, data_file: Optional[str] = None):
        self.data_file = data_file or TASKS_FILE
        self.tasks: Dict[str, CollabTask] = {}
        os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
        self._load()

    # ---------------- 持久化 ----------------
    def _save(self):
        try:
            payload = {tid: t.to_dict() for tid, t in self.tasks.items()}
            with open(self.data_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        except Exception as e:  # noqa: BLE001
            log.error(f"任务数据保存失败: {e}")

    def _load(self):
        if not os.path.exists(self.data_file):
            return
        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                payload = json.load(f)
            for tid, data in payload.items():
                self.tasks[tid] = CollabTask.from_dict(data)
        except Exception as e:  # noqa: BLE001
            log.error(f"任务数据加载失败: {e}")

    # ---------------- 通知钩子（延迟导入避免循环依赖） ----------------
    def _notify(self, user: str, ntype: str, title: str, content: str,
                severity: str = "info", metadata: Optional[Dict] = None):
        try:
            # 使用共享单例，保证与 API 路由层看到同一份内存数据
            from collaboration.notification import get_notification_manager
            get_notification_manager().send(user, ntype, title, content, severity, metadata)
        except Exception as e:  # noqa: BLE001
            log.debug(f"通知发送失败(已忽略): {e}")

    # ---------------- CRUD ----------------
    def create_task(self, title: str, description: str, assignee: Optional[str] = None,
                    priority: str = "medium", due_date: Optional[str] = None,
                    tags: Optional[List[str]] = None,
                    related_assessment_id: Optional[str] = None,
                    assigner: Optional[str] = None) -> str:
        task = CollabTask(
            title=title,
            description=description,
            assignee=assignee,
            assigner=assigner,
            priority=priority,
            due_date=due_date,
            tags=tags,
            related_assessment_id=related_assessment_id,
        )
        task.log_activity("create", assigner or "system", f"创建任务: {title}")
        self.tasks[task.task_id] = task
        self._save()
        return task.task_id

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        task = self.tasks.get(task_id)
        return task.to_dict() if task else None

    def update_task(self, task_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        task = self.tasks.get(task_id)
        if not task:
            return None
        allowed = {"title", "description", "priority", "due_date", "tags",
                   "status", "related_assessment_id", "assignee"}
        for key, value in kwargs.items():
            if key not in allowed or value is None:
                continue
            old = getattr(task, key, None)
            if key == "status":
                if value not in VALID_STATUS:
                    continue
                task.completed_at = _now() if value == "completed" else None
            if key == "priority" and value not in VALID_PRIORITY:
                continue
            setattr(task, key, value)
            task.log_activity(f"update_{key}", "system", f"{key}: {old} -> {value}")
        task.updated_at = _now()
        # 任务完成时通知负责人
        if kwargs.get("status") == "completed" and task.assignee:
            self._notify(task.assignee, "task_completed",
                         f"任务已完成: {task.title}",
                         f"任务 {task.task_id} 已被标记为完成。", severity="info")
        self._save()
        return task.to_dict()

    def delete_task(self, task_id: str) -> bool:
        if task_id in self.tasks:
            del self.tasks[task_id]
            self._save()
            return True
        return False

    def list_tasks(self, status: Optional[str] = None, assignee: Optional[str] = None,
                   priority: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        results = []
        for task in self.tasks.values():
            if status and task.status != status:
                continue
            if assignee and task.assignee != assignee:
                continue
            if priority and task.priority != priority:
                continue
            results.append(task.to_dict())
        results.sort(key=lambda t: t["updated_at"], reverse=True)
        return results[:limit]

    # ---------------- 分配 / 评论 ----------------
    def assign_task(self, task_id: str, assignee: str, assigner: str) -> Optional[Dict[str, Any]]:
        task = self.tasks.get(task_id)
        if not task:
            return None
        old = task.assignee
        task.assignee = assignee
        task.assigner = assigner
        task.log_activity("assign", assigner, f"分配给 {assignee}(原负责人: {old})")
        self._notify(assignee, "task_assigned",
                     f"你被分配了新任务: {task.title}",
                     f"任务 {task.task_id} 由 {assigner} 分配给你。", severity="warning",
                     metadata={"task_id": task_id})
        self._save()
        return task.to_dict()

    @staticmethod
    def _parse_mentions(content: str) -> List[str]:
        """解析 @提及。"""
        return re.findall(r"@([A-Za-z0-9_\-\u4e00-\u9fa5]+)", content or "")

    def add_comment(self, task_id: str, user: str, content: str) -> Optional[Dict[str, Any]]:
        task = self.tasks.get(task_id)
        if not task:
            return None
        mentions = self._parse_mentions(content)
        comment = TaskComment(user=user, content=content, mentions=mentions)
        comment.task_id = task_id
        task.comments.append(comment)
        task.log_activity("comment", user, content[:120])
        # 通知被提及的用户
        for m in mentions:
            self._notify(m, "comment_mentioned",
                         f"{user} 在任务中提到了你",
                         f"任务 {task_id}: {content}", severity="info",
                         metadata={"task_id": task_id, "comment_id": comment.comment_id})
        self._save()
        return comment.to_dict()

    def get_comments(self, task_id: str) -> List[Dict[str, Any]]:
        task = self.tasks.get(task_id)
        return [c.to_dict() for c in task.comments] if task else []

    def get_activity_log(self, task_id: str) -> List[Dict[str, Any]]:
        task = self.tasks.get(task_id)
        return task.activity_log if task else []

    # ---------------- 统计 ----------------
    def get_stats(self, user: Optional[str] = None) -> Dict[str, Any]:
        pool = list(self.tasks.values())
        if user:
            pool = [t for t in pool if t.assignee == user]
        by_status: Dict[str, int] = {}
        by_priority: Dict[str, int] = {}
        by_assignee: Dict[str, int] = {}
        for t in pool:
            by_status[t.status] = by_status.get(t.status, 0) + 1
            by_priority[t.priority] = by_priority.get(t.priority, 0) + 1
            if t.assignee:
                by_assignee[t.assignee] = by_assignee.get(t.assignee, 0) + 1
        return {
            "total": len(pool),
            "by_status": by_status,
            "by_priority": by_priority,
            "by_assignee": by_assignee,
        }


# 模块级单例
_task_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager
