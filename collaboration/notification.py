#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collaboration/notification.py — 通知系统

提供任务分配、评论提及、告警触发、任务完成、系统公告等事件的站内通知。
数据持久化于 data/collaboration/notifications.json，并提供轮询式实时拉取。
"""
import os
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging

    log = logging.getLogger("collaboration.notification")

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_BASE_DIR, "data", "collaboration")
NOTIFICATIONS_FILE = os.path.join(DATA_DIR, "notifications.json")

VALID_TYPE = {"task_assigned", "comment_mentioned", "alert_triggered",
              "task_completed", "system_announcement"}
VALID_SEVERITY = {"info", "warning", "error"}
VALID_STATUS = {"unread", "read"}


def _now() -> str:
    return datetime.now().isoformat()


def _new_id() -> str:
    return f"ntf-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"


class Notification:
    """站内通知"""

    def __init__(self, user: str, ntype: str, title: str, content: str,
                 severity: str = "info", metadata: Optional[Dict] = None,
                 notification_id: Optional[str] = None):
        self.notification_id: str = notification_id or _new_id()
        self.user: str = user
        self.type: str = ntype if ntype in VALID_TYPE else "system_announcement"
        self.title: str = title
        self.content: str = content
        self.severity: str = severity if severity in VALID_SEVERITY else "info"
        self.status: str = "unread"
        self.created_at: str = _now()
        self.read_at: Optional[str] = None
        self.metadata: Dict[str, Any] = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "notification_id": self.notification_id,
            "user": self.user,
            "type": self.type,
            "title": self.title,
            "content": self.content,
            "severity": self.severity,
            "status": self.status,
            "created_at": self.created_at,
            "read_at": self.read_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Notification":
        ntf = cls(
            user=data.get("user", ""),
            ntype=data.get("type", "system_announcement"),
            title=data.get("title", ""),
            content=data.get("content", ""),
            severity=data.get("severity", "info"),
            metadata=data.get("metadata", {}),
            notification_id=data.get("notification_id"),
        )
        ntf.status = data.get("status", "unread")
        ntf.created_at = data.get("created_at", _now())
        ntf.read_at = data.get("read_at")
        return ntf


class NotificationManager:
    """通知管理器（JSON 文件持久化）。"""

    def __init__(self, data_file: Optional[str] = None):
        self.data_file = data_file or NOTIFICATIONS_FILE
        self.notifications: Dict[str, Notification] = {}
        os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
        self._load()

    # ---------------- 持久化 ----------------
    def _save(self):
        try:
            payload = {nid: n.to_dict() for nid, n in self.notifications.items()}
            with open(self.data_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        except Exception as e:  # noqa: BLE001
            log.error(f"通知数据保存失败: {e}")

    def _load(self):
        if not os.path.exists(self.data_file):
            return
        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                payload = json.load(f)
            for nid, data in payload.items():
                self.notifications[nid] = Notification.from_dict(data)
        except Exception as e:  # noqa: BLE001
            log.error(f"通知数据加载失败: {e}")

    # ---------------- 发送 / 查询 ----------------
    def send(self, user: str, notification_type: str, title: str, content: str,
             severity: str = "info",
             metadata: Optional[Dict] = None) -> Dict[str, Any]:
        ntf = Notification(user, notification_type, title, content, severity, metadata)
        self.notifications[ntf.notification_id] = ntf
        self._save()
        return ntf.to_dict()

    def list_notifications(self, user: str, status: Optional[str] = None,
                           limit: int = 50) -> List[Dict[str, Any]]:
        results = [n for n in self.notifications.values() if n.user == user]
        if status:
            results = [n for n in results if n.status == status]
        results.sort(key=lambda n: n.created_at, reverse=True)
        return [n.to_dict() for n in results[:limit]]

    def get_unread_count(self, user: str) -> int:
        return sum(1 for n in self.notifications.values()
                   if n.user == user and n.status == "unread")

    def mark_as_read(self, notification_id: str, user: str) -> bool:
        ntf = self.notifications.get(notification_id)
        if not ntf or ntf.user != user:
            return False
        ntf.status = "read"
        ntf.read_at = _now()
        self._save()
        return True

    def mark_all_as_read(self, user: str) -> int:
        count = 0
        for ntf in self.notifications.values():
            if ntf.user == user and ntf.status == "unread":
                ntf.status = "read"
                ntf.read_at = _now()
                count += 1
        if count:
            self._save()
        return count

    def delete_notification(self, notification_id: str, user: str) -> bool:
        ntf = self.notifications.get(notification_id)
        if not ntf or ntf.user != user:
            return False
        del self.notifications[notification_id]
        self._save()
        return True

    def get_stats(self, user: Optional[str] = None) -> Dict[str, Any]:
        pool = [n for n in self.notifications.values() if (user is None or n.user == user)]
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        unread = 0
        for n in pool:
            by_type[n.type] = by_type.get(n.type, 0) + 1
            by_severity[n.severity] = by_severity.get(n.severity, 0) + 1
            if n.status == "unread":
                unread += 1
        return {
            "total": len(pool),
            "unread": unread,
            "by_type": by_type,
            "by_severity": by_severity,
        }

    # ---------------- 轮询式实时拉取 ----------------
    def get_latest(self, user: str, since_timestamp: str) -> List[Dict[str, Any]]:
        """返回自 since_timestamp 之后该用户的新通知（供前端轮询）。"""
        results = []
        for n in self.notifications.values():
            if n.user != user:
                continue
            if n.created_at > since_timestamp:
                results.append(n.to_dict())
        results.sort(key=lambda n: n["created_at"], reverse=True)
        return results


# 模块级单例
_notification_manager: Optional[NotificationManager] = None


def get_notification_manager() -> NotificationManager:
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager
