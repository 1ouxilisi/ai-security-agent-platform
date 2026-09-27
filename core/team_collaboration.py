#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
团队协作系统
Team Collaboration System

功能：任务分配、评论讨论、实时通知、团队管理、项目协作
"""

import os
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List
from enum import Enum
from loguru import logger


class TaskPriority(str, Enum):
    """任务优先级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(str, Enum):
    """任务状态"""
    TODO = "todo"
    IN_PROGRESS = "in_progress"
    REVIEW = "review"
    DONE = "done"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class NotificationType(str, Enum):
    """通知类型"""
    TASK_ASSIGNED = "task_assigned"
    TASK_UPDATED = "task_updated"
    TASK_COMPLETED = "task_completed"
    COMMENT_ADDED = "comment_added"
    MENTION = "mention"
    SYSTEM = "system"
    ALERT = "alert"


@dataclass
class Team:
    """团队"""
    team_id: str
    name: str
    description: str = ""
    owner_id: str = ""
    members: List[str] = field(default_factory=list)  # user_id列表
    created_at: float = field(default_factory=time.time)
    settings: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'team_id': self.team_id,
            'name': self.name,
            'description': self.description,
            'owner_id': self.owner_id,
            'members': self.members,
            'member_count': len(self.members),
            'created_at': self.created_at,
            'settings': self.settings,
        }


@dataclass
class Project:
    """项目"""
    project_id: str
    name: str
    description: str = ""
    team_id: str = ""
    owner_id: str = ""
    members: List[str] = field(default_factory=list)
    status: str = "active"  # active/archived/completed
    priority: TaskPriority = TaskPriority.MEDIUM
    created_at: float = field(default_factory=time.time)
    due_date: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'project_id': self.project_id,
            'name': self.name,
            'description': self.description,
            'team_id': self.team_id,
            'owner_id': self.owner_id,
            'members': self.members,
            'member_count': len(self.members),
            'status': self.status,
            'priority': self.priority.value,
            'created_at': self.created_at,
            'due_date': self.due_date,
            'tags': self.tags,
            'metadata': self.metadata,
        }


@dataclass
class Task:
    """协作任务"""
    task_id: str
    title: str
    description: str = ""
    project_id: str = ""
    assignee_id: Optional[str] = None
    creator_id: str = ""
    status: TaskStatus = TaskStatus.TODO
    priority: TaskPriority = TaskPriority.MEDIUM
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    due_date: Optional[float] = None
    completed_at: Optional[float] = None
    subtasks: List[Dict[str, Any]] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    estimated_hours: float = 0.0
    spent_hours: float = 0.0
    labels: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'title': self.title,
            'description': self.description,
            'project_id': self.project_id,
            'assignee_id': self.assignee_id,
            'creator_id': self.creator_id,
            'status': self.status.value,
            'priority': self.priority.value,
            'tags': self.tags,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'due_date': self.due_date,
            'completed_at': self.completed_at,
            'subtasks': self.subtasks,
            'attachments': self.attachments,
            'estimated_hours': self.estimated_hours,
            'spent_hours': self.spent_hours,
            'labels': self.labels,
        }


@dataclass
class Comment:
    """评论"""
    comment_id: str
    task_id: str = ""
    project_id: str = ""
    author_id: str = ""
    content: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    mentions: List[str] = field(default_factory=list)  # 提到的user_id
    attachments: List[str] = field(default_factory=list)
    is_resolved: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'comment_id': self.comment_id,
            'task_id': self.task_id,
            'project_id': self.project_id,
            'author_id': self.author_id,
            'content': self.content,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'mentions': self.mentions,
            'attachments': self.attachments,
            'is_resolved': self.is_resolved,
        }


@dataclass
class Notification:
    """通知"""
    notification_id: str
    user_id: str
    type: NotificationType
    title: str
    content: str = ""
    related_type: str = ""  # task/project/comment
    related_id: str = ""
    created_at: float = field(default_factory=time.time)
    is_read: bool = False
    read_at: Optional[float] = None
    action_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'notification_id': self.notification_id,
            'user_id': self.user_id,
            'type': self.type.value,
            'title': self.title,
            'content': self.content,
            'related_type': self.related_type,
            'related_id': self.related_id,
            'created_at': self.created_at,
            'is_read': self.is_read,
            'read_at': self.read_at,
            'action_url': self.action_url,
        }


@dataclass
class ActivityLog:
    """活动日志"""
    log_id: str
    user_id: str
    action: str
    target_type: str  # task/project/team/comment
    target_id: str
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    ip_address: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'log_id': self.log_id,
            'user_id': self.user_id,
            'action': self.action,
            'target_type': self.target_type,
            'target_id': self.target_id,
            'details': self.details,
            'created_at': self.created_at,
            'ip_address': self.ip_address,
        }


class TeamCollaborationManager:
    """团队协作管理器"""

    def __init__(self, data_dir: str = "data/collaboration"):
        self.data_dir = data_dir
        self.teams_file = os.path.join(data_dir, "teams.json")
        self.projects_file = os.path.join(data_dir, "projects.json")
        self.tasks_file = os.path.join(data_dir, "tasks.json")
        self.comments_file = os.path.join(data_dir, "comments.json")
        self.notifications_file = os.path.join(data_dir, "notifications.json")
        self.activity_file = os.path.join(data_dir, "activity.json")

        self._teams: Dict[str, Team] = {}
        self._projects: Dict[str, Project] = {}
        self._tasks: Dict[str, Task] = {}
        self._comments: Dict[str, Comment] = {}
        self._notifications: Dict[str, Notification] = {}
        self._activity: List[ActivityLog] = []

        os.makedirs(data_dir, exist_ok=True)
        self._load_all()

        logger.info("团队协作管理器初始化完成")

    # ============== 团队管理 ==============

    def create_team(self, name: str, owner_id: str, description: str = "") -> Team:
        """创建团队"""
        team_id = str(uuid.uuid4())
        team = Team(
            team_id=team_id,
            name=name,
            description=description,
            owner_id=owner_id,
            members=[owner_id],
        )
        self._teams[team_id] = team
        self._save_teams()
        self._log_activity(owner_id, "create_team", "team", team_id, {'name': name})
        logger.info(f"创建团队: {name} ({team_id})")
        return team

    def add_team_member(self, team_id: str, user_id: str) -> bool:
        """添加团队成员"""
        team = self._teams.get(team_id)
        if team and user_id not in team.members:
            team.members.append(user_id)
            self._save_teams()
            self._create_notification(
                user_id=user_id,
                type=NotificationType.SYSTEM,
                title="加入团队",
                content=f"你已加入团队: {team.name}",
                related_type="team",
                related_id=team_id,
            )
            return True
        return False

    def list_teams(self, user_id: str = None) -> List[Team]:
        """列出团队"""
        teams = list(self._teams.values())
        if user_id:
            teams = [t for t in teams if user_id in t.members]
        return sorted(teams, key=lambda t: t.created_at, reverse=True)

    # ============== 项目管理 ==============

    def create_project(self, name: str, team_id: str, owner_id: str,
                       description: str = "", priority: TaskPriority = TaskPriority.MEDIUM) -> Project:
        """创建项目"""
        project_id = str(uuid.uuid4())
        project = Project(
            project_id=project_id,
            name=name,
            description=description,
            team_id=team_id,
            owner_id=owner_id,
            members=[owner_id],
            priority=priority,
        )
        self._projects[project_id] = project
        self._save_projects()
        self._log_activity(owner_id, "create_project", "project", project_id, {'name': name})
        logger.info(f"创建项目: {name} ({project_id})")
        return project

    def list_projects(self, team_id: str = None, user_id: str = None) -> List[Project]:
        """列出项目"""
        projects = list(self._projects.values())
        if team_id:
            projects = [p for p in projects if p.team_id == team_id]
        if user_id:
            projects = [p for p in projects if user_id in p.members]
        return sorted(projects, key=lambda p: p.created_at, reverse=True)

    # ============== 任务管理 ==============

    def create_task(self, title: str, project_id: str, creator_id: str,
                    description: str = "", assignee_id: str = None,
                    priority: TaskPriority = TaskPriority.MEDIUM,
                    due_date: float = None, estimated_hours: float = 0.0) -> Task:
        """创建任务"""
        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            title=title,
            description=description,
            project_id=project_id,
            creator_id=creator_id,
            assignee_id=assignee_id,
            priority=priority,
            due_date=due_date,
            estimated_hours=estimated_hours,
        )
        self._tasks[task_id] = task
        self._save_tasks()
        self._log_activity(creator_id, "create_task", "task", task_id, {'title': title})

        if assignee_id:
            self._create_notification(
                user_id=assignee_id,
                type=NotificationType.TASK_ASSIGNED,
                title="新任务分配",
                content=f"你被分配了新任务: {title}",
                related_type="task",
                related_id=task_id,
            )

        logger.info(f"创建任务: {title} ({task_id})")
        return task

    def update_task_status(self, task_id: str, status: TaskStatus, user_id: str) -> Optional[Task]:
        """更新任务状态"""
        task = self._tasks.get(task_id)
        if not task:
            return None

        old_status = task.status
        task.status = status
        task.updated_at = time.time()

        if status == TaskStatus.DONE:
            task.completed_at = time.time()

        self._save_tasks()
        self._log_activity(user_id, "update_task_status", "task", task_id,
                          {'old_status': old_status.value, 'new_status': status.value})

        # 通知创建者和负责人
        if task.creator_id and task.creator_id != user_id:
            self._create_notification(
                user_id=task.creator_id,
                type=NotificationType.TASK_UPDATED,
                title="任务状态更新",
                content=f"任务 '{task.title}' 状态更新为: {status.value}",
                related_type="task",
                related_id=task_id,
            )

        if status == TaskStatus.DONE and task.assignee_id:
            self._create_notification(
                user_id=task.assignee_id,
                type=NotificationType.TASK_COMPLETED,
                title="任务完成",
                content=f"任务 '{task.title}' 已完成",
                related_type="task",
                related_id=task_id,
            )

        return task

    def assign_task(self, task_id: str, assignee_id: str, user_id: str) -> Optional[Task]:
        """分配任务"""
        task = self._tasks.get(task_id)
        if not task:
            return None

        task.assignee_id = assignee_id
        task.updated_at = time.time()
        self._save_tasks()
        self._log_activity(user_id, "assign_task", "task", task_id, {'assignee_id': assignee_id})

        self._create_notification(
            user_id=assignee_id,
            type=NotificationType.TASK_ASSIGNED,
            title="任务分配",
            content=f"你被分配了任务: {task.title}",
            related_type="task",
            related_id=task_id,
        )

        return task

    def list_tasks(self, project_id: str = None, assignee_id: str = None,
                   status: TaskStatus = None, priority: TaskPriority = None) -> List[Task]:
        """列出任务"""
        tasks = list(self._tasks.values())
        if project_id:
            tasks = [t for t in tasks if t.project_id == project_id]
        if assignee_id:
            tasks = [t for t in tasks if t.assignee_id == assignee_id]
        if status:
            tasks = [t for t in tasks if t.status == status]
        if priority:
            tasks = [t for t in tasks if t.priority == priority]
        return sorted(tasks, key=lambda t: t.created_at, reverse=True)

    def get_task(self, task_id: str) -> Optional[Task]:
        """获取任务"""
        return self._tasks.get(task_id)

    # ============== 评论管理 ==============

    def add_comment(self, task_id: str, author_id: str, content: str,
                    project_id: str = "") -> Comment:
        """添加评论"""
        comment_id = str(uuid.uuid4())

        # 提取@提及
        mentions = []
        for word in content.split():
            if word.startswith('@') and len(word) > 1:
                mentions.append(word[1:])

        comment = Comment(
            comment_id=comment_id,
            task_id=task_id,
            project_id=project_id,
            author_id=author_id,
            content=content,
            mentions=mentions,
        )
        self._comments[comment_id] = comment
        self._save_comments()
        self._log_activity(author_id, "add_comment", "comment", comment_id, {'task_id': task_id})

        # 通知任务相关人员
        task = self._tasks.get(task_id)
        if task:
            notify_users = set()
            if task.creator_id and task.creator_id != author_id:
                notify_users.add(task.creator_id)
            if task.assignee_id and task.assignee_id != author_id:
                notify_users.add(task.assignee_id)

            for user_id in notify_users:
                self._create_notification(
                    user_id=user_id,
                    type=NotificationType.COMMENT_ADDED,
                    title="新评论",
                    content=f"任务 '{task.title}' 有新评论",
                    related_type="comment",
                    related_id=comment_id,
                )

        # 通知被@的用户
        for mentioned_user in mentions:
            self._create_notification(
                user_id=mentioned_user,
                type=NotificationType.MENTION,
                title="有人提到你",
                content=f"在评论中提到了你: {content[:50]}...",
                related_type="comment",
                related_id=comment_id,
            )

        return comment

    def list_comments(self, task_id: str = None, project_id: str = None) -> List[Comment]:
        """列出评论"""
        comments = list(self._comments.values())
        if task_id:
            comments = [c for c in comments if c.task_id == task_id]
        if project_id:
            comments = [c for c in comments if c.project_id == project_id]
        return sorted(comments, key=lambda c: c.created_at)

    # ============== 通知管理 ==============

    def _create_notification(self, user_id: str, type: NotificationType,
                              title: str, content: str = "",
                              related_type: str = "", related_id: str = "",
                              action_url: str = "") -> Notification:
        """创建通知"""
        notification_id = str(uuid.uuid4())
        notification = Notification(
            notification_id=notification_id,
            user_id=user_id,
            type=type,
            title=title,
            content=content,
            related_type=related_type,
            related_id=related_id,
            action_url=action_url,
        )
        self._notifications[notification_id] = notification
        self._save_notifications()
        return notification

    def get_notifications(self, user_id: str, unread_only: bool = False,
                           limit: int = 50) -> List[Notification]:
        """获取用户通知"""
        notifications = [n for n in self._notifications.values() if n.user_id == user_id]
        if unread_only:
            notifications = [n for n in notifications if not n.is_read]
        notifications.sort(key=lambda n: n.created_at, reverse=True)
        return notifications[:limit]

    def mark_notification_read(self, notification_id: str, user_id: str) -> bool:
        """标记通知已读"""
        notification = self._notifications.get(notification_id)
        if notification and notification.user_id == user_id:
            notification.is_read = True
            notification.read_at = time.time()
            self._save_notifications()
            return True
        return False

    def mark_all_notifications_read(self, user_id: str) -> int:
        """标记所有通知已读"""
        count = 0
        for notification in self._notifications.values():
            if notification.user_id == user_id and not notification.is_read:
                notification.is_read = True
                notification.read_at = time.time()
                count += 1
        if count > 0:
            self._save_notifications()
        return count

    def get_unread_count(self, user_id: str) -> int:
        """获取未读通知数"""
        return len([n for n in self._notifications.values() if n.user_id == user_id and not n.is_read])

    # ============== 活动日志 ==============

    def _log_activity(self, user_id: str, action: str, target_type: str,
                      target_id: str, details: Dict[str, Any] = None,
                      ip_address: str = "") -> ActivityLog:
        """记录活动"""
        log = ActivityLog(
            log_id=str(uuid.uuid4()),
            user_id=user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
            ip_address=ip_address,
        )
        self._activity.append(log)
        if len(self._activity) > 10000:
            self._activity = self._activity[-10000:]
        self._save_activity()
        return log

    def get_activity_logs(self, user_id: str = None, target_type: str = None,
                          limit: int = 100) -> List[ActivityLog]:
        """获取活动日志"""
        logs = list(self._activity)
        if user_id:
            logs = [l for l in logs if l.user_id == user_id]
        if target_type:
            logs = [l for l in logs if l.target_type == target_type]
        logs.sort(key=lambda l: l.created_at, reverse=True)
        return logs[:limit]

    # ============== 统计 ==============

    def get_project_stats(self, project_id: str) -> Dict[str, Any]:
        """获取项目统计"""
        tasks = [t for t in self._tasks.values() if t.project_id == project_id]
        stats = {
            'total_tasks': len(tasks),
            'todo': len([t for t in tasks if t.status == TaskStatus.TODO]),
            'in_progress': len([t for t in tasks if t.status == TaskStatus.IN_PROGRESS]),
            'review': len([t for t in tasks if t.status == TaskStatus.REVIEW]),
            'done': len([t for t in tasks if t.status == TaskStatus.DONE]),
            'blocked': len([t for t in tasks if t.status == TaskStatus.BLOCKED]),
            'total_estimated_hours': sum(t.estimated_hours for t in tasks),
            'total_spent_hours': sum(t.spent_hours for t in tasks),
            'comments_count': len([c for c in self._comments.values() if c.project_id == project_id]),
        }
        stats['completion_rate'] = round(stats['done'] / stats['total_tasks'] * 100, 1) if stats['total_tasks'] > 0 else 0
        return stats

    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """获取用户统计"""
        assigned_tasks = [t for t in self._tasks.values() if t.assignee_id == user_id]
        created_tasks = [t for t in self._tasks.values() if t.creator_id == user_id]

        return {
            'assigned_tasks': len(assigned_tasks),
            'completed_tasks': len([t for t in assigned_tasks if t.status == TaskStatus.DONE]),
            'in_progress_tasks': len([t for t in assigned_tasks if t.status == TaskStatus.IN_PROGRESS]),
            'created_tasks': len(created_tasks),
            'comments_count': len([c for c in self._comments.values() if c.author_id == user_id]),
            'unread_notifications': self.get_unread_count(user_id),
            'teams_count': len([t for t in self._teams.values() if user_id in t.members]),
        }

    # ============== 持久化 ==============

    def _load_all(self):
        """加载所有数据"""
        self._load_teams()
        self._load_projects()
        self._load_tasks()
        self._load_comments()
        self._load_notifications()
        self._load_activity()

    def _load_teams(self):
        if os.path.exists(self.teams_file):
            try:
                with open(self.teams_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        team = Team(**{k: v for k, v in data.items() if k in Team.__dataclass_fields__})
                        self._teams[team.team_id] = team
            except Exception as e:
                logger.warning(f"加载团队数据失败: {e}")

    def _load_projects(self):
        if os.path.exists(self.projects_file):
            try:
                with open(self.projects_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        project = Project(**{k: v for k, v in data.items() if k in Project.__dataclass_fields__})
                        if isinstance(project.priority, str):
                            project.priority = TaskPriority(project.priority)
                        self._projects[project.project_id] = project
            except Exception as e:
                logger.warning(f"加载项目数据失败: {e}")

    def _load_tasks(self):
        if os.path.exists(self.tasks_file):
            try:
                with open(self.tasks_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        task = Task(**{k: v for k, v in data.items() if k in Task.__dataclass_fields__})
                        if isinstance(task.status, str):
                            task.status = TaskStatus(task.status)
                        if isinstance(task.priority, str):
                            task.priority = TaskPriority(task.priority)
                        self._tasks[task.task_id] = task
            except Exception as e:
                logger.warning(f"加载任务数据失败: {e}")

    def _load_comments(self):
        if os.path.exists(self.comments_file):
            try:
                with open(self.comments_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        comment = Comment(**{k: v for k, v in data.items() if k in Comment.__dataclass_fields__})
                        self._comments[comment.comment_id] = comment
            except Exception as e:
                logger.warning(f"加载评论数据失败: {e}")

    def _load_notifications(self):
        if os.path.exists(self.notifications_file):
            try:
                with open(self.notifications_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        notification = Notification(**{k: v for k, v in data.items() if k in Notification.__dataclass_fields__})
                        if isinstance(notification.type, str):
                            notification.type = NotificationType(notification.type)
                        self._notifications[notification.notification_id] = notification
            except Exception as e:
                logger.warning(f"加载通知数据失败: {e}")

    def _load_activity(self):
        if os.path.exists(self.activity_file):
            try:
                with open(self.activity_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        log = ActivityLog(**{k: v for k, v in data.items() if k in ActivityLog.__dataclass_fields__})
                        self._activity.append(log)
            except Exception as e:
                logger.warning(f"加载活动数据失败: {e}")

    def _save_teams(self):
        try:
            with open(self.teams_file, 'w', encoding='utf-8') as f:
                json.dump([t.to_dict() for t in self._teams.values()], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存团队数据失败: {e}")

    def _save_projects(self):
        try:
            with open(self.projects_file, 'w', encoding='utf-8') as f:
                json.dump([p.to_dict() for p in self._projects.values()], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存项目数据失败: {e}")

    def _save_tasks(self):
        try:
            with open(self.tasks_file, 'w', encoding='utf-8') as f:
                json.dump([t.to_dict() for t in self._tasks.values()], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存任务数据失败: {e}")

    def _save_comments(self):
        try:
            with open(self.comments_file, 'w', encoding='utf-8') as f:
                json.dump([c.to_dict() for c in self._comments.values()], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存评论数据失败: {e}")

    def _save_notifications(self):
        try:
            with open(self.notifications_file, 'w', encoding='utf-8') as f:
                json.dump([n.to_dict() for n in list(self._notifications.values())[-1000:]], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存通知数据失败: {e}")

    def _save_activity(self):
        try:
            with open(self.activity_file, 'w', encoding='utf-8') as f:
                json.dump([l.to_dict() for l in self._activity[-1000:]], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存活动数据失败: {e}")


# 全局团队协作管理器实例
_global_collaboration_manager: Optional[TeamCollaborationManager] = None


def get_collaboration_manager() -> TeamCollaborationManager:
    """获取全局团队协作管理器实例"""
    global _global_collaboration_manager
    if _global_collaboration_manager is None:
        _global_collaboration_manager = TeamCollaborationManager()
    return _global_collaboration_manager
