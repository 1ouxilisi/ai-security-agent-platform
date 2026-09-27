#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_server/collaboration_routes.py — 协作模块 REST API

FastAPI APIRouter，前缀 /api/collaboration。
所有端点统一 JSON 返回格式，异常被捕获后返回 {"success": False, ...}，不抛 500。
"""
import os
import sys
from typing import Optional, List

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collaboration.task_manager import get_task_manager
from collaboration.notification import get_notification_manager

# 模块级单例（共享进程内同一份内存数据，保证任务->通知联动立即可见）
task_manager = get_task_manager()
notification_manager = get_notification_manager()

router = APIRouter(prefix="/api/collaboration", tags=["协作"])


# ==================== 响应封装 ====================
def _ok(data=None, message: str = "ok") -> dict:
    return {"success": True, "message": message, "data": data}


def _err(message: str, data=None) -> dict:
    return {"success": False, "message": message, "data": data}


# ==================== 请求模型 ====================
class CreateTaskRequest(BaseModel):
    title: str = Field(..., description="任务标题")
    description: str = Field("", description="任务描述")
    assignee: Optional[str] = Field(None, description="负责人")
    priority: str = Field("medium", description="优先级 low/medium/high/critical")
    due_date: Optional[str] = Field(None, description="截止日期 ISO 字符串")
    tags: Optional[List[str]] = Field(None, description="标签列表")
    related_assessment_id: Optional[str] = Field(None, description="关联评估 ID")


class UpdateTaskRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    due_date: Optional[str] = None
    tags: Optional[List[str]] = None
    assignee: Optional[str] = None


class AssignTaskRequest(BaseModel):
    assignee: str = Field(..., description="新负责人")
    assigner: str = Field("system", description="分配人")


class CommentRequest(BaseModel):
    user: str = Field(..., description="评论人")
    content: str = Field(..., description="评论内容")


# ==================== 任务端点 ====================
@router.get("/tasks")
def list_tasks(status: Optional[str] = Query(None),
               assignee: Optional[str] = Query(None),
               priority: Optional[str] = Query(None),
               limit: int = Query(50, le=200)):
    try:
        data = task_manager.list_tasks(status=status, assignee=assignee,
                                      priority=priority, limit=limit)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(f"列出任务失败: {e}")


@router.post("/tasks")
def create_task(req: CreateTaskRequest):
    try:
        task_id = task_manager.create_task(
            title=req.title,
            description=req.description,
            assignee=req.assignee,
            priority=req.priority,
            due_date=req.due_date,
            tags=req.tags,
            related_assessment_id=req.related_assessment_id,
        )
        return _ok({"task_id": task_id}, "任务创建成功")
    except Exception as e:  # noqa: BLE001
        return _err(f"创建任务失败: {e}")


@router.get("/tasks/stats")
def task_stats(user: Optional[str] = Query(None)):
    try:
        return _ok(task_manager.get_stats(user=user))
    except Exception as e:  # noqa: BLE001
        return _err(f"任务统计失败: {e}")


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        data = task_manager.get_task(task_id)
        if data is None:
            return _err("任务不存在", None)
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _err(f"获取任务失败: {e}")


@router.put("/tasks/{task_id}")
def update_task(task_id: str, req: UpdateTaskRequest):
    try:
        data = task_manager.update_task(task_id, **req.model_dump(exclude_unset=True))
        if data is None:
            return _err("任务不存在")
        return _ok(data, "任务更新成功")
    except Exception as e:  # noqa: BLE001
        return _err(f"更新任务失败: {e}")


@router.delete("/tasks/{task_id}")
def delete_task(task_id: str):
    try:
        ok = task_manager.delete_task(task_id)
        return _ok({"deleted": ok}, "已删除" if ok else "任务不存在")
    except Exception as e:  # noqa: BLE001
        return _err(f"删除任务失败: {e}")


@router.post("/tasks/{task_id}/assign")
def assign_task(task_id: str, req: AssignTaskRequest):
    try:
        data = task_manager.assign_task(task_id, req.assignee, req.assigner)
        if data is None:
            return _err("任务不存在")
        return _ok(data, "任务分配成功")
    except Exception as e:  # noqa: BLE001
        return _err(f"分配任务失败: {e}")


@router.get("/tasks/{task_id}/comments")
def get_comments(task_id: str):
    try:
        return _ok(task_manager.get_comments(task_id))
    except Exception as e:  # noqa: BLE001
        return _err(f"获取评论失败: {e}")


@router.post("/tasks/{task_id}/comments")
def add_comment(task_id: str, req: CommentRequest):
    try:
        data = task_manager.add_comment(task_id, req.user, req.content)
        if data is None:
            return _err("任务不存在")
        return _ok(data, "评论已添加")
    except Exception as e:  # noqa: BLE001
        return _err(f"添加评论失败: {e}")


# ==================== 通知端点 ====================
@router.get("/notifications")
def list_notifications(user: str = Query(...),
                      status: Optional[str] = Query(None),
                      limit: int = Query(50, le=200)):
    try:
        return _ok(notification_manager.list_notifications(user, status=status, limit=limit))
    except Exception as e:  # noqa: BLE001
        return _err(f"列出通知失败: {e}")


@router.get("/notifications/unread-count")
def unread_count(user: str = Query(...)):
    try:
        return _ok({"user": user, "unread": notification_manager.get_unread_count(user)})
    except Exception as e:  # noqa: BLE001
        return _err(f"获取未读数量失败: {e}")


@router.get("/notifications/latest")
def latest_notifications(user: str = Query(...),
                         since: str = Query("1970-01-01T00:00:00")):
    """轮询拉取自 since 之后的新通知。"""
    try:
        return _ok(notification_manager.get_latest(user, since))
    except Exception as e:  # noqa: BLE001
        return _err(f"拉取最新通知失败: {e}")


@router.post("/notifications/{notification_id}/read")
def mark_read(notification_id: str, user: str = Query(...)):
    try:
        ok = notification_manager.mark_as_read(notification_id, user)
        return _ok({"marked": ok}, "已标记" if ok else "通知不存在")
    except Exception as e:  # noqa: BLE001
        return _err(f"标记已读失败: {e}")


@router.post("/notifications/read-all")
def mark_all_read(user: str = Query(...)):
    try:
        count = notification_manager.mark_all_as_read(user)
        return _ok({"marked": count}, "全部已读")
    except Exception as e:  # noqa: BLE001
        return _err(f"全部已读失败: {e}")


@router.delete("/notifications/{notification_id}")
def delete_notification(notification_id: str, user: str = Query(...)):
    try:
        ok = notification_manager.delete_notification(notification_id, user)
        return _ok({"deleted": ok}, "已删除" if ok else "通知不存在")
    except Exception as e:  # noqa: BLE001
        return _err(f"删除通知失败: {e}")
