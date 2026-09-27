#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
企业级API路由 - Enterprise API Routes
用户认证、扫描历史、监控管理、审计日志、任务队列、系统统计
"""
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import time

try:
    from enterprise.database import (
        create_user, authenticate_user, get_user_by_api_key, list_users,
        save_scan_result, get_scan_history, get_scan_result,
        add_monitor_target, get_monitor_targets,
        add_audit_log, get_audit_logs,
        create_task, get_next_task, complete_task,
        get_statistics, generate_api_key
    )
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from enterprise.database import (
        create_user, authenticate_user, get_user_by_api_key, list_users,
        save_scan_result, get_scan_history, get_scan_result,
        add_monitor_target, get_monitor_targets,
        add_audit_log, get_audit_logs,
        create_task, get_next_task, complete_task,
        get_statistics, generate_api_key
    )

router = APIRouter(prefix="/api/v1/enterprise", tags=["企业级功能"])


# ============================================================
# 请求模型
# ============================================================

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class MonitorTargetRequest(BaseModel):
    target: str
    scan_interval: int = 3600
    ports: str = "1-1000"


class TaskRequest(BaseModel):
    task_type: str
    parameters: Dict[str, Any] = {}
    priority: int = 5


# ============================================================
# 认证依赖
# ============================================================

async def get_current_user(x_api_key: str = Header(None)):
    """通过API Key获取当前用户"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="缺少API Key")
    user = get_user_by_api_key(x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return user


async def require_admin(user: dict = Depends(get_current_user)):
    """要求管理员权限"""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


# ============================================================
# 用户认证
# ============================================================

@router.post("/auth/register")
async def register(request: RegisterRequest):
    """用户注册"""
    result = create_user(request.username, request.password, request.email)
    if result["status"] == "failed":
        raise HTTPException(status_code=400, detail=result["error"])
    add_audit_log(result.get("user_id", 0), "register", request.username)
    return result


@router.post("/auth/login")
async def login(request: LoginRequest):
    """用户登录"""
    user = authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    add_audit_log(user["id"], "login", request.username)
    return {
        "status": "success",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "scan_quota": user["scan_quota"],
            "scans_used": user["scans_used"]
        },
        "api_key": user["api_key"]
    }


@router.get("/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    """获取当前用户信息"""
    return {"status": "success", "user": user}


@router.get("/users")
async def get_users(user: dict = Depends(require_admin)):
    """列出所有用户（管理员）"""
    return {"status": "success", "users": list_users()}


# ============================================================
# 扫描历史
# ============================================================

@router.get("/scans/history")
async def scan_history(user: dict = Depends(get_current_user), limit: int = 50):
    """获取用户扫描历史"""
    history = get_scan_history(user["id"], limit)
    return {"status": "success", "total": len(history), "history": history}


@router.get("/scans/{scan_id}")
async def scan_detail(scan_id: int, user: dict = Depends(get_current_user)):
    """获取扫描结果详情"""
    result = get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="扫描结果不存在")
    if result["user_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="无权访问此扫描结果")
    return {"status": "success", "scan": result}


# ============================================================
# 持续监控
# ============================================================

@router.post("/monitor/targets")
async def add_target(request: MonitorTargetRequest, user: dict = Depends(get_current_user)):
    """添加监控目标"""
    target_id = add_monitor_target(user["id"], request.target, request.scan_interval, request.ports)
    add_audit_log(user["id"], "add_monitor_target", request.target)
    return {"status": "success", "target_id": target_id, "target": request.target}


@router.get("/monitor/targets")
async def list_targets(user: dict = Depends(get_current_user)):
    """获取监控目标列表"""
    targets = get_monitor_targets(user["id"])
    return {"status": "success", "total": len(targets), "targets": targets}


# ============================================================
# 审计日志
# ============================================================

@router.get("/audit/logs")
async def audit_logs(user: dict = Depends(get_current_user), limit: int = 100):
    """获取审计日志"""
    logs = get_audit_logs(user["id"] if user["role"] != "admin" else None, limit)
    return {"status": "success", "total": len(logs), "logs": logs}


# ============================================================
# 任务队列
# ============================================================

@router.post("/tasks")
async def create_new_task(request: TaskRequest, user: dict = Depends(get_current_user)):
    """创建异步任务"""
    task_id = create_task(user["id"], request.task_type, request.parameters, request.priority)
    return {"status": "success", "task_id": task_id, "message": "任务已创建，将在后台执行"}


# ============================================================
# 系统统计
# ============================================================

@router.get("/statistics")
async def system_statistics(user: dict = Depends(require_admin)):
    """获取系统统计数据（管理员）"""
    stats = get_statistics()
    return {"status": "success", "statistics": stats}


@router.get("/dashboard")
async def enterprise_dashboard(user: dict = Depends(get_current_user)):
    """企业级仪表盘数据"""
    history = get_scan_history(user["id"], 10)
    targets = get_monitor_targets(user["id"])
    logs = get_audit_logs(user["id"], 10)

    total_findings = sum(h.get("findings_count", 0) for h in history)
    critical = sum(h.get("critical_count", 0) for h in history)
    high = sum(h.get("high_count", 0) for h in history)

    return {
        "status": "success",
        "user": {"username": user["username"], "role": user["role"],
                 "scan_quota": user["scan_quota"], "scans_used": user["scans_used"]},
        "summary": {
            "total_scans": len(history),
            "total_findings": total_findings,
            "critical_vulns": critical,
            "high_vulns": high,
            "monitor_targets": len(targets),
            "recent_activities": len(logs)
        },
        "recent_scans": history[:5],
        "monitor_targets": targets[:5],
        "recent_activities": logs[:5]
    }
