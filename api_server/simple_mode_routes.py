# -*- coding: utf-8 -*-
"""
simple_mode_routes.py —— 极简模式 API（21 个端点）

统一响应：{success, data, error}。
前端页面路由 /simple-console 由集成脚本统一挂载。
仅限授权环境下的安全测试与演示使用。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from simple_mode import (
    get_layout,
    get_task_manager,
    get_onboarding_guide,
    get_dashboard,
)
from simple_mode.task_manager_simple import STAGES

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/simple", tags=["极简模式"])

NOTICE = "仅限授权环境：极简模式仅用于授权安全测试 / 教学 / 演示。"


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                        "error": message}, status_code=status)


class CreateTaskBody(BaseModel):
    target: str = Field(..., description="测试目标 URL")
    name: Optional[str] = Field(None, description="任务名")
    options: Dict[str, Any] = Field(default_factory=dict)


# ----------------------------------------------------------------------
# 仪表盘 / 布局 / 功能
# ----------------------------------------------------------------------
@router.get("/dashboard")
def dashboard(session_id: str = Query("default")):
    """首屏聚合：布局 + 功能 + 统计 + 引导状态。"""
    try:
        return _ok(get_dashboard().overview(session_id).get("data"))
    except Exception as e:  # noqa: BLE001
        logger.exception("simple dashboard error")
        return _err(500, f"仪表盘加载失败：{e}")


@router.get("/layout")
def layout():
    """极简布局配置（三栏 + 顶部导航 + UI 常量）。"""
    try:
        return _ok(get_layout().get_layout())
    except Exception as e:  # noqa: BLE001
        return _err(500, f"布局加载失败：{e}")


@router.get("/features")
def features():
    """核心功能白名单。"""
    try:
        return _ok({"features": get_layout().get_core_features(),
                    "notice": NOTICE})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"功能列表加载失败：{e}")


@router.get("/hidden")
def hidden_info():
    """被极简模式隐藏的模块说明。"""
    try:
        return _ok(get_layout().get_hidden_count())
    except Exception as e:  # noqa: BLE001
        return _err(500, f"隐藏信息加载失败：{e}")


@router.get("/stages")
def stages():
    """任务流水线阶段定义。"""
    try:
        return _ok({"stages": STAGES})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"阶段加载失败：{e}")


@router.get("/ping")
def ping():
    return _ok({"pong": True, "mode": "simple"})


# ----------------------------------------------------------------------
# 任务
# ----------------------------------------------------------------------
@router.post("/tasks")
def create_task(body: CreateTaskBody):
    """新建任务。"""
    try:
        result = get_task_manager().create_task(
            body.target, body.name, body.options)
        if not result.get("success"):
            return _err(400, result.get("error", "创建失败"))
        return _ok(result["data"])
    except Exception as e:  # noqa: BLE001
        logger.exception("simple create_task error")
        return _err(500, f"创建任务失败：{e}")


@router.get("/tasks")
def list_tasks(status: Optional[str] = None, limit: int = 50):
    """任务列表。"""
    try:
        return _ok(get_task_manager().list_tasks(status, limit).get("data"))
    except Exception as e:  # noqa: BLE001
        return _err(500, f"任务列表加载失败：{e}")


@router.get("/stats")
def task_stats():
    """任务统计。"""
    try:
        return _ok(get_task_manager().stats().get("data"))
    except Exception as e:  # noqa: BLE001
        return _err(500, f"统计加载失败：{e}")


@router.get("/tasks/{task_id}")
def task_detail(task_id: str):
    """任务详情。"""
    try:
        r = get_task_manager().get_task(task_id)
        if not r.get("success"):
            return _err(404, r.get("error", "任务不存在"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"详情加载失败：{e}")


@router.get("/tasks/{task_id}/logs")
def task_logs(task_id: str, since: int = 0, limit: int = 200):
    """实时日志流。"""
    try:
        r = get_task_manager().get_logs(task_id, since, limit)
        if not r.get("success"):
            return _err(404, r.get("error", "日志不存在"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"日志加载失败：{e}")


@router.post("/tasks/{task_id}/tick")
def task_tick(task_id: str):
    """手动推进一个阶段（前端轮询模拟实时）。"""
    try:
        r = get_task_manager().tick(task_id)
        if not r.get("success"):
            return _err(400, r.get("error", "推进失败"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"推进失败：{e}")


@router.post("/tasks/{task_id}/cancel")
def task_cancel(task_id: str):
    """取消任务。"""
    try:
        r = get_task_manager().cancel(task_id)
        if not r.get("success"):
            return _err(400, r.get("error", "取消失败"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"取消失败：{e}")


@router.delete("/tasks/{task_id}")
def task_delete(task_id: str):
    """删除任务。"""
    try:
        r = get_task_manager().delete_task(task_id)
        if not r.get("success"):
            return _err(404, r.get("error", "删除失败"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"删除失败：{e}")


@router.get("/tasks/{task_id}/report")
def task_report(task_id: str):
    """获取任务报告。"""
    try:
        r = get_task_manager().get_report(task_id)
        if not r.get("success"):
            return _err(404, r.get("error", "报告不存在"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"报告加载失败：{e}")


@router.get("/tasks/{task_id}/detail")
def task_full_detail(task_id: str):
    """聚合：详情 + 日志 + 报告预览。"""
    try:
        r = get_dashboard().task_detail(task_id)
        if not r.get("success"):
            return _err(404, r.get("error", "详情不存在"))
        return _ok(r["data"])
    except Exception as e:  # noqa: BLE001
        return _err(500, f"详情聚合失败：{e}")


# ----------------------------------------------------------------------
# 新手引导
# ----------------------------------------------------------------------
@router.get("/onboarding/steps")
def onboarding_steps():
    """三步引导内容。"""
    try:
        return _ok(get_onboarding_guide().get_steps().get("data"))
    except Exception as e:  # noqa: BLE001
        return _err(500, f"引导步骤加载失败：{e}")


@router.get("/onboarding/state")
def onboarding_state(session_id: str = Query("default")):
    """当前引导状态。"""
    try:
        g = get_onboarding_guide()
        return _ok({"state": g.get_state(session_id),
                    "should_start": g.should_start(session_id)})
    except Exception as e:  # noqa: BLE001
        return _err(500, f"引导状态加载失败：{e}")


@router.post("/onboarding/advance")
def onboarding_advance(session_id: str = Query("default")):
    """推进到下一步。"""
    try:
        r = get_onboarding_guide().advance(session_id)
        return _ok(r.get("data"))
    except Exception as e:  # noqa: BLE001
        return _err(500, f"引导推进失败：{e}")


@router.post("/onboarding/reset")
def onboarding_reset(session_id: str = Query("default")):
    """重置引导（重新播放）。"""
    try:
        r = get_onboarding_guide().reset(session_id)
        return _ok(r.get("data"))
    except Exception as e:  # noqa: BLE001
        return _err(500, f"引导重置失败：{e}")


@router.post("/onboarding/finish")
def onboarding_finish(session_id: str = Query("default")):
    """手动完成引导。"""
    try:
        r = get_onboarding_guide().finish(session_id)
        return _ok(r.get("data"))
    except Exception as e:  # noqa: BLE001
        return _err(500, f"引导完成失败：{e}")
