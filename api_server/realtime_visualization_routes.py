# -*- coding: utf-8 -*-
"""
realtime_visualization_routes.py — WebSocket 实时可视化 REST API + WebSocket（24 端点）。

路由前缀: /api/v1/realtime-visualization
WebSocket: /ws/realtime/{task_id}
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/realtime-visualization",
                   tags=["实时可视化"])

# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from realtime_visualization import (
        manager, tracker, streamer, pusher, dashboard, LEVEL_COLORS,
    )
    _MOD_AVAILABLE = True
    logger.info("realtime_visualization_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("realtime_visualization_routes: load failed: %s", e)
    manager = tracker = streamer = pusher = dashboard = None  # type: ignore
    LEVEL_COLORS = {}  # type: ignore


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": message},
                        status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("实时可视化模块未加载", 503)
    return None


# =========================================================================== #
# WebSocket 端点
# =========================================================================== #
@router.websocket("/ws/realtime/{task_id}")
async def ws_realtime(websocket: WebSocket, task_id: str):
    """实时推送通道：连接后持续收到步骤/进度/日志/发现/AI思考事件。"""
    conn_id = "conn_" + uuid.uuid4().hex[:8]
    channel = f"task:{task_id}"
    await manager.connect(websocket, channel, conn_id)
    try:
        await websocket.send_json({
            "type": "connected", "task_id": task_id,
            "conn_id": conn_id, "ts": __import__("time").time(),
            "data": {"msg": "WebSocket 已连接，开始接收实时推送"},
        })
        # 先推一次当前快照
        snap = tracker.snapshot(task_id)
        if snap:
            await websocket.send_json({
                "type": "snapshot", "task_id": task_id,
                "ts": __import__("time").time(), "data": snap,
            })
        while True:
            # 保持连接；客户端消息仅做心跳
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(channel, conn_id)
    except Exception:
        manager.disconnect(channel, conn_id)


# =========================================================================== #
# 1. 实时演示任务
# =========================================================================== #
@router.post("/demo/start")
async def demo_start(target: str = Body("https://target.example.com", embed=True)):
    """启动一个实时演示任务（自动产生步骤/进度/日志/发现）。"""
    g = _guard()
    if g:
        return g
    info = await pusher.start_demo(target)
    return ok(info)


@router.post("/demo/{task_id}/stop")
def demo_stop(task_id: str):
    g = _guard()
    if g:
        return g
    pusher.stop_demo(task_id)
    return ok({"task_id": task_id, "stopped": True})


@router.get("/tasks")
def list_tasks():
    g = _guard()
    if g:
        return g
    return ok(dashboard.tasks_list())


@router.get("/tasks/{task_id}")
def task_snapshot(task_id: str):
    g = _guard()
    if g:
        return g
    d = dashboard.task_snapshot(task_id)
    if not d:
        return fail("task not found", 404)
    return ok(d)


@router.get("/tasks/{task_id}/progress")
def task_progress(task_id: str):
    g = _guard()
    if g:
        return g
    d = tracker.snapshot(task_id)
    if not d:
        return fail("task not found", 404)
    return ok(d)


# =========================================================================== #
# 2. 进度跟踪
# =========================================================================== #
@router.post("/progress/create")
def progress_create(
    target: str = Body(..., embed=True),
    steps: List[Dict[str, str]] = Body(default_factory=list, embed=True),
):
    g = _guard()
    if g:
        return g
    tp = tracker.create_task(target, steps=steps)
    return ok(tp.to_dict())


@router.post("/progress/{task_id}/step/{step_id}/start")
def step_start(task_id: str, step_id: str):
    g = _guard()
    if g:
        return g
    tracker.start_step(task_id, step_id)
    return ok({"task_id": task_id, "step_id": step_id, "status": "running"})


@router.post("/progress/{task_id}/step/{step_id}/update")
def step_update(task_id: str, step_id: str,
                progress: float = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    tracker.update_step(task_id, step_id, progress)
    return ok(tracker.snapshot(task_id))


@router.post("/progress/{task_id}/step/{step_id}/finish")
def step_finish(task_id: str, step_id: str,
                status: str = Body("done", embed=True)):
    g = _guard()
    if g:
        return g
    tracker.finish_step(task_id, step_id, status=status)
    return ok(tracker.snapshot(task_id))


# =========================================================================== #
# 3. 日志流
# =========================================================================== #
@router.post("/logs")
def write_log(
    task_id: str = Body(..., embed=True),
    level: str = Body("info", embed=True),
    message: str = Body(..., embed=True),
    source: str = Body("", embed=True),
):
    """写一条日志。"""
    g = _guard()
    if g:
        return g
    e = streamer.log(task_id, level, message, source)
    return ok(e.to_dict())


@router.get("/logs/{task_id}")
def read_logs(task_id: str, limit: int = Query(200, ge=1, le=1000),
              level: str = Query("")):
    g = _guard()
    if g:
        return g
    return ok(streamer.tail(task_id, limit=limit, level=level))


@router.get("/logs/colors")
def log_colors():
    g = _guard()
    if g:
        return g
    return ok(LEVEL_COLORS)


@router.post("/logs/{task_id}/pause")
def logs_pause(task_id: str):
    g = _guard()
    if g:
        return g
    streamer.set_paused(task_id, True)
    return ok({"task_id": task_id, "paused": True})


@router.post("/logs/{task_id}/resume")
def logs_resume(task_id: str):
    g = _guard()
    if g:
        return g
    streamer.set_paused(task_id, False)
    return ok({"task_id": task_id, "paused": False})


@router.post("/logs/{task_id}/clear")
def logs_clear(task_id: str):
    g = _guard()
    if g:
        return g
    n = streamer.clear(task_id)
    return ok({"task_id": task_id, "cleared": n})


# =========================================================================== #
# 4. 实时推送（手动触发）
# =========================================================================== #
@router.post("/push/event")
async def push_event(task_id: str = Body(..., embed=True),
                     event_type: str = Body("event", embed=True),
                     payload: Dict[str, Any] = Body(default_factory=dict,
                                                    embed=True)):
    g = _guard()
    if g:
        return g
    await pusher.push_event(task_id, event_type, payload)
    return ok({"task_id": task_id, "pushed": event_type})


@router.post("/push/finding")
async def push_finding(task_id: str = Body(..., embed=True),
                       finding: Dict[str, Any] = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    await pusher.push_finding(task_id, finding)
    return ok({"task_id": task_id, "pushed": "finding"})


@router.post("/push/thinking")
async def push_thinking(task_id: str = Body(..., embed=True),
                        thought: Dict[str, Any] = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    await pusher.push_thinking(task_id, thought)
    return ok({"task_id": task_id, "pushed": "thinking"})


# =========================================================================== #
# 5. 仪表盘 / 系统
# =========================================================================== #
@router.get("/ws/stats")
def ws_stats():
    g = _guard()
    if g:
        return g
    return ok(manager.stats())


@router.get("/dashboard/overview")
def dash_overview():
    g = _guard()
    if g:
        return g
    return ok(dashboard.overview())


@router.get("/dashboard/{task_id}")
def dash_task(task_id: str):
    g = _guard()
    if g:
        return g
    d = dashboard.task_snapshot(task_id)
    if not d:
        return fail("task not found", 404)
    return ok(d)


@router.get("/stats")
def stats():
    g = _guard()
    if g:
        return g
    return ok({
        "websocket": manager.stats(),
        "progress": tracker.stats(),
        "logs": streamer.stats(),
        "pusher": pusher.stats(),
    })
