# -*- coding: utf-8 -*-
"""
ai_autonomous_planner_routes.py — AI 自主规划能力大升级 REST API（28 端点）。

路由前缀: /api/v1/ai-autonomous-planner
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ai-autonomous-planner",
                   tags=["AI自主规划"])

# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from ai_autonomous_planner import (
        agent, engine, decomposer, visualizer, adjuster, dashboard, PIPELINE,
    )
    _MOD_AVAILABLE = True
    logger.info("ai_autonomous_planner_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("ai_autonomous_planner_routes: load failed: %s", e)
    agent = engine = decomposer = visualizer = adjuster = dashboard = None  # type: ignore
    PIPELINE = []  # type: ignore


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": message},
                        status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("AI 自主规划模块未加载", 503)
    return None


# =========================================================================== #
# 1. 自主会话管理
# =========================================================================== #
@router.post("/start")
def start_autonomous(
    goal: str = Body(..., embed=True, description="用户目标，例如：帮我渗透这个网站"),
    target: str = Body("", embed=True, description="目标 URL/主机，可空"),
    template: str = Body("", embed=True, description="web/host/api，留空自动识别"),
    auto: bool = Body(True, embed=True, description="是否全自动后台执行"),
):
    """一键启动 AI 自主渗透（自动拆解 + 自动推进 + 自动换策略）。"""
    g = _guard()
    if g:
        return g
    if not goal.strip():
        return fail("goal 不能为空")
    info = agent.run(goal=goal.strip(), target=target.strip(),
                     template=template.strip(), auto=auto)
    return ok(info)


@router.get("/sessions")
def list_sessions():
    """所有自主规划会话列表。"""
    g = _guard()
    if g:
        return g
    return ok(dashboard.sessions_list())


@router.get("/sessions/{session_id}")
def session_detail(session_id: str):
    """会话完整详情（含思考时间线/调整记录/子任务）。"""
    g = _guard()
    if g:
        return g
    d = dashboard.session_detail(session_id)
    if not d:
        return fail("session not found", 404)
    return ok(d)


@router.get("/sessions/{session_id}/status")
def session_status(session_id: str):
    """轻量状态轮询。"""
    g = _guard()
    if g:
        return g
    d = engine.get(session_id)
    if d is None:
        return fail("session not found", 404)
    s = d.to_dict()
    return ok({
        "session_id": session_id,
        "status": s["status"],
        "stage_index": s["stage_index"],
        "progress": s["progress"],
        "step_count": s["step_count"],
        "findings_count": s["findings_count"],
    })


@router.post("/sessions/{session_id}/pause")
def pause_session(session_id: str):
    g = _guard()
    if g:
        return g
    if not engine.pause(session_id):
        return fail("session not found", 404)
    return ok({"session_id": session_id, "status": "paused"})


@router.post("/sessions/{session_id}/resume")
def resume_session(session_id: str):
    g = _guard()
    if g:
        return g
    if not engine.resume(session_id):
        return fail("session not found", 404)
    return ok({"session_id": session_id, "status": "running"})


@router.get("/sessions/{session_id}/steps")
def session_steps(session_id: str):
    g = _guard()
    if g:
        return g
    d = engine.get(session_id)
    if d is None:
        return fail("session not found", 404)
    return ok([s.to_dict() for s in d.steps])


@router.get("/sessions/{session_id}/findings")
def session_findings(session_id: str):
    g = _guard()
    if g:
        return g
    d = engine.get(session_id)
    if d is None:
        return fail("session not found", 404)
    return ok(d.findings)


@router.get("/sessions/{session_id}/events")
def session_events(session_id: str, limit: int = Query(200, ge=1, le=1000)):
    """智能体事件流（供轮询兜底；实时走 WebSocket）。"""
    g = _guard()
    if g:
        return g
    return ok(agent.events(session_id, limit=limit))


# =========================================================================== #
# 2. 任务拆解
# =========================================================================== #
@router.post("/decompose")
def decompose(
    goal: str = Body(..., embed=True),
    target: str = Body("", embed=True),
    template: str = Body("", embed=True),
):
    """把自然语言目标拆解为带依赖的子任务 DAG。"""
    g = _guard()
    if g:
        return g
    if not goal.strip():
        return fail("goal 不能为空")
    dg = decomposer.decompose(goal.strip(), target=target.strip(),
                              template=template.strip())
    return ok(dg.to_dict())


@router.get("/decompose/{goal_id}")
def decompose_result(goal_id: str):
    g = _guard()
    if g:
        return g
    dg = decomposer.get_goal(goal_id)
    if dg is None:
        return fail("goal not found", 404)
    return ok(dg.to_dict())


@router.get("/decompose/{goal_id}/subtasks")
def decompose_subtasks(goal_id: str):
    g = _guard()
    if g:
        return g
    dg = decomposer.get_goal(goal_id)
    if dg is None:
        return fail("goal not found", 404)
    return ok([s.to_dict() for s in dg.subtasks])


@router.get("/decompose/{goal_id}/next")
def decompose_next(goal_id: str):
    """返回下一个可执行的子任务。"""
    g = _guard()
    if g:
        return g
    st = decomposer.next_ready_subtask(goal_id)
    return ok(st.to_dict() if st else None)


@router.get("/templates")
def list_templates():
    """列出可用的拆解模板。"""
    g = _guard()
    if g:
        return g
    return ok(decomposer.stats()["templates"])


@router.post("/decompose/detect")
def detect_template(goal: str = Body(..., embed=True)):
    """仅做意图识别，不创建任务。"""
    g = _guard()
    if g:
        return g
    return ok({
        "template": decomposer.detect_template(goal),
        "target": decomposer.extract_target(goal),
    })


# =========================================================================== #
# 3. 思考过程可视化
# =========================================================================== #
@router.get("/thinking/sessions")
def thinking_sessions(limit: int = Query(50, ge=1, le=200)):
    g = _guard()
    if g:
        return g
    return ok(visualizer.list_sessions(limit=limit))


@router.get("/thinking/{session_id}/timeline")
def thinking_timeline(session_id: str):
    g = _guard()
    if g:
        return g
    return ok(visualizer.get_timeline(session_id))


@router.get("/thinking/{session_id}/latest")
def thinking_latest(session_id: str):
    g = _guard()
    if g:
        return g
    return ok(visualizer.latest_thought(session_id))


@router.post("/thinking/{session_id}/add")
def thinking_add(session_id: str,
                 phase: str = Body("analysis", embed=True),
                 observation: str = Body("", embed=True),
                 reasoning: str = Body("", embed=True),
                 decision: str = Body("", embed=True),
                 expectation: str = Body("", embed=True),
                 confidence: float = Body(0.7, embed=True)):
    """手动追加一条思考步骤（便于演示/回放）。"""
    g = _guard()
    if g:
        return g
    step = visualizer.add_step(
        session_id, phase=phase, observation=observation,
        reasoning=reasoning, decision=decision, expectation=expectation,
        confidence=confidence)
    if step is None:
        return fail("think session not found", 404)
    return ok(step.to_dict())


# =========================================================================== #
# 4. 动态调整（失败换策略）
# =========================================================================== #
@router.get("/adjust/strategies")
def adjust_strategies():
    """列出全部可用替代策略。"""
    g = _guard()
    if g:
        return g
    return ok(adjuster.list_strategies())


@router.get("/adjust/chain/{direction}")
def adjust_chain(direction: str):
    """查看某个方向失败后的降级链。"""
    g = _guard()
    if g:
        return g
    return ok(adjuster.get_fallback_chain(direction))


@router.post("/adjust/failure")
def adjust_failure(
    session_id: str = Body(..., embed=True),
    failed_direction: str = Body(..., embed=True),
    reason: str = Body("", embed=True),
):
    """记录一次失败并自动挑选替代策略。"""
    g = _guard()
    if g:
        return g
    ev = adjuster.record_failure(session_id, failed_direction, reason)
    return ok(ev)


@router.get("/adjust/{session_id}/events")
def adjust_events(session_id: str):
    g = _guard()
    if g:
        return g
    return ok(adjuster.get_events(session_id))


# =========================================================================== #
# 5. 仪表盘 / 系统
# =========================================================================== #
@router.get("/dashboard/overview")
def dashboard_overview():
    """全局仪表盘总览。"""
    g = _guard()
    if g:
        return g
    return ok(dashboard.overview())


@router.get("/dashboard/{session_id}")
def dashboard_session(session_id: str):
    """单会话仪表盘聚合。"""
    g = _guard()
    if g:
        return g
    d = dashboard.session_detail(session_id)
    if not d:
        return fail("session not found", 404)
    return ok(d)


@router.get("/pipeline")
def get_pipeline():
    """返回阶段流水线定义。"""
    g = _guard()
    if g:
        return g
    return ok(PIPELINE)


@router.get("/stats")
def stats():
    """模块统计。"""
    g = _guard()
    if g:
        return g
    return ok({
        "engine_sessions": len(engine.list_sessions()),
        "running": len(agent.list_running()),
        "decomposer": decomposer.stats(),
        "visualizer": visualizer.stats(),
        "adjuster": adjuster.stats(),
    })
