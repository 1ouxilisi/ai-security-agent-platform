# -*- coding: utf-8 -*-
"""
ctf_pro_routes.py — 方向1：CTF Pro REST API（50+ 端点 + WebSocket）。

路由前缀: /api/v1/ctf-pro
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ctf-pro",
                   tags=["CTFPro-方向1"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from ctf_pro import (
        get_orchestrator, get_dashboard, get_realtime_push,
        get_competition_phase, get_challenge_phase, get_deployment_phase,
        get_gameplay_phase, get_ranking_phase, get_postmortem_phase,
        get_training_phase, get_team_phase, get_ai_analysis,
        get_report_generator, STAGES, REPORTS_DIR, CHALLENGE_CATEGORIES,
        DIFFICULTIES,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _RT = get_realtime_push()
    _COMP = get_competition_phase()
    _CHAL = get_challenge_phase()
    _DEP = get_deployment_phase()
    _GP = get_gameplay_phase()
    _RANK = get_ranking_phase()
    _PM = get_postmortem_phase()
    _TRAIN = get_training_phase()
    _TEAM = get_team_phase()
    _AI = get_ai_analysis()
    _REP = get_report_generator()
    _MOD_AVAILABLE = True
    logger.info("ctf_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("ctf_pro_routes: load failed: %s", e)
    _ORCH = _DASH = _RT = None  # type: ignore
    _COMP = _CHAL = _DEP = None  # type: ignore
    _GP = _RANK = _PM = _TRAIN = _TEAM = None  # type: ignore
    _AI = _REP = None  # type: ignore


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c == "\n" or c == "\t"
                       or ord(c) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data),
                         "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE or _ORCH is None:
        return fail("CTF Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 任务管理（八阶段一键全流程）
# =========================================================================== #
@router.post("/start")
def start_ctf(name: str = Body("CTF 八阶段全流程", embed=True)):
    g = _guard()
    if g:
        return g
    t = _ORCH.create_task(name)
    threading.Thread(target=_ORCH.run_full,
                     args=(t.task_id,), daemon=True).start()
    return ok({"task_id": t.task_id, "name": name,
               "status": t.status, "stage": t.stage,
               "progress": t.progress})


@router.get("/tasks")
def list_tasks():
    g = _guard()
    if g:
        return g
    return ok({"tasks": _ORCH.list_tasks()})


@router.get("/task/{task_id}")
def task_detail(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.to_dict())


@router.get("/stages")
def stages():
    g = _guard()
    if g:
        return g
    return ok({"stages": [
        {"key": k, "label": lbl, "progress": p} for k, lbl, p in STAGES]})


# =========================================================================== #
# 1. 赛事管理
# =========================================================================== #
@router.post("/competitions")
def create_competition(payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        c = _COMP.create_competition(**payload)
        return ok(c)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/competitions")
def list_competitions():
    g = _guard()
    if g:
        return g
    return ok({"competitions": _COMP.list_competitions()})


@router.get("/competitions/{comp_id}")
def get_competition(comp_id: str):
    g = _guard()
    if g:
        return g
    c = _COMP.get_competition(comp_id)
    if c is None:
        return fail("赛事不存在", 404)
    return ok(c.to_dict())


@router.put("/competitions/{comp_id}/config")
def update_competition_config(comp_id: str,
                              config: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_COMP.update_config(comp_id, config))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/competitions/{comp_id}/status")
def change_comp_status(comp_id: str,
                       status: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_COMP.change_status(comp_id, status))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/competitions/{comp_id}/announcements")
def add_announcement(comp_id: str,
                     title: str = Body(...),
                     content: str = Body(...),
                     level: str = Body("info")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_COMP.add_announcement(comp_id, title, content, level))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/competitions/{comp_id}/announcements")
def list_announcements(comp_id: str):
    g = _guard()
    if g:
        return g
    return ok({"announcements": _COMP.list_announcements(comp_id)})


@router.post("/competitions/{comp_id}/register")
def register(comp_id: str,
             payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_COMP.register(comp_id, **payload))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/registrations/{reg_id}/review")
def review_registration(reg_id: str,
                        approve: bool = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_COMP.review_registration(reg_id, approve))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/competitions/{comp_id}/reg-stats")
def reg_stats(comp_id: str):
    g = _guard()
    if g:
        return g
    return ok(_COMP.registration_stats(comp_id))


@router.get("/templates")
def list_templates():
    g = _guard()
    if g:
        return g
    return ok({"templates": _COMP.list_templates()})


@router.get("/competitions/stats")
def competition_stats():
    g = _guard()
    if g:
        return g
    return ok(_COMP.stats())


# =========================================================================== #
# 2. 题目管理
# =========================================================================== #
@router.post("/challenges")
def create_challenge(payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_CHAL.create_challenge(**payload))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/challenges")
def list_challenges(category: str = "", difficulty: str = "",
                    status: str = "", competition_id: str = "",
                    include_flag: bool = False):
    g = _guard()
    if g:
        return g
    rows = _CHAL.list_challenges(category, difficulty, status,
                                 competition_id, include_flag)
    return ok({"challenges": rows, "total": len(rows)})


@router.get("/challenges/{chal_id}")
def get_challenge(chal_id: str, include_flag: bool = False):
    g = _guard()
    if g:
        return g
    c = _CHAL.get_challenge(chal_id, include_flag)
    if c is None:
        return fail("题目不存在", 404)
    return ok(c)


@router.put("/challenges/{chal_id}")
def update_challenge(chal_id: str,
                     patch: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_CHAL.update_challenge(chal_id, patch))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/challenges/{chal_id}/status")
def change_chal_status(chal_id: str,
                       status: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_CHAL.change_status(chal_id, status))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/challenges/{chal_id}/attachments")
def add_attachment(chal_id: str,
                   name: str = Body(...), url: str = Body(...),
                   size: int = Body(0), kind: str = Body("")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_CHAL.add_attachment(chal_id, name, url, size, kind))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/challenges/{chal_id}/hints")
def add_hint(chal_id: str,
             content: str = Body(...), cost: int = Body(0)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_CHAL.add_hint(chal_id, content, cost))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/challenges-taxonomy")
def challenge_taxonomy():
    g = _guard()
    if g:
        return g
    return ok(_CHAL.taxonomy())


@router.get("/challenges/stats")
def challenge_stats():
    g = _guard()
    if g:
        return g
    return ok(_CHAL.stats())


# =========================================================================== #
# 3. 题目部署（Docker）
# =========================================================================== #
@router.get("/deploy/docker-status")
def docker_status():
    g = _guard()
    if g:
        return g
    return ok(_DEP.docker_status())


@router.get("/deploy/templates")
def deploy_templates():
    g = _guard()
    if g:
        return g
    return ok({"templates": _DEP.list_templates()})


@router.post("/deploy")
def deploy_challenge(payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_DEP.deploy(**payload))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/deploy/{deploy_id}/{action}")
def deploy_lifecycle(deploy_id: str, action: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(_DEP.lifecycle(deploy_id, action))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/deploy/{deploy_id}/logs")
def deploy_logs(deploy_id: str, tail: int = 100):
    g = _guard()
    if g:
        return g
    try:
        return ok(_DEP.view_logs(deploy_id, tail))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/deploy")
def list_deployments(chal_id: str = "", team_id: str = ""):
    g = _guard()
    if g:
        return g
    return ok({"deployments": _DEP.list_deployments(chal_id, team_id)})


@router.get("/deploy/stats")
def deploy_stats():
    g = _guard()
    if g:
        return g
    return ok(_DEP.stats())


# =========================================================================== #
# 4. 比赛进行
# =========================================================================== #
@router.post("/submit")
def submit_flag(chal_id: str = Body(...),
                team_id: str = Body(...),
                flag: str = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        sub = _GP.submit(chal_id, team_id, flag)
        _RT.emit_submission("ctf-live", sub)
        return ok(sub)
    except PermissionError as e:
        return fail(str(e), 429)
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/answers/register")
def register_answer(chal_id: str = Body(...),
                    correct_flags: list = Body(...),
                    base_score: int = Body(200)):
    g = _guard()
    if g:
        return g
    _GP.register_answer(chal_id, correct_flags, base_score)
    return ok({"registered": chal_id, "flags": len(correct_flags)})


@router.get("/submissions")
def list_submissions(chal_id: str = "", team_id: str = "",
                     correct_only: bool = False, limit: int = 100):
    g = _guard()
    if g:
        return g
    return ok({"submissions": _GP.list_submissions(
        chal_id, team_id, correct_only, limit)})


@router.get("/challenges/{chal_id}/solve-status")
def solve_status(chal_id: str):
    g = _guard()
    if g:
        return g
    return ok(_GP.solve_status(chal_id))


@router.post("/discussions")
def add_discussion(chal_id: str = Body(...),
                   author: str = Body(...),
                   content: str = Body(...),
                   kind: str = Body("discussion")):
    g = _guard()
    if g:
        return g
    return ok(_GP.add_discussion(chal_id, author, content, kind))


@router.get("/discussions")
def list_discussions(chal_id: str = ""):
    g = _guard()
    if g:
        return g
    return ok({"discussions": _GP.list_discussions(chal_id)})


@router.get("/events")
def event_stream(limit: int = 100):
    g = _guard()
    if g:
        return g
    return ok({"events": _GP.event_stream(limit)})


@router.get("/gameplay/stats")
def gameplay_stats():
    g = _guard()
    if g:
        return g
    return ok(_GP.stats())


# =========================================================================== #
# 5. 实时排名
# =========================================================================== #
@router.post("/ranking/rebuild")
def rebuild_ranking():
    g = _guard()
    if g:
        return g
    lb = _RANK.rebuild()
    _RT.emit_ranking("ctf-live", lb)
    return ok({"leaderboard": lb})


@router.get("/ranking/leaderboard")
def leaderboard():
    g = _guard()
    if g:
        return g
    return ok({"leaderboard": _RANK.leaderboard()})


@router.get("/ranking/blood-board")
def blood_board(blood: str = "first"):
    g = _guard()
    if g:
        return g
    return ok({"blood": blood, "rows": _RANK.blood_board(blood)})


@router.get("/ranking/progress")
def solve_progress(total: int = 0):
    g = _guard()
    if g:
        return g
    return ok(_RANK.solve_progress(total))


@router.post("/ranking/snapshot")
def rank_snapshot():
    g = _guard()
    if g:
        return g
    return ok(_RANK.rank_history_snapshot())


@router.get("/ranking/stats")
def ranking_stats():
    g = _guard()
    if g:
        return g
    return ok(_RANK.stats())


# =========================================================================== #
# 6. 比赛复盘
# =========================================================================== #
@router.post("/writeups")
def submit_writeup(chal_id: str = Body(...), author: str = Body(...),
                   title: str = Body(...), content: str = Body(...),
                   kind: str = Body("player")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_PM.submit_writeup(chal_id, author, title,
                                     content, kind))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/writeups")
def list_writeups(chal_id: str = "", kind: str = ""):
    g = _guard()
    if g:
        return g
    return ok({"writeups": _PM.list_writeups(chal_id, kind)})


@router.post("/writeups/{wid}/rate")
def rate_writeup(wid: str, rating: int = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_PM.rate_writeup(wid, rating))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/postmortem/solve-stats")
def solve_stats():
    g = _guard()
    if g:
        return g
    return ok({"stats": _PM.solve_statistics()})


@router.get("/postmortem/knowledge")
def knowledge_coverage():
    g = _guard()
    if g:
        return g
    return ok({"coverage": _PM.knowledge_coverage()})


@router.get("/postmortem/export")
def export_data():
    g = _guard()
    if g:
        return g
    return ok(_PM.export_data())


@router.post("/postmortem/generate")
def generate_postmortem(title: str = Body("比赛复盘", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_PM.generate_postmortem(title))


# =========================================================================== #
# 7. 训练模式
# =========================================================================== #
@router.post("/training/start")
def start_training(user: str = Body(...), mode: str = Body("free"),
                   ref: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_TRAIN.start_training(user, mode, ref))


@router.post("/training/{rec_id}/finish")
def finish_training(rec_id: str, solved: bool = Body(...),
                    score: int = Body(0), category: str = Body("")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_TRAIN.finish_training(rec_id, solved, score, category))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/training/records")
def training_records(user: str = ""):
    g = _guard()
    if g:
        return g
    return ok({"records": _TRAIN.list_records(user)})


@router.get("/training/paths")
def learning_paths():
    g = _guard()
    if g:
        return g
    return ok({"paths": _TRAIN.learning_paths()})


@router.get("/training/ability")
def ability_assessment(user: str = Query(...)):
    g = _guard()
    if g:
        return g
    return ok(_TRAIN.ability_assessment(user))


@router.post("/training/goals")
def set_goal(user: str = Body(...), goal: str = Body(...),
             target: str = Body(...), deadline: str = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_TRAIN.set_goal(user, goal, target, deadline))


@router.get("/training/goals")
def list_goals(user: str = ""):
    g = _guard()
    if g:
        return g
    return ok({"goals": _TRAIN.list_goals(user)})


@router.get("/training/stats")
def training_stats(user: str = ""):
    g = _guard()
    if g:
        return g
    return ok(_TRAIN.stats(user))


# =========================================================================== #
# 8. 战队管理
# =========================================================================== #
@router.post("/teams")
def create_team(name: str = Body(...), captain: str = Body(...),
                logo: str = Body(""), description: str = Body(""),
                manifesto: str = Body("")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_TEAM.create_team(name, captain, logo,
                                   description, manifesto))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/teams")
def list_teams():
    g = _guard()
    if g:
        return g
    return ok({"teams": _TEAM.list_teams()})


@router.get("/teams/{team_id}")
def get_team(team_id: str):
    g = _guard()
    if g:
        return g
    t = _TEAM.get_team(team_id)
    if t is None:
        return fail("战队不存在", 404)
    return ok(t.to_dict())


@router.post("/teams/{team_id}/members")
def add_member(team_id: str, uid: str = Body(...),
               name: str = Body(...), role: str = Body("member"),
               permission: str = Body("view")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_TEAM.add_member(team_id, uid, name, role,
                                   permission))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.delete("/teams/{team_id}/members/{uid}")
def remove_member(team_id: str, uid: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(_TEAM.remove_member(team_id, uid))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/teams/{team_id}/apply")
def apply_join(team_id: str, uid: str = Body(...), name: str = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_TEAM.apply_join(team_id, uid, name))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/teams/{team_id}/apply/{uid}/review")
def review_application(team_id: str, uid: str,
                       approve: bool = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_TEAM.review_application(team_id, uid, approve))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/teams/{team_id}/training-plan")
def set_training_plan(team_id: str, plan_type: str = Body(...),
                      schedule: str = Body(...), focus: str = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_TEAM.set_training_plan(team_id, plan_type,
                                         schedule, focus))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/teams/{team_id}/match")
def record_match(team_id: str, comp_name: str = Body(...),
                 rank: int = Body(1), score: int = Body(0),
                 solved: int = Body(0)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_TEAM.record_match(team_id, comp_name, rank,
                                     score, solved))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.post("/teams/{team_id}/announcements")
def team_announcement(team_id: str, title: str = Body(...),
                      content: str = Body(...)):
    g = _guard()
    if g:
        return g
    try:
        return ok(_TEAM.add_announcement(team_id, title, content))
    except Exception as e:  # noqa: BLE001
        return fail(str(e))


@router.get("/teams/ranking")
def team_ranking():
    g = _guard()
    if g:
        return g
    return ok({"ranking": _TEAM.ranking()})


@router.get("/teams/stats")
def team_stats():
    g = _guard()
    if g:
        return g
    return ok(_TEAM.stats())


# =========================================================================== #
# AI 分析
# =========================================================================== #
@router.post("/ai/analyze-difficulty")
def ai_analyze_difficulty(payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_AI.analyze_difficulty(**payload))


@router.get("/ai/solve-hint")
def ai_solve_hint(category: str = Query(...), subcategory: str = ""):
    g = _guard()
    if g:
        return g
    return ok(_AI.solve_hint(category, subcategory))


@router.post("/ai/recommend-path")
def ai_recommend_path(ability: Dict[str, float] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_AI.recommend_path(ability))


@router.post("/ai/generate-challenge")
def ai_generate_challenge(category: str = Body("Web"),
                          difficulty: str = Body("简单")):
    g = _guard()
    if g:
        return g
    return ok(_AI.auto_generate_challenge(category, difficulty))


@router.post("/ai/postmortem")
def ai_postmortem(stats: list = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_AI.postmortem_analysis(stats))


@router.get("/ai/team-advice")
def ai_team_advice():
    g = _guard()
    if g:
        return g
    return ok({"advice": _AI.team_training_advice({})})


@router.get("/ai/history")
def ai_history(limit: int = 50):
    g = _guard()
    if g:
        return g
    return ok({"history": _AI.history(limit)})


# =========================================================================== #
# 仪表盘
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    g = _guard()
    if g:
        return g
    return ok(_DASH.kpi())


@router.get("/dashboard/full")
def dash_full():
    g = _guard()
    if g:
        return g
    return ok(_DASH.full_screen())


@router.get("/dashboard/top-teams")
def dash_top_teams(n: int = 10):
    g = _guard()
    if g:
        return g
    return ok({"teams": _DASH.top_teams(n)})


@router.get("/dashboard/trend")
def dash_trend(points: int = 12):
    g = _guard()
    if g:
        return g
    return ok({"series": _DASH.submission_trend(points)})


@router.get("/dashboard/events")
def dash_events(limit: int = 15):
    g = _guard()
    if g:
        return g
    return ok({"events": _DASH.recent_events(limit)})


# =========================================================================== #
# 报告
# =========================================================================== #
@router.post("/report/generate")
def generate_report(fmt: str = Body("both", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_REP.generate(fmt))


@router.get("/report/latest")
def latest_report():
    g = _guard()
    if g:
        return g
    import glob
    files = sorted(glob.glob(os.path.join(REPORTS_DIR, "*.md")),
                   key=os.path.getmtime, reverse=True)
    if not files:
        return fail("暂无报告", 404)
    with open(files[0], "r", encoding="utf-8") as f:
        md = f.read()
    return ok({"path": files[0], "markdown": md})


# =========================================================================== #
# 元数据
# =========================================================================== #
@router.get("/meta/categories")
def meta_categories():
    g = _guard()
    if g:
        return g
    return ok({"categories": CHALLENGE_CATEGORIES,
               "difficulties": DIFFICULTIES})


# =========================================================================== #
# WebSocket 实时推送
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_endpoint(websocket: WebSocket, task_id: str):
    """实时推送进度/日志/思考/提交/排名/结果。"""
    await websocket.accept()
    if not _MOD_AVAILABLE:
        await websocket.send_json({"type": "error",
                                   "message": "模块未加载"})
        await websocket.close()
        return
    _RT.subscribe(task_id, websocket)
    for ev in _RT.history(task_id):
        try:
            await websocket.send_json(ev)
        except Exception:
            break
    try:
        sent_index = len(_RT.history(task_id))
        while True:
            hist = _RT.history(task_id)
            if len(hist) > sent_index:
                for ev in hist[sent_index:]:
                    await websocket.send_json(ev)
                sent_index = len(hist)
            await websocket.send_json({"type": "ping",
                                       "ts": time.time()})
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _RT.unsubscribe(task_id, websocket)
