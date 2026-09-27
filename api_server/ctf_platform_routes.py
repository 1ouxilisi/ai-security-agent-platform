# -*- coding: utf-8 -*-
"""
ctf_platform_routes.py — CTF 训练平台 REST API（36 个端点）。

路由前缀: /api/v1/ctf-platform
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

设计定位：CTF 安全训练与教育管理平台，不提供任何真实攻击能力。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ctf-platform", tags=["CTF训练平台"])


# --------------------------------------------------------------------------- #
# 核心模块 try-import（失败时回退内存模拟，路由仍可用）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from api_server.ctf_platform.challenge_manager import get_challenge_manager, CATEGORIES, DIFFICULTIES
    from api_server.ctf_platform.competition_manager import get_competition_manager, FORMATS
    from api_server.ctf_platform.challenge_solver import get_challenge_solver
    from api_server.ctf_platform.learning_path import get_learning_manager, LEVELS
    from api_server.ctf_platform.team_manager import get_team_manager, ROLES
    from api_server.ctf_platform.ctf_dashboard import get_dashboard
    _MOD_AVAILABLE = True
    logger.info("ctf_platform_routes: modules loaded OK (api_server.ctf_platform)")
except Exception:
    try:
        from ctf_platform.challenge_manager import get_challenge_manager, CATEGORIES, DIFFICULTIES
        from ctf_platform.competition_manager import get_competition_manager, FORMATS
        from ctf_platform.challenge_solver import get_challenge_solver
        from ctf_platform.learning_path import get_learning_manager, LEVELS
        from ctf_platform.team_manager import get_team_manager, ROLES
        from ctf_platform.ctf_dashboard import get_dashboard
        _MOD_AVAILABLE = True
        logger.info("ctf_platform_routes: modules loaded OK (ctf_platform)")
    except Exception as e:  # pragma: no cover
        logger.exception("ctf_platform_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    _TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in _TASKS:
        t = _TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应（_clean 递归清理控制字符）
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("CTF 模块加载失败，请检查日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ChallengeCreate(BaseModel):
    title: str = ""
    category: str = "Misc"
    difficulty: str = "easy"
    score: int = 100
    description: str = ""
    flag: str = ""
    dynamic_flag: bool = False
    author: str = "admin"
    tags: List[str] = Field(default_factory=list)
    hints: List[Dict[str, Any]] = Field(default_factory=list)


class ChallengeUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    score: Optional[int] = None
    tags: Optional[List[str]] = None
    hints: Optional[List[Dict[str, Any]]] = None
    note: str = ""


class ReviewRequest(BaseModel):
    reviewer: str = "admin"
    opinion: str = ""
    action: str = "approve"


class FlagSubmit(BaseModel):
    user: str = "anonymous"
    challenge_id: str = ""
    flag: str = ""
    client_ip: str = ""


class ContainerStart(BaseModel):
    user: str = "anonymous"


class HintRequest(BaseModel):
    user: str = "anonymous"
    order: int = 1


class EventCreate(BaseModel):
    name: str = ""
    description: str = ""
    format: str = "jeopardy"
    start_time: str = ""
    end_time: str = ""
    organizer: str = "admin"
    public: bool = True


class RegistrationReq(BaseModel):
    team: str = ""
    members: List[str] = Field(default_factory=list)
    contact: str = ""


class WriteupReq(BaseModel):
    challenge_id: str = ""
    author: str = "anonymous"
    title: str = ""
    content: str = ""
    tags: List[str] = Field(default_factory=list)


class DiscussionReq(BaseModel):
    author: str = "anonymous"
    content: str = ""


class PathEnroll(BaseModel):
    user: str = "anonymous"
    course_id: str = ""


class TeamCreate(BaseModel):
    name: str = ""
    description: str = ""
    leader: str = "admin"
    public: bool = True
    tags: List[str] = Field(default_factory=list)


# =========================================================================== #
# 1. 题目与靶场管理（10 个端点）
# =========================================================================== #
@router.get("/challenges")
def list_challenges(category: Optional[str] = Query(default=None),
                    difficulty: Optional[str] = Query(default=None),
                    status: Optional[str] = Query(default=None),
                    keyword: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_challenge_manager().list_challenges(category, difficulty,
                                                          status, keyword))
    except Exception as e:
        logger.exception("list_challenges error")
        return fail(f"查询失败: {e}", 500)


@router.get("/challenges/{cid}")
def get_challenge(cid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ch = get_challenge_manager().get_challenge(cid)
        if not ch:
            return fail("题目不存在", 404)
        # 不向前端泄露正确 flag
        safe = {k: v for k, v in ch.items() if k not in ("flag",)}
        safe["has_flag"] = bool(ch.get("flag"))
        return ok(safe)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/challenges")
def create_challenge(req: ChallengeCreate):
    try:
        g = _guard()
        if g is not None:
            return g
        ch = get_challenge_manager().create_challenge(req.model_dump())
        return ok(ch)
    except Exception as e:
        logger.exception("create_challenge error")
        return fail(f"创建失败: {e}", 500)


@router.put("/challenges/{cid}")
def update_challenge(cid: str, req: ChallengeUpdate):
    try:
        g = _guard()
        if g is not None:
            return g
        ch = get_challenge_manager().update_challenge(cid, req.model_dump())
        if not ch:
            return fail("题目不存在", 404)
        return ok(ch)
    except Exception as e:
        return fail(f"更新失败: {e}", 500)


@router.delete("/challenges/{cid}")
def delete_challenge(cid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        if not get_challenge_manager().delete_challenge(cid):
            return fail("题目不存在", 404)
        return ok({"deleted": cid})
    except Exception as e:
        return fail(f"删除失败: {e}", 500)


@router.post("/challenges/{cid}/review")
def review_challenge(cid: str, req: ReviewRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        rec = get_challenge_manager().submit_review(cid, req.reviewer,
                                                    req.opinion, req.action)
        if not rec:
            return fail("题目不存在", 404)
        return ok(rec)
    except Exception as e:
        return fail(f"审核失败: {e}", 500)


@router.get("/challenges/{cid}/versions")
def challenge_versions(cid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"challenge_id": cid,
                   "versions": get_challenge_manager().list_versions(cid)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/challenges/{cid}/container/start")
def start_container(cid: str, req: ContainerStart):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("container_start")
        c = get_challenge_manager().start_container(cid, req.user)
        _finish_task(task_id, c)
        return ok({"task_id": task_id, "container": c})
    except Exception as e:
        return fail(f"启动失败: {e}", 500)


@router.post("/containers/{cid}/stop")
def stop_container(cid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_ = get_challenge_manager().stop_container(cid)
        return ok({"stopped": bool(ok_)})
    except Exception as e:
        return fail(f"停止失败: {e}", 500)


@router.get("/containers")
def list_containers(user: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"containers": get_challenge_manager().list_containers(user)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 2. 竞赛与赛事管理（8 个端点）
# =========================================================================== #
@router.get("/events")
def list_events(status: Optional[str] = Query(default=None),
                format: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_competition_manager().list_events(status, format))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/events/{eid}")
def get_event(eid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ev = get_competition_manager().get_event(eid)
        if not ev:
            return fail("赛事不存在", 404)
        return ok(ev)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/events")
def create_event(req: EventCreate):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_competition_manager().create_event(req.model_dump()))
    except Exception as e:
        return fail(f"创建失败: {e}", 500)


@router.post("/events/{eid}/register")
def register_event(eid: str, req: RegistrationReq):
    try:
        g = _guard()
        if g is not None:
            return g
        rec = get_competition_manager().register(eid, req.team,
                                                 req.members, req.contact)
        return ok(rec)
    except Exception as e:
        return fail(f"报名失败: {e}", 500)


@router.get("/events/{eid}/registrations")
def list_registrations(eid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_competition_manager().list_registrations(eid))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/events/{eid}/leaderboard")
def event_leaderboard(eid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_competition_manager().leaderboard(eid))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/events/{eid}/monitor")
def event_monitor(eid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_competition_manager().monitor(eid))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/events/{eid}/postmortem")
def event_postmortem(eid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_competition_manager().postmortem(eid))
    except Exception as e:
        return fail(f"复盘失败: {e}", 500)


# =========================================================================== #
# 3. 解题与 Flag 验证（7 个端点）
# =========================================================================== #
@router.post("/flag/submit")
def submit_flag(req: FlagSubmit):
    try:
        g = _guard()
        if g is not None:
            return g
        cm = get_challenge_manager()
        ch = cm.get_challenge(req.challenge_id)
        expected = ch.get("flag", "") if ch else ""
        dynamic = cm.get_dynamic_flag(req.challenge_id, req.user) or ""
        res = get_challenge_solver().submit_flag(
            req.user, req.challenge_id, req.flag,
            expected_flag=expected, dynamic_flag=dynamic,
            client_ip=req.client_ip,
        )
        return ok(res)
    except Exception as e:
        logger.exception("submit_flag error")
        return fail(f"提交失败: {e}", 500)


@router.get("/solves/{user}")
def my_solves(user: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"user": user,
                   "solves": get_challenge_solver().my_solves(user)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/hints/unlock")
def unlock_hint(req: HintRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        # 题目 id 通过 query 不方便，这里直接用固定示例内容
        return ok(get_challenge_solver().unlock_hint(
            req.user, "chal_demo", req.order,
            hint_content="提示：先观察输入与回显。"))
    except Exception as e:
        return fail(f"解锁失败: {e}", 500)


@router.post("/writeups")
def submit_writeup(req: WriteupReq):
    try:
        g = _guard()
        if g is not None:
            return ok(get_challenge_solver().submit_writeup(req.model_dump()))
    except Exception as e:
        return fail(f"提交失败: {e}", 500)


@router.get("/writeups")
def list_writeups(challenge_id: Optional[str] = Query(default=None),
                  status: str = "published"):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"writeups": get_challenge_solver().list_writeups(challenge_id,
                                                                    status)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/discussions/{cid}")
def post_discussion(cid: str, req: DiscussionReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_challenge_solver().post_discussion(cid, req.author, req.content))
    except Exception as e:
        return fail(f"发布失败: {e}", 500)


@router.get("/cheat/alerts")
def cheat_alerts():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_challenge_solver().detect_cheat())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 4. 学习路径（5 个端点）
# =========================================================================== #
@router.get("/learning/paths")
def list_paths():
    try:
        g = _guard()
        if g is not None:
            return ok({"paths": get_learning_manager().list_paths(),
                       "levels": LEVELS})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/learning/courses")
def list_courses(category: Optional[str] = Query(default=None),
                 level: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return ok({"courses": get_learning_manager().list_courses(category, level)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/learning/enroll")
def enroll_course(req: PathEnroll):
    try:
        g = _guard()
        if g is not None:
            return ok(get_learning_manager().enroll(req.user, req.course_id))
    except Exception as e:
        return fail(f"选课失败: {e}", 500)


@router.get("/learning/skill-radar/{user}")
def skill_radar(user: str):
    try:
        g = _guard()
        if g is not None:
            return ok(get_learning_manager().skill_radar(user))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/learning/stats/{user}")
def learning_stats(user: str):
    try:
        g = _guard()
        if g is not None:
            return ok(get_learning_manager().stats(user))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 5. 战队管理（4 个端点）
# =========================================================================== #
@router.get("/teams")
def list_teams(keyword: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g is not None:
            return ok({"teams": get_team_manager().list_teams(keyword),
                       "roles": ROLES})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/teams")
def create_team(req: TeamCreate):
    try:
        g = _guard()
        if g is not None:
            return ok(get_team_manager().create_team(req.model_dump()))
    except Exception as e:
        return fail(f"创建失败: {e}", 500)


@router.get("/teams/{tid}")
def get_team(tid: str):
    try:
        g = _guard()
        if g is not None:
            t = get_team_manager().get_team(tid)
            if not t:
                return fail("战队不存在", 404)
            return ok(t)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/duels")
def duel_history():
    try:
        g = _guard()
        if g is not None:
            return ok({"duels": get_team_manager().duel_history()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 6. 运营仪表盘（4 个端点）
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    try:
        g = _guard()
        if g is not None:
            return ok(get_dashboard().overview())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/activity")
def dash_activity():
    try:
        g = _guard()
        if g is not None:
            return ok(get_dashboard().activity())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/stats")
def dash_stats():
    try:
        g = _guard()
        if g is not None:
            return ok({
                "challenges": get_dashboard().challenge_stats(),
                "users": get_dashboard().user_stats(),
                "events": get_dashboard().event_stats(),
                "metrics": get_dashboard().metrics(),
            })
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/meta")
def meta():
    """平台元信息与枚举。"""
    try:
        return ok({
            "prefix": "/api/v1/ctf-platform",
            "categories": CATEGORIES if _MOD_AVAILABLE else [],
            "difficulties": DIFFICULTIES if _MOD_AVAILABLE else [],
            "formats": FORMATS if _MOD_AVAILABLE else [],
            "module_available": _MOD_AVAILABLE,
        })
    except Exception as e:
        return fail(f"查询失败: {e}", 500)
