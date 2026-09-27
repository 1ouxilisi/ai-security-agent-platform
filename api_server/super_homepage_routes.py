# -*- coding: utf-8 -*-
"""
api_server/super_homepage_routes.py — 方向3：极致用户体验 REST API。

路由前缀: /api/v1/super-homepage
统一响应: {"success": bool, "data": ..., "error": ...}
覆盖：超级首页聚合 / 智能引导 / 全局搜索 / 快速操作 / 主题 / 导航。
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

router = APIRouter(prefix="/api/v1/super-homepage", tags=["超级首页 UX"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from super_homepage.homepage_config import (
        get_homepage_config, THEME, FEATURE_CARDS, QUICK_STATS, NAV_GROUPS, RESPONSIVE,
    )
    from super_homepage.smart_guide import get_smart_guide_manager, GUIDE_FLOW
    from super_homepage.global_search import get_global_search, SearchItem
    from super_homepage.quick_actions import get_quick_actions_manager, QUICK_ACTIONS
    from super_homepage.ux_dashboard import get_ux_dashboard, UX_LATEST_ACTIVITY
    _MOD_AVAILABLE = True
    logger.info("super_homepage_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("super_homepage_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from super_homepage.homepage_config import (  # noqa
            get_homepage_config, THEME, FEATURE_CARDS, QUICK_STATS, NAV_GROUPS, RESPONSIVE,
        )
        from super_homepage.smart_guide import get_smart_guide_manager, GUIDE_FLOW  # noqa
        from super_homepage.global_search import get_global_search, SearchItem  # noqa
        from super_homepage.quick_actions import get_quick_actions_manager, QUICK_ACTIONS  # noqa
        from super_homepage.ux_dashboard import get_ux_dashboard, UX_LATEST_ACTIVITY  # noqa
        _MOD_AVAILABLE = True
        logger.info("super_homepage_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("super_homepage_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = uuid.uuid4().hex[:16]
    TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish_task(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in TASKS:
        t = TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        chars = [c for c in obj if ord(c) >= 32 or c in ("\t", "\n", "\r")]
        s = "".join(chars)
        return s.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("超级首页模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class GuideActionReq(BaseModel):
    user_id: str = "default"


class GuideStepReq(BaseModel):
    user_id: str = "default"
    step: int = 1


class SearchReq(BaseModel):
    query: str
    limit: int = 20


class QuickActionReq(BaseModel):
    action_id: str
    user_id: str = "default"
    context: Dict[str, Any] = Field(default_factory=dict)


class ActivityReq(BaseModel):
    icon: str = "📌"
    text: str
    route: str = ""
    user_id: str = "default"


class ThemeUpdateReq(BaseModel):
    mode: str = "dark"
    accent: Optional[str] = None


# =========================================================================== #
# 1. 超级首页聚合（4 个端点）
# =========================================================================== #
@router.get("/homepage")
def get_homepage(user_id: str = Query("default")):
    """超级首页主数据：英雄区 + 功能卡片 + 统计 + 快速操作 + 最近动态 + 引导状态。"""
    g = _guard()
    if g:
        return g
    try:
        dash = get_ux_dashboard()
        return ok(dash.homepage(user_id))
    except Exception as e:  # pragma: no cover
        logger.exception("homepage error")
        return fail(str(e))


@router.get("/overview")
def get_overview():
    """控制台总览（含统计指标）。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(get_ux_dashboard().overview())
    except Exception as e:  # pragma: no cover
        return fail(str(e))


@router.get("/feature-cards")
def feature_cards():
    """四大核心功能卡片。"""
    g = _guard()
    if g:
        return g
    return ok(get_homepage_config().feature_cards)


@router.get("/feature-cards/{card_id}")
def feature_card_detail(card_id: str):
    card = get_homepage_config().feature_card(card_id)
    if not card:
        return fail(f"功能卡片不存在: {card_id}", 404)
    return ok(card)


# =========================================================================== #
# 2. 快速统计（2 个端点）
# =========================================================================== #
@router.get("/quick-stats")
def quick_stats():
    """已扫描目标 / 已发现漏洞 / 待处理报告 / 已纳管资产。"""
    g = _guard()
    if g:
        return g
    return ok(get_ux_dashboard().quick_stats())


@router.get("/recent-activity")
def recent_activity(limit: int = Query(8, ge=1, le=50)):
    """最近操作记录。"""
    g = _guard()
    if g:
        return g
    return ok(get_ux_dashboard().recent_activity(limit))


@router.post("/recent-activity")
def add_activity(req: ActivityReq):
    """追加一条最近操作。"""
    g = _guard()
    if g:
        return g
    rec = get_ux_dashboard().add_activity(req.icon, req.text, req.route)
    return ok(rec)


# =========================================================================== #
# 3. 智能引导（7 个端点）
# =========================================================================== #
@router.get("/guide/flow")
def guide_flow():
    """三步引导流程定义。"""
    g = _guard()
    if g:
        return g
    return ok(GUIDE_FLOW)


@router.get("/guide/state")
def guide_state(user_id: str = Query("default")):
    """查询某用户引导状态（决定是否自动弹出）。"""
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_manager().get_state(user_id))


@router.post("/guide/start")
def guide_start(req: GuideActionReq):
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_manager().start(req.user_id))


@router.post("/guide/next")
def guide_next(req: GuideActionReq):
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_manager().next_step(req.user_id))


@router.post("/guide/complete")
def guide_complete(req: GuideActionReq):
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_manager().complete(req.user_id))


@router.post("/guide/skip")
def guide_skip(req: GuideActionReq):
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_manager().skip(req.user_id))


@router.post("/guide/reset")
def guide_reset(req: GuideActionReq):
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_manager().reset(req.user_id))


@router.get("/guide/stats")
def guide_stats():
    g = _guard()
    if g:
        return g
    return ok({
        **get_smart_guide_manager().stats(),
        "events": get_smart_guide_manager().events(50),
    })


# =========================================================================== #
# 4. 全局搜索（5 个端点）
# =========================================================================== #
@router.get("/search")
def global_search(q: str = Query("", description="搜索关键词"),
                  limit: int = Query(20, ge=1, le=50)):
    """全局模糊搜索：功能/漏洞/报告/目标。"""
    g = _guard()
    if g:
        return g
    t0 = time.perf_counter()
    res = get_global_search().search(q, limit)
    res["took_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return ok(res)


@router.post("/search")
def global_search_post(req: SearchReq):
    g = _guard()
    if g:
        return g
    t0 = time.perf_counter()
    res = get_global_search().search(req.query, req.limit)
    res["took_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return ok(res)


@router.get("/search/history")
def search_history(limit: int = Query(15, ge=1, le=50)):
    g = _guard()
    if g:
        return g
    return ok(get_global_search().history(limit))


@router.delete("/search/history")
def search_history_clear():
    g = _guard()
    if g:
        return g
    return ok(get_global_search().clear_history())


@router.get("/search/stats")
def search_stats():
    g = _guard()
    if g:
        return g
    return ok(get_global_search().stats())


# =========================================================================== #
# 5. 快速操作（4 个端点）
# =========================================================================== #
@router.get("/quick-actions")
def quick_actions_list():
    g = _guard()
    if g:
        return g
    return ok(get_quick_actions_manager().list())


@router.post("/quick-actions/run")
def quick_action_run(req: QuickActionReq):
    g = _guard()
    if g:
        return g
    res = get_quick_actions_manager().run(req.action_id, req.context)
    if not res.get("success"):
        return fail(res.get("error", "执行失败"), 404)
    return ok(res)


@router.get("/quick-actions/history")
def quick_action_history(limit: int = Query(20, ge=1, le=50)):
    g = _guard()
    if g:
        return g
    return ok(get_quick_actions_manager().history(limit))


@router.get("/quick-actions/stats")
def quick_action_stats():
    g = _guard()
    if g:
        return g
    return ok(get_quick_actions_manager().stats())


# =========================================================================== #
# 6. 主题 / 导航 / 响应式（5 个端点）
# =========================================================================== #
@router.get("/theme")
def get_theme():
    g = _guard()
    if g:
        return g
    return ok(get_homepage_config().theme)


@router.put("/theme")
def update_theme(req: ThemeUpdateReq):
    g = _guard()
    if g:
        return g
    theme = get_homepage_config().theme
    theme["mode"] = req.mode
    if req.accent:
        theme["colors"]["accent"] = req.accent
    return ok(theme)


@router.get("/nav")
def nav_groups():
    g = _guard()
    if g:
        return g
    return ok({
        "groups": get_homepage_config().nav_groups,
        "item_count": get_homepage_config().nav_item_count(),
    })


@router.get("/responsive")
def responsive_config():
    g = _guard()
    if g:
        return g
    return ok(get_homepage_config().responsive)


@router.get("/config")
def full_config():
    g = _guard()
    if g:
        return g
    return ok(get_homepage_config().all())
