# -*- coding: utf-8 -*-
"""
api_server/ux_upgrade_routes.py — 方向5：用户体验大升级 REST API。
路由前缀: /api/v1/ux-upgrade
统一响应: {"success": bool, "data": ..., "error": ...}
覆盖: 超级首页/智能引导/移动端/暗色主题/全局搜索/UX聚合。
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ux-upgrade", tags=["用户体验大升级"])

_MOD_AVAILABLE = False
try:
    from ux_upgrade import (
        get_homepage_v2, get_smart_guide_v2, get_mobile_adaptive,
        get_dark_theme, get_global_search_v2, get_ux_dashboard,
    )
    _MOD_AVAILABLE = True
    logger.info("ux_upgrade_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("ux_upgrade_routes: load failed: %s", e)


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
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
        return fail("UX 升级模块不可用，请检查加载日志", 503)
    return None


# 请求模型
class UserReq(BaseModel):
    user_id: str = "default"


class QuickActionReq(BaseModel):
    action_id: str
    user_id: str = "default"
    context: Dict[str, Any] = Field(default_factory=dict)


class SearchReq(BaseModel):
    query: str
    limit: int = 15


class ThemeReq(BaseModel):
    mode: str = "dark"


class ViewportReq(BaseModel):
    width: int = 1280


class FixReq(BaseModel):
    error_code: str
    raw: str = ""


# --------------------------------------------------------------------------- #
# 0. UX 聚合
# --------------------------------------------------------------------------- #
@router.get("/overview")
def ux_overview():
    g = _guard()
    if g:
        return g
    return ok(get_ux_dashboard().overview())


# --------------------------------------------------------------------------- #
# 1. 超级首页 V2
# --------------------------------------------------------------------------- #
@router.get("/homepage")
def homepage(user_id: str = "default"):
    g = _guard()
    if g:
        return g
    return ok(get_homepage_v2().get(user_id))


@router.post("/homepage/quick-action")
def homepage_quick(req: QuickActionReq):
    g = _guard()
    if g:
        return g
    return ok(get_homepage_v2().quick_action(req.action_id, req.context))


@router.get("/homepage/activity")
def homepage_activity(limit: int = Query(10, ge=1, le=50)):
    g = _guard()
    if g:
        return g
    return ok(get_homepage_v2().recent_activity(limit=limit))


@router.get("/homepage/stats")
def homepage_stats():
    g = _guard()
    if g:
        return g
    return ok(get_homepage_v2()._live_stats())


# --------------------------------------------------------------------------- #
# 2. 智能引导 V2
# --------------------------------------------------------------------------- #
@router.get("/guide/should-start")
def guide_should(user_id: str = "default"):
    g = _guard()
    if g:
        return g
    return ok({"user_id": user_id,
               "should_start": get_smart_guide_v2().should_start(user_id)})


@router.post("/guide/start")
def guide_start(req: UserReq):
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_v2().start(req.user_id))


@router.post("/guide/next")
def guide_next(req: UserReq):
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_v2().next_step(req.user_id))


@router.post("/guide/complete")
def guide_complete(req: UserReq):
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_v2().complete(req.user_id))


@router.get("/guide/tooltips")
def guide_tooltips():
    g = _guard()
    if g:
        return g
    return ok({"tooltips": get_smart_guide_v2().get_tooltips()})


@router.get("/guide/tooltip/{key}")
def guide_tooltip(key: str):
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_v2().get_tooltip(key))


@router.post("/guide/suggest-fix")
def guide_fix(req: FixReq):
    g = _guard()
    if g:
        return g
    return ok(get_smart_guide_v2().suggest_fix(req.error_code, req.raw))


# --------------------------------------------------------------------------- #
# 3. 移动端适配
# --------------------------------------------------------------------------- #
@router.get("/mobile/config")
def mobile_config():
    g = _guard()
    if g:
        return g
    return ok(get_mobile_adaptive().config())


@router.post("/mobile/detect")
def mobile_detect(req: ViewportReq):
    g = _guard()
    if g:
        return g
    return ok(get_mobile_adaptive().detect(req.width))


@router.get("/mobile/dashboard")
def mobile_dashboard():
    g = _guard()
    if g:
        return g
    return ok(get_mobile_adaptive().mobile_dashboard())


@router.get("/mobile/breakpoint")
def mobile_breakpoint():
    g = _guard()
    if g:
        return g
    from ux_upgrade.mobile_adaptive import BREAKPOINT
    return ok({"breakpoint_px": BREAKPOINT})


# --------------------------------------------------------------------------- #
# 4. 暗色主题
# --------------------------------------------------------------------------- #
@router.get("/theme/current")
def theme_current():
    g = _guard()
    if g:
        return g
    return ok(get_dark_theme().current())


@router.get("/theme/palette")
def theme_palette():
    g = _guard()
    if g:
        return g
    return ok(get_dark_theme().palette())


@router.post("/theme/set")
def theme_set(req: ThemeReq):
    g = _guard()
    if g:
        return g
    return ok(get_dark_theme().set_mode(req.mode))


@router.post("/theme/toggle")
def theme_toggle():
    g = _guard()
    if g:
        return g
    return ok(get_dark_theme().toggle())


@router.get("/theme/css-variables")
def theme_css():
    g = _guard()
    if g:
        return g
    return ok({"variables": get_dark_theme().css_variables()})


# --------------------------------------------------------------------------- #
# 5. 全局搜索 V2
# --------------------------------------------------------------------------- #
@router.get("/search")
def global_search(q: str = Query("", description="搜索词"),
                  limit: int = Query(15, ge=1, le=50)):
    g = _guard()
    if g:
        return g
    return ok(get_global_search_v2().search(q, limit=limit))


@router.post("/search")
def global_search_post(req: SearchReq):
    g = _guard()
    if g:
        return g
    return ok(get_global_search_v2().search(req.query, limit=req.limit))


@router.get("/search/index-size")
def search_index_size():
    g = _guard()
    if g:
        return g
    return ok({"index_size": get_global_search_v2().index_size()})


@router.get("/search/hotkeys")
def search_hotkeys():
    g = _guard()
    if g:
        return g
    return ok({"hotkeys": ["Ctrl+K", "↑↓", "Enter", "Esc"]})
