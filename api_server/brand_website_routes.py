# -*- coding: utf-8 -*-
"""
api_server/brand_website_routes.py — 品牌官网落地页 REST API 路由入口。

实际路由定义在 brand_website/api_routes.py（30+ 端点），本文件为 app.py
的导入入口，暴露 `router` 对象，遵循项目约定：
    from api_server.brand_website_routes import router as brand_website_router
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:
    from brand_website.api_routes import (  # noqa: F401
        router,
        ok,
        fail,
        _clean,
        _new_task,
        _finish_task,
        _get_task,
    )
    logger.info("brand_website_routes: router loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("brand_website_routes: load failed: %s", e)
    # 回退：空 router，保证 app.py 导入不炸
    from fastapi import APIRouter  # noqa: E402

    router = APIRouter(prefix="/api/v1/brand-website", tags=["品牌官网落地页"])


__all__ = ["router", "ok", "fail", "_clean", "_new_task", "_finish_task", "_get_task"]
