# -*- coding: utf-8 -*-
"""
api_server/tool_runtime_routes.py — 外部工具运行时与性能 REST API 入口。

实际路由实现在 tool_runtime/api_routes.py，此处做 re-export，
便于 app.py 通过 `from api_server.tool_runtime_routes import router` 挂载。

路由前缀: /api/v1/system-health  （共 36 个端点）
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:
    from tool_runtime.api_routes import router  # noqa: F401
    logger.info("tool_runtime_routes: router loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("tool_runtime_routes: load failed: %s", e)
    # 兜底：提供一个空 router，避免 app.py import 失败
    from fastapi import APIRouter
    router = APIRouter(prefix="/api/v1/system-health", tags=["工具运行时与性能"])
