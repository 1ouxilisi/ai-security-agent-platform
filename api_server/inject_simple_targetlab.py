# -*- coding: utf-8 -*-
"""
inject_simple_targetlab.py —— 统一注入脚本（不修改 app.py）

功能：
  1. 注入方向3「极简模式」路由   -> /api/v1/simple/*      + 页面 /simple-console
  2. 注入方向5「本地靶场」路由   -> /api/v1/target-lab/*  + 页面 /target-lab

用法：
  方式 A（推荐，直接跑）：
      python -m api_server.inject_simple_targetlab
  方式 B（在你自己的启动脚本里）：
      from api_server.app import app
      from api_server.inject_simple_targetlab import register
      register(app)

本脚本只做"追加"，不会改动 app.py 源码。
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("inject_simple_targetlab")

HERE = os.path.dirname(os.path.abspath(__file__))

# 新增的前端页面路由表
_PAGES = [
    ("/simple-console", "simple_mode_console.html", "极简控制台"),
    ("/target-lab", "target_lab_manager_console.html", "本地靶场管理控制台"),
]


def register(app) -> dict:
    """把两个新路由 + 两个新页面挂到已有 FastAPI app 上。返回注册摘要。"""
    summary = {"routers": [], "pages": []}

    # ---- 1. 极简模式路由 ----
    try:
        from api_server.simple_mode_routes import router as simple_router
        app.include_router(simple_router)
        summary["routers"].append("/api/v1/simple/* (21 端点)")
        logger.info("极简模式路由已注入")
    except Exception as e:  # noqa: BLE001
        logger.warning("极简模式路由注入失败: %s", e)

    # ---- 2. 本地靶场路由 ----
    try:
        from api_server.target_lab_manager_routes import router as lab_router
        app.include_router(lab_router)
        summary["routers"].append("/api/v1/target-lab/* (26 端点)")
        logger.info("本地靶场路由已注入")
    except Exception as e:  # noqa: BLE001
        logger.warning("本地靶场路由注入失败: %s", e)

    # ---- 3. 前端页面 ----
    try:
        from fastapi.responses import HTMLResponse

        for route, fname, desc in _PAGES:
            def _make_handler(fname=fname, desc=desc):
                async def _page():
                    p = os.path.join(HERE, fname)
                    if os.path.exists(p):
                        with open(p, "r", encoding="utf-8") as f:
                            return HTMLResponse(f.read())
                    return HTMLResponse(f"<h1>{desc}页面未找到: {fname}</h1>",
                                        status_code=404)
                return _page
            app.get(route, include_in_schema=False)(_make_handler())
            summary["pages"].append(f"{route} -> {fname}")
        logger.info("前端页面已注入: %s", [p[0] for p in _PAGES])
    except Exception as e:  # noqa: BLE001
        logger.warning("前端页面注入失败: %s", e)

    return summary


def run(host: str = "0.0.0.0", port: int = 8000) -> None:
    """导入 app、注入路由、启动 uvicorn。"""
    from api_server.app import app  # noqa: WPS433  (延迟导入，避免循环)

    s = register(app)
    print("=" * 60)
    print("已注入方向3 + 方向5：")
    for r in s["routers"]:
        print("  [API]  ", r)
    for p in s["pages"]:
        print("  [页面] ", p)
    print("=" * 60)
    print(f"极简控制台: http://127.0.0.1:{port}/simple-console")
    print(f"本地靶场:   http://127.0.0.1:{port}/target-lab")
    print("=" * 60)

    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run(port=port)
