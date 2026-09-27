# -*- coding: utf-8 -*-
"""
集成脚本 — 把「AI 自主规划」与「WebSocket 实时可视化」两个新模块注入 app.py。

幂等：用标记注释包裹注入块，重复运行不会重复注入。

用法:
    cd ai-hacking-agent
    python -m api_server.integrate_autonomous_realtime
"""

from __future__ import annotations

import io
import os
import sys

_MARKER_BEGIN = "# === AIPLANNER_RT_BEGIN ==="
_MARKER_END = "# === AIPLANNER_RT_END ==="

_BLOCK = '''
%(begin)s
# ---- Direction 1: AI 自主规划能力大升级 ----
try:
    from api_server.ai_autonomous_planner_routes import router as ai_planner_router
    app.include_router(ai_planner_router)
    log.info("AI 自主规划路由已注册：/api/v1/ai-autonomous-planner（27端点）")
except Exception as e:
    log.warning(f"AI 自主规划路由注册失败: {e}")

# ---- Direction 2: WebSocket 实时可视化 ----
try:
    from api_server.realtime_visualization_routes import router as rt_vis_router
    app.include_router(rt_vis_router)
    log.info("实时可视化路由已注册：/api/v1/realtime-visualization（22 REST + 1 WebSocket）")
except Exception as e:
    log.warning(f"实时可视化路由注册失败: {e}")

# ---- 前端页面路由 ----
try:
    from fastapi.responses import HTMLResponse as _HTMLR_APRT
    from pathlib import Path as _Path_APRT
    _PAGES_APRT = [
        ("/ai-autonomous-planner", "ai_autonomous_planner_console.html", "AI 自主规划控制台"),
        ("/realtime-visualization", "realtime_visualization_console.html", "实时可视化控制台"),
    ]
    for _route, _fname, _desc in _PAGES_APRT:
        def _make_page_aprt(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_aprt():
                _p = _Path_APRT(__file__).parent / fname
                if _p.exists():
                    return _HTMLR_APRT(content=_p.read_text(encoding="utf-8"))
                return _HTMLR_APRT(content=f"<h1>{desc} 未找到</h1>")
            return _page_aprt
        _make_page_aprt()
    log.info("前端页面已注册：/ai-autonomous-planner /realtime-visualization")
except Exception as e:
    log.warning(f"前端页面路由注册失败: {e}")
%(end)s
''' % {"begin": _MARKER_BEGIN, "end": _MARKER_END}


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    app_py = os.path.join(here, "app.py")
    if not os.path.exists(app_py):
        print(f"[ERR] 找不到 {app_py}", file=sys.stderr)
        return 1

    with io.open(app_py, "r", encoding="utf-8") as f:
        content = f.read()

    if _MARKER_BEGIN in content and _MARKER_END in content:
        print("[SKIP] app.py 已注入过，无需重复操作。")
        return 0

    # 追加到文件末尾
    if not content.endswith("\n"):
        content += "\n"
    content += _BLOCK

    with io.open(app_py, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 已注入 AI 自主规划 + WebSocket 实时可视化路由到 app.py")
    print("     - /api/v1/ai-autonomous-planner  (27 端点)")
    print("     - /api/v1/realtime-visualization  (22 REST + 1 WebSocket)")
    print("     - /ai-autonomous-planner  (页面)")
    print("     - /realtime-visualization (页面)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
