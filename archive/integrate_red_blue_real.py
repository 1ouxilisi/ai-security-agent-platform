# -*- coding: utf-8 -*-
"""
integrate_red_blue_real.py — 方向4 红蓝对抗真实化 集成脚本（幂等）。

作用:
    把「红蓝对抗真实化」路由 + 控制台页面注入 api_server/app.py。
    - 路由前缀: /api/v1/red-blue-real  (118 端点，含 1 WebSocket)
    - 控制台页面: /red-blue-real

幂等: 已存在标记块则跳过，不重复注入。
用法:
    python integrate_red_blue_real.py
"""

from __future__ import annotations

import io
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
APP_PY = os.path.join(ROOT, "api_server", "app.py")

MARKER_BEGIN = "# ==== INJECT: red_blue_real (方向4) ===="
MARKER_END = "# ==== /INJECT: red_blue_real (方向4) ===="

BLOCK = f'''
{MARKER_BEGIN}
try:
    from api_server.red_blue_real_routes import router as _rbr_router
    app.include_router(_rbr_router)
    print("方向4 红蓝对抗真实化路由已注册 (118端点: 红8战术+蓝5能力+紫+C2工具+导航+报告+WS)")
except Exception as _e:
    print(f"方向4 红蓝对抗真实化路由注册失败: {{_e}}")

try:
    from fastapi.responses import HTMLResponse as _HTMLRBR
    @app.get("/red-blue-real", include_in_schema=False)
    async def _rbr_page():
        import os as _osrbr
        _p = _osrbr.path.join(_osrbr.path.dirname(__file__),
                           "red_blue_real_console.html")
        if _osrbr.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLRBR(content=_f.read())
        return _HTMLRBR(content="<h1>red_blue_real_console.html 未找到</h1>")
    print("方向4 控制台页面已注册: /red-blue-real")
except Exception as _e:
    print(f"方向4 控制台页面注册失败: {{_e}}")
{MARKER_END}
'''


def main() -> int:
    if not os.path.exists(APP_PY):
        print(f"[!] 未找到 app.py: {APP_PY}")
        return 1
    with io.open(APP_PY, "r", encoding="utf-8") as f:
        src = f.read()

    if MARKER_BEGIN in src:
        print("[=] 方向4 红蓝对抗真实化 已注入过，跳过（幂等）。")
        return 0

    if not src.endswith("\n"):
        src += "\n"
    src += "\n" + BLOCK
    with io.open(APP_PY, "w", encoding="utf-8") as f:
        f.write(src)
    print("[+] 已注入方向4 红蓝对抗真实化 到 app.py")
    print("    - 路由: /api/v1/red-blue-real (118 端点)")
    print("    - 页面: /red-blue-real")
    return 0


if __name__ == "__main__":
    sys.exit(main())
