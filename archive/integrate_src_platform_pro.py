# -*- coding: utf-8 -*-
"""
integrate_src_platform_pro.py — 方向2：SRC 漏洞平台做深（5.5→9.0）集成脚本。

把 src_platform_pro 路由 + 控制台页面注入 api_server/app.py，幂等。
"""

from __future__ import annotations

import os
import sys

APP_PY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "api_server", "app.py")

MARKER = "# ==== INJECT: src_platform_pro (方向2) ===="

INJECT_BLOCK = '''

''' + MARKER + '''
try:
    from api_server.src_platform_pro_routes import router as _src_router
    app.include_router(_src_router)
    print("方向2 SRC Pro 路由已注入（八阶段 / 80+端点 / AI / WebSocket / 大屏 / 报告）")
except Exception as _e:
    print(f"方向2 SRC Pro 路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLSRC
    @app.get("/src-platform-pro", include_in_schema=False)
    async def _src_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "src_platform_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLSRC(content=_f.read())
        return _HTMLSRC(content="<h1>src_platform_pro_console.html 未找到</h1>")
    print("方向2 控制台页面已注册: /src-platform-pro")
except Exception as _e:
    print(f"方向2 控制台页面注册失败: {_e}")
'''


def main() -> int:
    if not os.path.exists(APP_PY):
        print(f"[!] 找不到 app.py: {APP_PY}")
        return 1
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if MARKER in content:
        print("[=] 已注入过，跳过。")
        return 0
    with open(APP_PY, "a", encoding="utf-8") as f:
        f.write(INJECT_BLOCK)
    print(f"[+] 已注入到 {APP_PY}")
    print("[+] 路由前缀: /api/v1/src-platform-pro")
    print("[+] 控制台页面: /src-platform-pro")
    print("[+] WebSocket: /api/v1/src-platform-pro/ws/{task_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
