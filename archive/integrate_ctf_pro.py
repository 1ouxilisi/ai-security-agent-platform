# -*- coding: utf-8 -*-
"""
integrate_ctf_pro.py — 方向1：CTF 夺旗赛做深（5.5→9.0）集成脚本。

把 ctf_pro 路由 + 控制台页面注入 api_server/app.py，幂等。
不修改 app.py 原有逻辑，仅在末尾追加一段注入块。
"""

from __future__ import annotations

import os
import sys

APP_PY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "api_server", "app.py")

MARKER = "# ==== INJECT: ctf_pro (方向1 CTF) ===="

INJECT_BLOCK = '''

''' + MARKER + '''
try:
    from api_server.ctf_pro_routes import router as _ctf_router
    app.include_router(_ctf_router)
    print("方向1 CTF Pro 路由已注入（八阶段 / 8大题型 / Docker部署 / AI / WebSocket / CTF大屏 / 报告）")
except Exception as _e:
    print(f"方向1 CTF Pro 路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLCTF
    @app.get("/ctf-pro", include_in_schema=False)
    async def _ctf_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "ctf_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLCTF(content=_f.read())
        return _HTMLCTF(content="<h1>ctf_pro_console.html 未找到</h1>")
    print("方向1 CTF 控制台页面已注册: /ctf-pro")
except Exception as _e:
    print(f"方向1 CTF 控制台页面注册失败: {_e}")
'''


def main() -> int:
    if not os.path.exists(APP_PY):
        print(f"[!] 找不到 app.py: {APP_PY}")
        return 1
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if MARKER in content:
        print("[=] 已注入过，跳过（幂等）。")
        return 0
    with open(APP_PY, "a", encoding="utf-8") as f:
        f.write(INJECT_BLOCK)
    print(f"[+] 已注入到 {APP_PY}")
    print("[+] 路由前缀: /api/v1/ctf-pro")
    print("[+] 控制台页面: /ctf-pro")
    print("[+] WebSocket: /api/v1/ctf-pro/ws/{task_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
