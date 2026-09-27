# -*- coding: utf-8 -*-
"""
integrate_cloud_security_pro.py — 方向3 云安全 Pro 集成脚本。

将 cloud_security_pro 路由 + 控制台页面注入 api_server/app.py。
幂等：已注入则跳过。
"""

from __future__ import annotations

import os
import sys

APP_PY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "api_server", "app.py")

MARKER = "# ==== INJECT: cloud_security_pro (方向3) ===="

INJECT_BLOCK = '''

''' + MARKER + '''
try:
    from api_server.cloud_security_pro_routes import router as _csp_router
    app.include_router(_csp_router)
    print("方向3 云安全Pro路由已注册 (含 WebSocket /ws)")
except Exception as _e:
    print(f"方向3 云安全Pro路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLCSP
    @app.get("/cloud-security-pro", include_in_schema=False)
    async def _csp_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "cloud_security_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLCSP(content=_f.read())
        return _HTMLCSP(content="<h1>cloud_security_pro_console.html 未找到</h1>")
    print("方向3 控制台页面已注册: /cloud-security-pro")
except Exception as _e:
    print(f"方向3 控制台页面注册失败: {_e}")
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
    print("[+] 路由前缀: /api/v1/cloud-security-pro")
    print("[+] WebSocket: /api/v1/cloud-security-pro/ws")
    print("[+] 控制台页面: /cloud-security-pro")
    return 0


if __name__ == "__main__":
    sys.exit(main())
