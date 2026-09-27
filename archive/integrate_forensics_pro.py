# -*- coding: utf-8 -*-
"""
integrate_forensics_pro.py — 方向2：取证分析做深（5.5→9.0）集成脚本。

把 forensics_pro 路由 + 控制台页面注入 api_server/app.py，幂等。
"""

from __future__ import annotations

import os
import sys

APP_PY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "api_server", "app.py")

MARKER = "# ==== INJECT: forensics_pro (方向2) ===="

INJECT_BLOCK = '''

''' + MARKER + '''
try:
    from api_server.forensics_pro_routes import router as _fp_router
    app.include_router(_fp_router)
    print("方向2 取证Pro路由已注册（八阶段 / 94端点 / AI / WebSocket / 大屏 / 报告）")
except Exception as _e:
    print(f"方向2 取证Pro路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLFP
    @app.get("/forensics-pro", include_in_schema=False)
    async def _fp_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "forensics_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLFP(content=_f.read())
        return _HTMLFP(content="<h1>forensics_pro_console.html 未找到</h1>")
    print("方向2 控制台页面已注册: /forensics-pro")
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
    print("[+] 路由前缀: /api/v1/forensics-pro")
    print("[+] 控制台页面: /forensics-pro")
    print("[+] WebSocket: /api/v1/forensics-pro/ws/{task_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
