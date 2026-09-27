# -*- coding: utf-8 -*-
"""
integrate_threat_intel_pro.py — 方向2 威胁情报做深 集成脚本。

将 threat_intel_pro 路由 + 控制台页面注入 api_server/app.py。
幂等：已注入则跳过。
"""

from __future__ import annotations

import os
import sys

APP_PY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "api_server", "app.py")

MARKER = "# ==== INJECT: threat_intel_pro (方向2) ===="

INJECT_BLOCK = '''

''' + MARKER + '''
try:
    from api_server.threat_intel_pro_routes import router as _tip_router
    app.include_router(_tip_router)
    print("方向2 威胁情报Pro路由已注册 (八阶段/IOC/Actor/攻击面/暗网/STIX/WebSocket)")
except Exception as _e:
    print(f"方向2 威胁情报Pro路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLTIP
    @app.get("/threat-intel-pro", include_in_schema=False)
    async def _tip_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "threat_intel_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLTIP(content=_f.read())
        return _HTMLTIP(content="<h1>threat_intel_pro_console.html 未找到</h1>")
    print("方向2 控制台页面已注册: /threat-intel-pro")
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
    print("[+] 路由前缀: /api/v1/threat-intel-pro")
    print("[+] WebSocket: /api/v1/threat-intel-pro/ws/{task_id}")
    print("[+] 控制台页面: /threat-intel-pro")
    return 0


if __name__ == "__main__":
    sys.exit(main())
