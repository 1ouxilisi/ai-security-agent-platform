# -*- coding: utf-8 -*-
"""
integrate_soc_pro.py — 方向1：SOC 安全运营做深（5.5→9.0）集成脚本。

把 soc_pro 路由 + 控制台页面注入 api_server/app.py，幂等。
"""

from __future__ import annotations

import os
import sys

APP_PY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "api_server", "app.py")

MARKER = "# ==== INJECT: soc_pro (方向1) ===="

INJECT_BLOCK = '''

''' + MARKER + '''
try:
    from api_server.soc_pro_routes import router as _soc_router
    app.include_router(_soc_router)
    print("方向1 SOC Pro 路由已注入（七阶段 / 58 检测规则 / AI / WebSocket / 大屏 / 报告）")
except Exception as _e:
    print(f"方向1 SOC Pro 路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLSOC
    @app.get("/soc-pro", include_in_schema=False)
    async def _soc_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "soc_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLSOC(content=_f.read())
        return _HTMLSOC(content="<h1>soc_pro_console.html 未找到</h1>")
    print("方向1 控制台页面已注册: /soc-pro")
except Exception as _e:
    print(f"方向1 控制台页面注册失败: {_e}")
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
    print("[+] 路由前缀: /api/v1/soc-pro")
    print("[+] 控制台页面: /soc-pro")
    print("[+] WebSocket: /api/v1/soc-pro/ws/{task_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
