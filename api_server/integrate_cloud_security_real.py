# -*- coding: utf-8 -*-
"""
集成脚本 — 把「云安全真实版 cloud_security_real」注入 app.py。

幂等：用标记注释包裹注入块，重复运行不会重复注入。

用法:
    cd ai-hacking-agent
    python -m api_server.integrate_cloud_security_real
"""

from __future__ import annotations

import io
import os
import sys

_MARKER_BEGIN = "# === CSREAL_BEGIN ==="
_MARKER_END = "# === CSREAL_END ==="

_BLOCK = '''
%(begin)s
# ---- 方向3：云安全真实化（6.5 -> 8.5）----
try:
    from api_server.cloud_security_real_routes import router as _csreal_router
    app.include_router(_csreal_router)
    print("方向3 云安全真实版路由已注册: /api/v1/cloud-security-real (60+ REST)")
except Exception as _e:
    print(f"方向3 云安全真实版路由注册失败: {_e}")

# ---- 前端页面路由: /cloud-security-real ----
try:
    from fastapi.responses import HTMLResponse as _HTMLR_CSREAL
    import os as _os_csreal
    @app.get("/cloud-security-real", include_in_schema=False)
    async def _page_csreal():
        _p = _os_csreal.path.join(_os_csreal.path.dirname(__file__),
                                  "cloud_security_real_console.html")
        if _os_csreal.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLR_CSREAL(content=_f.read())
        return _HTMLR_CSREAL(content="<h1>cloud_security_real_console.html 未找到</h1>")
    print("方向3 云安全真实版页面已注册: /cloud-security-real")
except Exception as _e:
    print(f"方向3 云安全真实版页面注册失败: {_e}")
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
        print("[SKIP] app.py 已注入 cloud_security_real，无需重复操作。")
        return 0

    if not content.endswith("\n"):
        content += "\n"
    content += _BLOCK

    with io.open(app_py, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 已注入 cloud_security_real 到 app.py")
    print("     - /api/v1/cloud-security-real  (60+ REST 端点)")
    print("     - /cloud-security-real          (深色主题控制台页面)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
