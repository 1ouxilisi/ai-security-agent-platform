# -*- coding: utf-8 -*-
"""
集成脚本 — 把「统一 SOC Center + 领域联动工作流」注入 app.py。

幂等：用标记注释包裹注入块，重复运行不会重复注入。

用法:
    cd ai-hacking-agent
    python integrate_soc_center_linkage.py
    # 或
    python -m api_server.integrate_soc_center_linkage
"""

from __future__ import annotations

import io
import os
import sys

_MARKER_BEGIN = "# === SOCCENTER_LINKAGE_BEGIN ==="
_MARKER_END = "# === SOCCENTER_LINKAGE_END ==="

_BLOCK = '''
%(begin)s
# ---- 方向1：统一安全运营中心 SOC Center（54 REST + 统一 WebSocket） ----
try:
    from api_server.soc_center_routes import router as _socc_router
    app.include_router(_socc_router)
    print("统一 SOC Center 路由已注册：/api/v1/soc-center（54 REST + 统一 WebSocket）")
except Exception as _e:
    print(f"统一 SOC Center 路由注册失败: {_e}")

# ---- 前端页面路由: /soc-center ----
try:
    from fastapi.responses import HTMLResponse as _HTMLSOCC
    @app.get("/soc-center", include_in_schema=False)
    async def _page_socc():
        import os as _os_socc
        _p = _os_socc.path.join(_os_socc.path.dirname(__file__),
                                "soc_center_console.html")
        if _os_socc.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLSOCC(content=_f.read())
        return _HTMLSOCC(content="<h1>soc_center_console.html 未找到</h1>")
    print("统一 SOC Center 页面已注册：/soc-center")
except Exception as _e:
    print(f"统一 SOC Center 页面注册失败: {_e}")

# ---- 方向2：领域联动工作流（35 REST） ----
try:
    from api_server.workflow_linkage_routes import router as _wfl_router
    app.include_router(_wfl_router)
    print("领域联动工作流 路由已注册：/api/v1/workflow-linkage（35 REST）")
except Exception as _e:
    print(f"领域联动工作流 路由注册失败: {_e}")

# ---- 前端页面路由: /workflow-linkage ----
try:
    from fastapi.responses import HTMLResponse as _HTMLWFL
    @app.get("/workflow-linkage", include_in_schema=False)
    async def _page_wfl():
        import os as _os_wfl
        _p = _os_wfl.path.join(_os_wfl.path.dirname(__file__),
                               "workflow_linkage_console.html")
        if _os_wfl.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLWFL(content=_f.read())
        return _HTMLWFL(content="<h1>workflow_linkage_console.html 未找到</h1>")
    print("领域联动工作流 页面已注册：/workflow-linkage")
except Exception as _e:
    print(f"领域联动工作流 页面注册失败: {_e}")
%(end)s
''' % {"begin": _MARKER_BEGIN, "end": _MARKER_END}


def _find_app_py() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "app.py"),                    # 脚本在 api_server/ 内
        os.path.join(here, "api_server", "app.py"),     # 脚本在项目根
        os.path.join(os.path.dirname(here), "api_server", "app.py"),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    raise SystemExit("[ERR] 找不到 api_server/app.py")


def main() -> int:
    app_py = _find_app_py()
    with io.open(app_py, "r", encoding="utf-8") as f:
        content = f.read()

    if _MARKER_BEGIN in content and _MARKER_END in content:
        print("[SKIP] app.py 已注入 统一SOC Center + 领域联动，无需重复操作。")
        return 0

    if not content.endswith("\n"):
        content += "\n"
    content += _BLOCK

    with io.open(app_py, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 已注入 统一SOC Center + 领域联动 到 app.py")
    print("     - /api/v1/soc-center        (54 REST + 统一 WebSocket)")
    print("     - /soc-center               (深色主题控制台)")
    print("     - /api/v1/workflow-linkage  (35 REST)")
    print("     - /workflow-linkage         (深色主题联动控制台)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
