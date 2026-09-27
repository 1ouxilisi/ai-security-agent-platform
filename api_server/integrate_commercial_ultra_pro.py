# -*- coding: utf-8 -*-
"""
集成脚本 — 把「商业产品化 Ultra Pro」注入 app.py。

幂等：用标记注释包裹注入块，重复运行不会重复注入。

用法:
    cd ai-hacking-agent
    python -m api_server.integrate_commercial_ultra_pro
"""

from __future__ import annotations

import io
import os
import sys

_MARKER_BEGIN = "# === CUPRO_BEGIN ==="
_MARKER_END = "# === CUPRO_END ==="

_BLOCK = '''
%(begin)s
# ---- 方向4：商业产品化做深（支付/订阅/客户/SLA/工单/API计费/多租户） ----
try:
    from api_server.commercial_ultra_pro_routes import router as _cupro_router
    app.include_router(_cupro_router)
    log.info("商业产品化 Ultra Pro 路由已注册：/api/v1/commercial-ultra-pro（96 端点）")
except Exception as e:
    log.warning(f"商业产品化 Ultra Pro 路由注册失败: {e}")

# ---- 前端页面路由: /admin-center ----
try:
    from fastapi.responses import HTMLResponse as _HTMLR_CUPRO
    from pathlib import Path as _Path_CUPRO
    @app.get("/admin-center", include_in_schema=False)
    async def _page_cupro():
        _p = _Path_CUPRO(__file__).parent / "commercial_ultra_pro_console.html"
        if _p.exists():
            return _HTMLR_CUPRO(content=_p.read_text(encoding="utf-8"))
        return _HTMLR_CUPRO(content="<h1>商业产品化 Ultra Pro 控制台未找到</h1>")
    log.info("商业产品化 Ultra Pro 页面已注册：/admin-center")
except Exception as e:
    log.warning(f"商业产品化 Ultra Pro 页面注册失败: {e}")
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
        print("[SKIP] app.py 已注入商业产品化 Ultra Pro，无需重复操作。")
        return 0

    if not content.endswith("\n"):
        content += "\n"
    content += _BLOCK

    with io.open(app_py, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 已注入商业产品化 Ultra Pro 到 app.py")
    print("     - /api/v1/commercial-ultra-pro  (96 REST 端点)")
    print("     - /admin-center                  (深色主题商业管理后台)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
