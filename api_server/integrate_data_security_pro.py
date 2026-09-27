# -*- coding: utf-8 -*-
"""
集成脚本 — 把「数据安全 Pro」注入 app.py。

幂等：用标记注释包裹注入块，重复运行不会重复注入。

用法:
    cd ai-hacking-agent
    python -m api_server.integrate_data_security_pro
"""

from __future__ import annotations

import io
import os
import sys

_MARKER_BEGIN = "# === DSPRO_BEGIN ==="
_MARKER_END = "# === DSPRO_END ==="

_BLOCK = '''
%(begin)s
# ---- Direction 3: 数据安全做深（5.5 -> 9.0） ----
try:
    from api_server.data_security_pro_routes import router as _dsp_router
    app.include_router(_dsp_router)
    log.info("数据安全 Pro 路由已注册：/api/v1/data-security-pro（64 REST + 1 WebSocket）")
except Exception as e:
    log.warning(f"数据安全 Pro 路由注册失败: {e}")

# ---- 前端页面路由: /data-security-pro ----
try:
    from fastapi.responses import HTMLResponse as _HTMLR_DSP
    from pathlib import Path as _Path_DSP
    @app.get("/data-security-pro", include_in_schema=False)
    async def _page_dsp():
        _p = _Path_DSP(__file__).parent / "data_security_pro_console.html"
        if _p.exists():
            return _HTMLR_DSP(content=_p.read_text(encoding="utf-8"))
        return _HTMLR_DSP(content="<h1>数据安全 Pro 控制台未找到</h1>")
    log.info("数据安全 Pro 页面已注册：/data-security-pro")
except Exception as e:
    log.warning(f"数据安全 Pro 页面注册失败: {e}")
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
        print("[SKIP] app.py 已注入过数据安全 Pro，无需重复操作。")
        return 0

    if not content.endswith("\n"):
        content += "\n"
    content += _BLOCK

    with io.open(app_py, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 已注入数据安全 Pro 到 app.py")
    print("     - /api/v1/data-security-pro  (64 REST + 1 WebSocket)")
    print("     - /data-security-pro         (深色主题控制台 + 数据安全大屏)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
