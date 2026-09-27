# -*- coding: utf-8 -*-
"""
集成脚本 — 把方向3（PDF报告导出）+ 方向5（真实环境验证体系）注入 app.py。

幂等：用标记注释包裹注入块，重复运行不会重复注入。

用法:
    cd ai-hacking-agent
    python -m api_server.integrate_pdf_validation
"""

from __future__ import annotations

import io
import os
import sys

_BEGIN = "# === PDFVAL_BEGIN ==="
_END = "# === PDFVAL_END ==="

_BLOCK = '''
%(begin)s
# ---- 方向3: PDF报告导出 + 方向5: 真实环境验证体系 ----
try:
    from api_server.pdf_report_routes import router as _pdf_router
    app.include_router(_pdf_router)
    print("方向3 PDF报告路由已注册：/api/v1/pdf-report（40+端点）")
except Exception as _e:
    print(f"方向3 PDF报告路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLRC
    from pathlib import Path as _PathRC
    @app.get("/report-center", include_in_schema=False)
    async def _page_rc():
        _p = _PathRC(__file__).parent / "report_center_console.html"
        if _p.exists():
            return _HTMLRC(content=_p.read_text(encoding="utf-8"))
        return _HTMLRC(content="<h1>report_center_console.html 未找到</h1>")
    print("方向3 报告中心页面已注册：/report-center")
except Exception as _e:
    print(f"方向3 报告中心页面注册失败: {_e}")

try:
    from api_server.validation_center_routes import router as _val_router
    app.include_router(_val_router)
    print("方向5 验证中心路由已注册：/api/v1/validation（40+端点）")
except Exception as _e:
    print(f"方向5 验证中心路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLVC
    from pathlib import Path as _PathVC
    @app.get("/validation-center", include_in_schema=False)
    async def _page_vc():
        _p = _PathVC(__file__).parent / "validation_center_console.html"
        if _p.exists():
            return _HTMLVC(content=_p.read_text(encoding="utf-8"))
        return _HTMLVC(content="<h1>validation_center_console.html 未找到</h1>")
    print("方向5 验证中心页面已注册：/validation-center")
except Exception as _e:
    print(f"方向5 验证中心页面注册失败: {_e}")
%(end)s
''' % {"begin": _BEGIN, "end": _END}


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    app_py = os.path.join(here, "app.py")
    if not os.path.exists(app_py):
        print(f"[ERR] 找不到 {app_py}", file=sys.stderr)
        return 1

    with io.open(app_py, "r", encoding="utf-8") as f:
        content = f.read()

    if _BEGIN in content and _END in content:
        print("[SKIP] app.py 已注入过 PDF/验证 集成，无需重复操作。")
        return 0

    if not content.endswith("\n"):
        content += "\n"
    content += _BLOCK

    with io.open(app_py, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 已注入 方向3 PDF报告 + 方向5 验证中心 到 app.py")
    print("     - /api/v1/pdf-report       (40+ REST)")
    print("     - /report-center           (统一报告中心控制台)")
    print("     - /api/v1/validation       (40+ REST)")
    print("     - /validation-center       (验证中心控制台)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
