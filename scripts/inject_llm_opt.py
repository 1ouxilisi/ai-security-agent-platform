# -*- coding: utf-8 -*-
"""
scripts/inject_llm_opt.py — 方向5 LLM 接入优化：app.py 集成注入片段

任务要求「不要修改 app.py，由集成脚本统一注入」。
本文件给出应注入到 api_server/app.py 的代码片段（放在已有 LLM-CONFIG-INTEGRATION
块之后即可）。真正执行时由集成脚本读取本文件并 patch 到 app.py。

注入内容（两部分）：
    1. 路由注册：api_server.llm_opt_routes.router
    2. 前端页面：GET /llm-optimization -> llm_opt_console.html
"""
from __future__ import annotations

import os
from pathlib import Path

# 注入片段（与 app.py 中已有 try/except 风格一致）
INJECT_SNIPPET = '''

# >>> LLM-OPT-INTEGRATION (方向5: LLM接入优化)
try:
    from api_server.llm_opt_routes import router as llm_opt_router
    app.include_router(llm_opt_router)
    log.info("方向5 LLM接入优化路由已注册：/api/v1/llm-opt/*，共17个端点")
except Exception as _e_llm_opt:
    log.warning(f"方向5 LLM接入优化路由注册失败: {_e_llm_opt}")

try:
    from fastapi.responses import HTMLResponse as _HTMLR_LLM_OPT
    @app.get("/llm-optimization", include_in_schema=False)
    async def _llm_opt_page():
        _p = os.path.join(os.path.dirname(__file__), "llm_opt_console.html")
        if os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLR_LLM_OPT(content=_f.read())
        return _HTMLR_LLM_OPT(content="<h1>LLM 优化控制台未找到</h1>")
    log.info("方向5 LLM优化前端页面已注册：/llm-optimization")
except Exception as _e_llm_opt_page:
    log.warning(f"方向5 LLM优化前端页面注册失败: {_e_llm_opt_page}")
# <<< LLM-OPT-INTEGRATION
'''


def inject(app_py_path: str | None = None) -> str:
    """把注入片段追加到 app.py 末尾（若尚未注入过）。"""
    if app_py_path is None:
        root = Path(__file__).resolve().parent.parent
        app_py_path = str(root / "api_server" / "app.py")

    with open(app_py_path, "r", encoding="utf-8") as f:
        content = f.read()

    if "LLM-OPT-INTEGRATION" in content:
        return f"[SKIP] {app_py_path} 已包含方向5注入块"

    with open(app_py_path, "a", encoding="utf-8") as f:
        f.write(INJECT_SNIPPET)
    return f"[OK] 已注入方向5集成块到 {app_py_path}"


if __name__ == "__main__":
    # 打印注入片段，便于人工 review
    print(INJECT_SNIPPET)
    print("\n--- 如需自动注入，调用 inject() ---")
