# -*- coding: utf-8 -*-
"""
集成脚本 — 将 fp_optimizer_pro 和 llm_ultra 路由注入 app.py。

使用方式（在app.py末尾、全局异常处理器之前添加）：

# ============== 方向1 Pro + 方向3 Ultra ==============
try:
    from api_server.fp_optimizer_pro_routes import router as fp_pro_router
    app.include_router(fp_pro_router)
    log.info("方向1 Pro 误报率优化路由已注册：/api/v1/fp-optimizer-pro（32端点）")
except Exception as e:
    log.warning(f"方向1 Pro 路由注册失败: {e}")

try:
    from api_server.llm_ultra_routes import router as llm_ultra_router
    app.include_router(llm_ultra_router)
    log.info("方向3 LLM极致优化路由已注册：/api/v1/llm-ultra（38端点）")
except Exception as e:
    log.warning(f"方向3 LLM极致优化路由注册失败: {e}")

# 前端页面路由
try:
    from fastapi.responses import HTMLResponse as _HTMLR_FPLLM
    _PAGES_FPLLM = [
        ("/fp-optimizer-pro", "fp_optimizer_pro_console.html", "误报率优化Pro控制台"),
        ("/llm-ultra", "llm_ultra_console.html", "LLM极致优化控制台"),
    ]
    for _route, _fname, _desc in _PAGES_FPLLM:
        def _make_page_fpllm(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_fpllm():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_FPLLM(content=_f.read())
                return _HTMLR_FPLLM(content=f"<h1>{desc}页面未找到</h1>")
            return _page_fpllm
        _make_page_fpllm()
    log.info("方向1Pro+方向3 前端页面已注册：/fp-optimizer-pro /llm-ultra")
except Exception as e:
    log.warning(f"前端页面注册失败: {e}")
"""
print(__doc__)
