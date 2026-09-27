# -*- coding: utf-8 -*-
"""
install_llm_integration.py — 把 LLM 配置路由与 /llm-config 页面幂等注入 app.py

按需求「不要手改 app.py，由集成脚本统一注入」：
    - 读取 api_server/app.py（UTF-8，自动兼容 CRLF/LF）
    - 若已含标记 # >>> LLM-CONFIG-INTEGRATION 则跳过（幂等）
    - 否则在「全局异常处理器」锚点前插入 try/except 注册块
    - 锚点缺失时回退到 def run_api_server 之前

运行：python install_llm_integration.py
"""
from __future__ import annotations
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent / "api_server" / "app.py"
MARKER = "# >>> LLM-CONFIG-INTEGRATION"

_BLOCK_TMPL = '''
@@MARKER@@
try:
    from api_server.llm_config_routes import router as llm_config_router
    app.include_router(llm_config_router)
    log.info("LLM配置路由已注册：状态/保存/连接测试/AI对话/漏洞分析/修复方案/提供商，共7个端点")
except Exception as _e_llm_cfg:
    log.warning(f"LLM配置路由注册失败: {_e_llm_cfg}")


try:
    from fastapi.responses import HTMLResponse as _HTMLR_LLM
    @app.get("/llm-config", include_in_schema=False)
    async def _llm_config_page():
        _p = os.path.join(os.path.dirname(__file__), "llm_config_console.html")
        if os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLR_LLM(content=_f.read())
        return _HTMLR_LLM(content="<h1>LLM 配置页面未找到</h1>")
    log.info("LLM配置前端页面已注册：/llm-config")
except Exception as _e_llm_page:
    log.warning(f"LLM配置前端页面注册失败: {_e_llm_page}")
# <<< LLM-CONFIG-INTEGRATION
'''
BLOCK = _BLOCK_TMPL.replace("@@MARKER@@", MARKER)

ANCHORS = [
    "# ============== 全局异常处理器",
    "# ============== 鍏ㄥ眬寮傚父澶勭悊",  # GBK 误写兜底（不会命中，仅占位）
    "def run_api_server",
]


def main() -> int:
    if not APP.exists():
        print(f"[FAIL] 未找到 {APP}")
        return 1

    raw = APP.read_bytes()
    crlf = b"\r\n" in raw
    text = raw.decode("utf-8")

    if MARKER in text:
        print("[SKIP] app.py 已注入过 LLM 配置集成，无需重复")
        return 0

    block = BLOCK.replace("\n", "\r\n") if crlf else BLOCK

    # 找锚点：优先「全局异常处理器」注释行
    idx = -1
    anchor_used = None
    for a in ["全局异常处理器", "def run_api_server"]:
        i = text.find(a)
        if i != -1:
            idx = i
            anchor_used = a
            break

    if idx == -1:
        # 兜底：追加到文件末尾
        text = text.rstrip() + "\n\n" + block
        print("[OK] 未找到锚点，已追加到 app.py 末尾")
    else:
        # 回退到该锚点所在行的行首
        line_start = text.rfind("\n", 0, idx) + 1
        text = text[:line_start] + block + "\n" + text[line_start:]
        print(f"[OK] 已在锚点「{anchor_used}」前注入集成块")

    APP.write_bytes(text.encode("utf-8"))
    print(f"[DONE] app.py 已更新（CRLF={crlf}），新增路由 + /llm-config 页面")
    return 0


if __name__ == "__main__":
    sys.exit(main())
