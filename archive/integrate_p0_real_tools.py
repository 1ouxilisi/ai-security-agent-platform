# -*- coding: utf-8 -*-
"""P0 修复集成脚本：注入真实工具路由 + 误报率验证路由到 api_server/app.py。"""
import os, sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

MARK = "# P0-1/P0-2 real tools & fp-rate routes"

ROUTES_CODE = '''

# ============== ''' + MARK + ''' ==============
try:
    from api_server.fp_rate_routes import tools_router as _p0_tools_router
    app.include_router(_p0_tools_router)
    log.info("P0-1 真实工具路由已注册: /api/v1/real-tools-deep/nmap|sqlmap|nuclei|nikto|dirb|dirsearch")
except Exception as e:
    log.warning(f"P0-1 真实工具路由注册失败: {e}")

try:
    from api_server.fp_rate_routes import router as _p0_fp_router
    app.include_router(_p0_fp_router)
    log.info("P0-2 误报率验证路由已注册: /api/v1/real-validation/fp-test/*")
except Exception as e:
    log.warning(f"P0-2 误报率验证路由注册失败: {e}")

try:
    from fastapi.responses import HTMLResponse as _HTML_P0
    @app.get("/fp-rate-console", include_in_schema=False)
    async def _fp_rate_console_page():
        _p = os.path.join(os.path.dirname(__file__), "fp_rate_console.html")
        if os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTML_P0(content=_f.read())
        return _HTML_P0(content="<h1>误报率验证控制台页面未找到</h1>")
    log.info("P0-2 误报率验证控制台已注册: /fp-rate-console")
except Exception as e:
    log.warning(f"P0-2 控制台页面注册失败: {e}")

'''


def inject():
    if not os.path.exists(APP_PY):
        print("[ERROR] app.py not found:", APP_PY)
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if MARK in content:
        print("[INFO] P0 路由已存在，跳过注入")
        return True
    anchor = "# ============== 全局异常处理器（不暴露堆栈，统一返回 JSON 500） =============="
    if anchor not in content:
        print("[ERROR] 未找到注入锚点")
        return False
    content = content.replace(anchor, ROUTES_CODE + "\n" + anchor)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] P0 路由已注入 app.py")
    return True


def verify():
    print("\n=== 模块导入验证 ===")
    mods = [
        "real_tools_deep.nmap_deep", "real_tools_deep.sqlmap_deep",
        "real_tools_deep.other_tools", "real_validation.fp_rate",
        "api_server.fp_rate_routes",
    ]
    ok = 0
    for m in mods:
        try:
            __import__(m)
            print("  [OK]", m)
            ok += 1
        except Exception as e:
            print("  [FAIL]", m, "->", e)
    print(f"导入通过 {ok}/{len(mods)}")
    return ok == len(mods)


if __name__ == "__main__":
    inject()
    verify()
