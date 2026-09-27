# -*- coding: utf-8 -*-
"""注入：方向1 内网渗透真实能力 + 方向2 移动安全真实能力。"""
import os, sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 方向1：内网渗透真实能力（20+端点） ==============
try:
    from api_server.internal_pentest_real_routes import router as internal_real_router
    app.include_router(internal_real_router)
    log.info("方向1 内网渗透真实能力路由已注册（Nmap/SMB/RPC/LDAP/Nuclei 真实执行）")
except Exception as e:
    log.warning(f"方向1 路由注册失败: {e}")

# ============== 方向2：移动安全真实能力（20+端点） ==============
try:
    from api_server.mobile_real_routes import router as mobile_real_router
    app.include_router(mobile_real_router)
    log.info("方向2 移动安全真实分析路由已注册（APK真实解析+权限风险+静态漏洞）")
except Exception as e:
    log.warning(f"方向2 路由注册失败: {e}")

# ============== 新增控制台页面 ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_REAL
    _PAGES_REAL = [
        ("/internal-pentest-real", "internal_pentest_real_console.html", "内网渗透真实能力控制台"),
        ("/mobile-real", "mobile_real_console.html", "移动安全真实分析控制台"),
    ]
    for _route, _fname, _desc in _PAGES_REAL:
        def _make_page(_fname=_fname, _desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page():
                _p = os.path.join(os.path.dirname(__file__), _fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as f:
                        return _HTMLR_REAL(content=f.read())
                return _HTMLR_REAL(content=f"<h1>{_desc}页面未找到</h1>")
            return _page
        _make_page()
    log.info("控制台页面已注册：/internal-pentest-real /mobile-real")
except Exception as e:
    log.warning(f"控制台页面注册失败: {e}")

'''

MARKER = "# ============== 全局异常处理器"


def inject():
    if not os.path.exists(APP_PY):
        print("[ERROR] app.py 不存在:", APP_PY)
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "方向1：内网渗透真实能力" in content:
        print("[INFO] 已注入，跳过")
        return True
    if MARKER not in content:
        print("[ERROR] 未找到注入标记")
        return False
    content = content.replace(MARKER, ROUTES_CODE + "\n" + MARKER)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 路由已注入 app.py")
    return True


if __name__ == "__main__":
    inject()
