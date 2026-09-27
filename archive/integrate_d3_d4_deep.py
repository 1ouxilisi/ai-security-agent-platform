# -*- coding: utf-8 -*-
"""
方向3 + 方向4 集成脚本：移动安全深度做实 v2 + 云安全深度做实。

注入内容：
    1) cloud_deep_router（前缀 /api/v1/cloud-deep，30+ 端点）
    2) 前端页面 /mobile-deep-v2 与 /cloud-deep

mobile_deep_router 已在 app.py 注册（第20轮），本次 v2 端点直接挂在同一 router 上，
无需重复 include。
"""
from __future__ import annotations

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

MARKER = "# ============== 全局异常处理器"

ROUTES_CODE = '''

# ============== 方向3+4：移动安全深度做实 v2 / 云安全深度做实 ==============
try:
    from api_server.cloud_deep_routes import router as cloud_deep_router
    app.include_router(cloud_deep_router)
    log.info("方向4 云安全深度路由已注册：/api/v1/cloud-deep，30+ 端点")
except Exception as e:
    log.warning(f"方向4 云安全深度路由注册失败: {e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLR_D34
    _PAGES_D34 = [
        ("/mobile-deep-v2", "mobile_deep_console.html", "移动安全深度控制台 v2"),
        ("/cloud-deep", "cloud_deep_console.html", "云安全深度控制台"),
    ]
    for _route, _fname, _desc in _PAGES_D34:
        def _make_page_d34(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_d34():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_D34(content=_f.read())
                return _HTMLR_D34(content=f"<h1>{desc}页面未找到</h1>")
            return _page_d34
        _make_page_d34()
    log.info("方向3+4 新前端页面已注册：/mobile-deep-v2 /cloud-deep")
except Exception as e:
    log.warning(f"方向3+4 新前端页面注册失败: {e}")

'''


def inject():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "方向3+4：移动安全深度做实 v2" in content:
        print("[INFO] 已注入，跳过")
        return True
    if MARKER not in content:
        print("[ERROR] 未找到注入标记")
        return False
    content = content.replace(MARKER, ROUTES_CODE + "\n" + MARKER)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 已注入 app.py")
    return True


def verify():
    expected = [
        "mobile_deep/__init__.py",
        "mobile_deep/apk_deep_analyzer.py",
        "mobile_deep/static_code_scanner.py",
        "mobile_deep/permission_risk_rater.py",
        "mobile_deep/vuln_detector.py",
        "mobile_deep/dynamic_framework.py",
        "mobile_deep/mobile_deep_dashboard.py",
        "cloud_deep/__init__.py",
        "cloud_deep/cloud_client.py",
        "cloud_deep/config_checker.py",
        "cloud_deep/asset_discovery.py",
        "cloud_deep/risk_rater.py",
        "cloud_deep/cloud_deep_dashboard.py",
        "api_server/mobile_deep_routes.py",
        "api_server/mobile_deep_console.html",
        "api_server/cloud_deep_routes.py",
        "api_server/cloud_deep_console.html",
    ]
    miss = []
    for rel in expected:
        p = os.path.join(PROJECT_ROOT, rel)
        if not os.path.exists(p):
            miss.append(rel)
    print(f"[VERIFY] files ok: {len(expected)-len(miss)}/{len(expected)}")
    for m in miss:
        print(f"  MISSING: {m}")
    return not miss


if __name__ == "__main__":
    ok1 = inject()
    ok2 = verify()
    sys.exit(0 if ok1 and ok2 else 1)
