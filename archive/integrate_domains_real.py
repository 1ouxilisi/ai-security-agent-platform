# -*- coding: utf-8 -*-
"""integrate_domains_real.py — 方向2：所有领域真实可用（补齐短板）集成脚本。

注入 api_server/app.py：
  - 注册 domains_real_router（/api/v1/domains-real，60+端点）
  - 注册前端页面 /domains-real

用法：
    python integrate_domains_real.py
"""
from __future__ import annotations

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

MARKER = "domains_real_router"  # 幂等判断关键字

ROUTES_CODE = '''

# ============== 方向2：所有领域真实可用（补齐短板） ==============
try:
    from api_server.domains_real_routes import router as domains_real_router
    app.include_router(domains_real_router)
    log.info("方向2 所有领域真实可用路由已注册：/api/v1/domains-real（60+端点）")
except Exception as e:
    log.warning(f"方向2 domains_real_router 注册失败: {e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLR_DOMAINS_REAL
    @app.get("/domains-real", include_in_schema=False)
    async def _domains_real_console_page():
        _p = os.path.join(os.path.dirname(__file__), "domains_real_console.html")
        if os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLR_DOMAINS_REAL(content=_f.read())
        return _HTMLR_DOMAINS_REAL(content="<h1>领域真实可用控制台页面未找到</h1>")
    log.info("方向2 前端页面已注册：/domains-real")
except Exception as e:
    log.warning(f"方向2 前端页面注册失败: {e}")

'''


def inject_routes() -> bool:
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if MARKER in content:
        print("[INFO] 方向2 domains_real 路由已存在，跳过注入")
        return True
    anchor = "# ============== 全局异常处理器"
    if anchor not in content:
        print("[ERROR] 未找到全局异常处理器锚点")
        return False
    content = content.replace(anchor, ROUTES_CODE + "\n" + anchor)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 方向2 domains_real 路由注入 app.py 完成")
    return True


def verify_import() -> bool:
    """验证模块可导入"""
    try:
        from domains_real import (
            red_blue_real,
            supply_chain_real,
            devsecops_real,
            forensics_real,
            iot_ics_real,
            domains_real_dashboard,
        )
        print("[OK] domains_real 包所有模块导入成功")
        return True
    except Exception as e:
        print(f"[ERROR] 模块导入失败: {e}")
        return False


def verify_routes() -> bool:
    """验证路由模块可导入"""
    try:
        from api_server.domains_real_routes import router
        count = len(router.routes)
        print(f"[OK] domains_real_routes 导入成功，共 {count} 个路由")
        return True
    except Exception as e:
        print(f"[ERROR] 路由模块导入失败: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("方向2：所有领域真实可用（补齐短板）集成")
    print("=" * 60)
    verify_import()
    verify_routes()
    inject_routes()
    print("=" * 60)
    print("集成完成！启动后访问 http://localhost:8000/domains-real")
    print("=" * 60)
