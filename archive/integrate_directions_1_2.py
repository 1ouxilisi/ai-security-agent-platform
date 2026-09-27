# -*- coding: utf-8 -*-
"""integrate_directions_1_2.py — 方向1（误报率验证做实）+ 方向2（内网渗透深度做实）集成。

注入 api_server/app.py：
  - 注册 fp_validation_router（/api/v1/fp-validation）
  - 注册 internal_deep_router（/api/v1/internal-deep）
  - 注册前端页面 /fp-validation 与 /internal-deep
"""
from __future__ import annotations

import importlib
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

MARKER = "fp_validation_router"  # 幂等判断关键字

ROUTES_CODE = '''

# ============== 方向1+方向2：误报率验证做实 + 内网渗透深度做实 ==============
try:
    from api_server.fp_validation_routes import router as fp_validation_router
    app.include_router(fp_validation_router)
    log.info("方向1 误报率验证做实路由已注册：/api/v1/fp-validation（20+端点）")
except Exception as e:
    log.warning(f"方向1 fp_validation_router 注册失败: {e}")

try:
    from api_server.internal_deep_routes import router as internal_deep_router
    app.include_router(internal_deep_router)
    log.info("方向2 内网渗透深度做实路由已注册：/api/v1/internal-deep（25+端点）")
except Exception as e:
    log.warning(f"方向2 internal_deep_router 注册失败: {e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLR_DIR12
    _PAGES_DIR12 = [
        ("/fp-validation", "fp_validation_console.html", "误报率验证控制台"),
        ("/internal-deep", "internal_deep_console.html", "内网渗透深度控制台"),
    ]
    for _route, _fname, _desc in _PAGES_DIR12:
        def _make_page_handler_dir12(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_dir12():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_DIR12(content=_f.read())
                return _HTMLR_DIR12(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_dir12
        _make_page_handler_dir12()
    log.info("方向1+方向2 前端页面已注册：/fp-validation /internal-deep")
except Exception as e:
    log.warning(f"方向1+方向2 前端页面注册失败: {e}")

'''


def inject_routes() -> bool:
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if MARKER in content:
        print("[INFO] 方向1+方向2 路由已存在，跳过注入")
        return True
    anchor = "# ============== 全局异常处理器"
    if anchor not in content:
        print("[ERROR] 未找到全局异常处理器锚点")
        return False
    content = content.replace(anchor, ROUTES_CODE + "\n" + anchor)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 方向1+方向2 路由注入 app.py 完成")
    return True


def verify_files() -> bool:
    expected = [
        "fp_validation/__init__.py",
        "fp_validation/range_repository.py",
        "fp_validation/fp_runner.py",
        "fp_validation/metrics_calculator.py",
        "fp_validation/rule_optimizer.py",
        "fp_validation/fp_report.py",
        "fp_validation/fp_dashboard.py",
        "internal_deep/__init__.py",
        "internal_deep/smb_enum.py",
        "internal_deep/ad_query.py",
        "internal_deep/cred_extract.py",
        "internal_deep/lateral_movement.py",
        "internal_deep/privesc_detector.py",
        "internal_deep/attack_chain.py",
        "internal_deep/internal_deep_dashboard.py",
        "api_server/fp_validation_routes.py",
        "api_server/internal_deep_routes.py",
        "api_server/fp_validation_console.html",
        "api_server/internal_deep_console.html",
    ]
    missing = []
    for rel in expected:
        p = os.path.join(PROJECT_ROOT, rel)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                n = len(f.readlines())
            print(f"  [OK] {rel} ({n} 行)")
        else:
            missing.append(rel)
            print(f"  [MISSING] {rel}")
    return not missing


def verify_imports() -> bool:
    modules = [
        "fp_validation",
        "fp_validation.range_repository",
        "fp_validation.fp_runner",
        "fp_validation.metrics_calculator",
        "fp_validation.rule_optimizer",
        "fp_validation.fp_report",
        "fp_validation.fp_dashboard",
        "internal_deep",
        "internal_deep.smb_enum",
        "internal_deep.ad_query",
        "internal_deep.cred_extract",
        "internal_deep.lateral_movement",
        "internal_deep.privesc_detector",
        "internal_deep.attack_chain",
        "internal_deep.internal_deep_dashboard",
        "api_server.fp_validation_routes",
        "api_server.internal_deep_routes",
    ]
    failed = 0
    for m in modules:
        try:
            importlib.import_module(m)
            print(f"  [OK] {m}")
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] {m}: {e}")
            failed += 1
    return failed == 0


def verify_endpoints() -> bool:
    checks = [
        ("api_server.fp_validation_routes", 20),
        ("api_server.internal_deep_routes", 25),
    ]
    ok = True
    for mod, need in checks:
        try:
            m = importlib.import_module(mod)
            r = getattr(m, "router", None)
            cnt = len(getattr(r, "routes", [])) if r else 0
            flag = cnt >= need
            print(f"  [{'OK' if flag else 'WARN'}] {mod}: {cnt} 端点 (>= {need})")
            if not flag:
                ok = False
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] {mod}: {e}")
            ok = False
    return ok


def main() -> int:
    print("=" * 60)
    print("方向1（误报率验证做实）+ 方向2（内网渗透深度做实）集成")
    print("=" * 60)
    inject_routes()
    print("\n[1] 文件存在校验")
    verify_files()
    print("\n[2] 模块导入校验")
    verify_imports()
    print("\n[3] 端点数量校验")
    verify_endpoints()
    print("\n[DONE]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
