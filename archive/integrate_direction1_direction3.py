# -*- coding: utf-8 -*-
"""方向1（技术深度大升级）+ 方向3（真实可用性大升级）集成与验证脚本。

用法:
    python integrate_direction1_direction3.py
"""
from __future__ import annotations

import importlib
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 方向1：技术深度大升级路由（37 端点） ==============
try:
    from api_server.tech_deep_routes import router as tech_deep_router
    app.include_router(tech_deep_router)
    log.info("方向1 技术深度大升级路由已注册：Web做深/内网做实/移动做实/云做实，共37个端点")
except Exception as e:
    log.warning(f"方向1 技术深度路由注册失败: {e}")


# ============== 方向3：真实可用性大升级路由（26 端点） ==============
try:
    from api_server.real_usability_routes import router as real_usability_router
    app.include_router(real_usability_router)
    log.info("方向3 真实可用性大升级路由已注册：误报率/E2E/靶场/质量，共26个端点")
except Exception as e:
    log.warning(f"方向3 真实可用性路由注册失败: {e}")


# ============== 方向1+3：新前端页面路由（2个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_D1D3
    _PAGES_D1D3 = [
        ("/tech-deep", "tech_deep_console.html", "技术深度大升级控制台"),
        ("/real-usability", "real_usability_console.html", "真实可用性大升级控制台"),
    ]
    for _route, _fname, _desc in _PAGES_D1D3:
        def _make_page_handler_d1d3(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_d1d3():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_D1D3(content=_f.read())
                return _HTMLR_D1D3(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_d1d3
        _make_page_handler_d1d3()
    log.info("方向1+3 前端页面已注册：/tech-deep /real-usability")
except Exception as e:
    log.warning(f"方向1+3 前端页面注册失败: {e}")

'''


def inject_routes() -> bool:
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "方向1：技术深度大升级路由" in content:
        print("[INFO] 方向1/3 路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 方向1/3 路由注册代码已注入 app.py")
    return True


def verify_files() -> bool:
    print("\n" + "=" * 60)
    print("【文件存在验证】")
    print("=" * 60)
    expected = [
        "tech_deep_upgrade/__init__.py",
        "tech_deep_upgrade/web_pentest_deep.py",
        "tech_deep_upgrade/internal_pentest_deep.py",
        "tech_deep_upgrade/mobile_security_deep.py",
        "tech_deep_upgrade/cloud_security_deep.py",
        "tech_deep_upgrade/tech_dashboard.py",
        "real_usability/__init__.py",
        "real_usability/fp_optimizer.py",
        "real_usability/e2e_runner.py",
        "real_usability/range_manager.py",
        "real_usability/quality_check.py",
        "real_usability/usability_dashboard.py",
        "api_server/tech_deep_routes.py",
        "api_server/real_usability_routes.py",
        "api_server/tech_deep_console.html",
        "api_server/real_usability_console.html",
    ]
    missing = []
    total_lines = 0
    for fpath in expected:
        full = os.path.join(PROJECT_ROOT, fpath)
        if os.path.exists(full):
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                lines = len(f.readlines())
            total_lines += lines
            print(f"  [OK] {fpath} ({lines} 行)")
        else:
            missing.append(fpath)
            print(f"  [MISSING] {fpath}")
    print(f"\n总计: {len(expected)} 个文件, 存在: {len(expected)-len(missing)}, "
          f"缺失: {len(missing)}, 总代码行数: {total_lines}")
    return len(missing) == 0


def verify_imports() -> bool:
    print("\n" + "=" * 60)
    print("【模块导入验证】")
    print("=" * 60)
    modules = [
        "tech_deep_upgrade",
        "tech_deep_upgrade.web_pentest_deep",
        "tech_deep_upgrade.internal_pentest_deep",
        "tech_deep_upgrade.mobile_security_deep",
        "tech_deep_upgrade.cloud_security_deep",
        "tech_deep_upgrade.tech_dashboard",
        "real_usability",
        "real_usability.fp_optimizer",
        "real_usability.e2e_runner",
        "real_usability.range_manager",
        "real_usability.quality_check",
        "real_usability.usability_dashboard",
        "api_server.tech_deep_routes",
        "api_server.real_usability_routes",
    ]
    passed = failed = 0
    for mod_name in modules:
        try:
            importlib.import_module(mod_name)
            print(f"  [OK] {mod_name}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {mod_name}: {e}")
            failed += 1
    print(f"\n总计: {len(modules)} 个模块, 通过: {passed}, 失败: {failed}")
    return failed == 0


def verify_endpoints() -> bool:
    print("\n" + "=" * 60)
    print("【API 端点计数】")
    print("=" * 60)
    checks = [
        ("api_server.tech_deep_routes", "tech_deep", 30),
        ("api_server.real_usability_routes", "real_usability", 25),
    ]
    all_ok = True
    for mod_name, label, expected in checks:
        try:
            mod = importlib.import_module(mod_name)
            router = getattr(mod, "router", None)
            if router:
                cnt = len(getattr(router, "routes", []))
                ok_flag = cnt >= expected
                print(f"  [{'OK' if ok_flag else 'WARN'}] {label}: "
                      f"{cnt} 个端点 (预期 >= {expected})")
                if not ok_flag:
                    all_ok = False
        except Exception as e:
            print(f"  [FAIL] {mod_name}: {e}")
            all_ok = False
    return all_ok


def verify_html() -> bool:
    print("\n" + "=" * 60)
    print("【前端页面验证】")
    print("=" * 60)
    files = [
        "api_server/tech_deep_console.html",
        "api_server/real_usability_console.html",
    ]
    ok_cnt = 0
    for f in files:
        full = os.path.join(PROJECT_ROOT, f)
        if os.path.exists(full):
            with open(full, "r", encoding="utf-8") as fh:
                c = fh.read()
            if "<html" in c.lower() and "<script" in c.lower() \
               and len(c) > 3000:
                print(f"  [OK] {f} ({len(c)} 字节)")
                ok_cnt += 1
            else:
                print(f"  [WARN] {f}: 内容不完整 ({len(c)} 字节)")
        else:
            print(f"  [MISSING] {f}")
    return ok_cnt == len(files)


def verify_unit() -> bool:
    print("\n" + "=" * 60)
    print("【单元冒烟】")
    print("=" * 60)
    try:
        from tech_deep_upgrade import FINGERPRINT_DB, TECH_SCORE_BASELINE
        from real_usability import TARGET_RANGES, USABILITY_SCORE_BASELINE
        from real_usability.quality_check import QualityChecker

        assert len(FINGERPRINT_DB) >= 100, "指纹库 < 100"
        print(f"  [OK] 指纹库 {len(FINGERPRINT_DB)} 条")
        assert len(TARGET_RANGES) == 10, "靶场 != 10"
        print(f"  [OK] 靶场 {len(TARGET_RANGES)} 个")

        qc = QualityChecker()
        r = qc.check_finding({"name": "SQLi", "severity": "critical"})
        print(f"  [OK] 质量检查评分: {r['score']}/100 ({r['grade']})")

        print(f"  [OK] 技术深度: {TECH_SCORE_BASELINE['before']} → "
              f"{TECH_SCORE_BASELINE['after']}")
        print(f"  [OK] 可用性: {USABILITY_SCORE_BASELINE['before']} → "
              f"{USABILITY_SCORE_BASELINE['after']}")
        return True
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  [FAIL] {e}")
        return False


def main() -> int:
    print("=" * 60)
    print("方向1（技术深度大升级）+ 方向3（真实可用性大升级）")
    print("集成与验证")
    print("=" * 60)
    files_ok = verify_files()
    inj_ok = inject_routes()
    imports_ok = verify_imports()
    ep_ok = verify_endpoints()
    html_ok = verify_html()
    unit_ok = verify_unit()

    print("\n" + "=" * 60)
    print("验证总结")
    print("=" * 60)
    print(f"  文件存在: {'PASS' if files_ok else 'FAIL'}")
    print(f"  路由注入: {'PASS' if inj_ok else 'FAIL'}")
    print(f"  模块导入: {'PASS' if imports_ok else 'FAIL'}")
    print(f"  API端点:  {'PASS' if ep_ok else 'FAIL'}")
    print(f"  前端页面: {'PASS' if html_ok else 'FAIL'}")
    print(f"  单元冒烟: {'PASS' if unit_ok else 'FAIL'}")
    all_pass = all([files_ok, inj_ok, imports_ok, ep_ok, html_ok, unit_ok])
    print(f"\n  总体结果: {'ALL PASS' if all_pass else 'HAS FAILURES'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
