# -*- coding: utf-8 -*-
"""第22轮升级集成与验证脚本（最终轮）"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第22轮升级方向1：一键Demo模式路由（30+端点） ==============
try:
    from api_server.demo_mode_routes import router as demo_mode_router
    app.include_router(demo_mode_router)
    log.info("第22轮一键Demo模式路由已注册：Demo数据集/自动演示/交互引导/快速体验/品牌定制/运营控制台，共30+个端点")
except Exception as e:
    log.warning(f"第22轮一键Demo模式路由注册失败: {e}")


# ============== 第22轮升级方向2：真实靶场集成路由（30+端点） ==============
try:
    from api_server.range_integration_routes import router as range_integration_router
    app.include_router(range_integration_router)
    log.info("第22轮真实靶场集成路由已注册：靶场管理/漏洞靶场/自动扫描/报告生成/学习训练/运营控制台，共30+个端点")
except Exception as e:
    log.warning(f"第22轮真实靶场集成路由注册失败: {e}")


# ============== 第22轮升级方向3：性能最终优化路由（30+端点） ==============
try:
    from api_server.performance_final_routes import router as performance_final_router
    app.include_router(performance_final_router)
    log.info("第22轮性能最终优化路由已注册：全链路压测/瓶颈修复/启动优化/API优化/内存优化/监控告警，共30+个端点")
except Exception as e:
    log.warning(f"第22轮性能最终优化路由注册失败: {e}")


# ============== 第22轮升级方向4：安全最终加固路由（30+端点） ==============
try:
    from api_server.security_final_routes import router as security_final_router
    app.include_router(security_final_router)
    log.info("第22轮安全最终加固路由已注册：自身渗透/依赖扫描/基线检查/审计监控/数据安全/安全控制台，共30+个端点")
except Exception as e:
    log.warning(f"第22轮安全最终加固路由注册失败: {e}")


# ============== 第22轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR22
    _PAGES_R22 = [
        ("/demo-mode", "demo_mode_console.html", "一键Demo模式控制台"),
        ("/range-integration", "range_integration_console.html", "真实靶场集成控制台"),
        ("/performance-final", "performance_final_console.html", "性能最终优化控制台"),
        ("/security-final", "security_final_console.html", "安全最终加固控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R22:
        def _make_page_handler_r22(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r22():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR22(content=_f.read())
                return _HTMLR22(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r22
        _make_page_handler_r22()
    log.info("第22轮新前端页面已注册：/demo-mode /range-integration /performance-final /security-final")
except Exception as e:
    log.warning(f"第22轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第22轮升级方向1：一键Demo模式路由" in content:
        print("[INFO] 第22轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第22轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "demo_mode.demo_dataset", "demo_mode.demo_engine",
        "demo_mode.interactive_guide", "demo_mode.quick_experience",
        "demo_mode.demo_branding", "demo_mode.demo_dashboard",
        "range_integration.range_manager", "range_integration.vuln_range",
        "range_integration.auto_scanner", "range_integration.range_report",
        "range_integration.range_learning", "range_integration.range_dashboard",
        "performance_final.load_testing", "performance_final.bottleneck_fixer",
        "performance_final.startup_optimizer", "performance_final.api_optimizer",
        "performance_final.memory_optimizer", "performance_final.perf_dashboard",
        "security_final.self_pentest_final", "security_final.dep_vuln_final",
        "security_final.baseline_final", "security_final.audit_monitor",
        "security_final.data_security_final", "security_final.security_dashboard_final",
        "api_server.demo_mode_routes", "api_server.range_integration_routes",
        "api_server.performance_final_routes", "api_server.security_final_routes",
    ]
    results = []
    passed = failed = 0
    for mod_name in modules:
        try:
            importlib.import_module(mod_name)
            results.append(f"  [OK] {mod_name}")
            passed += 1
        except Exception as e:
            results.append(f"  [FAIL] {mod_name}: {e}")
            failed += 1
    print(f"\n=== 模块导入验证 ===")
    print(f"总计: {len(modules)} 个模块, 通过: {passed}, 失败: {failed}")
    for r in results:
        print(r)
    return failed == 0


def verify_files_exist():
    expected = [
        "demo_mode/__init__.py", "demo_mode/demo_dataset.py",
        "demo_mode/demo_engine.py", "demo_mode/interactive_guide.py",
        "demo_mode/quick_experience.py", "demo_mode/demo_branding.py",
        "demo_mode/demo_dashboard.py",
        "range_integration/__init__.py", "range_integration/range_manager.py",
        "range_integration/vuln_range.py", "range_integration/auto_scanner.py",
        "range_integration/range_report.py", "range_integration/range_learning.py",
        "range_integration/range_dashboard.py",
        "performance_final/__init__.py", "performance_final/load_testing.py",
        "performance_final/bottleneck_fixer.py", "performance_final/startup_optimizer.py",
        "performance_final/api_optimizer.py", "performance_final/memory_optimizer.py",
        "performance_final/perf_dashboard.py",
        "security_final/__init__.py", "security_final/self_pentest_final.py",
        "security_final/dep_vuln_final.py", "security_final/baseline_final.py",
        "security_final/audit_monitor.py", "security_final/data_security_final.py",
        "security_final/security_dashboard_final.py",
        "api_server/demo_mode_routes.py", "api_server/range_integration_routes.py",
        "api_server/performance_final_routes.py", "api_server/security_final_routes.py",
        "api_server/demo_mode_console.html", "api_server/range_integration_console.html",
        "api_server/performance_final_console.html", "api_server/security_final_console.html",
    ]
    print(f"\n=== 文件存在验证 ===")
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
    print(f"\n总计: {len(expected)} 个文件, 存在: {len(expected)-len(missing)}, 缺失: {len(missing)}, 总代码行数: {total_lines} 行")
    return len(missing) == 0


def verify_api_routes():
    print(f"\n=== API路由验证 ===")
    route_mods = [
        ("api_server.demo_mode_routes", "demo_mode", 30),
        ("api_server.range_integration_routes", "range_integration", 30),
        ("api_server.performance_final_routes", "performance_final", 30),
        ("api_server.security_final_routes", "security_final", 30),
    ]
    all_ok = True
    total = 0
    for mod_name, prefix, expected in route_mods:
        try:
            mod = importlib.import_module(mod_name)
            router = getattr(mod, "router", None)
            if router is None:
                print(f"  [FAIL] {mod_name}: 未找到router")
                all_ok = False
                continue
            routes = getattr(router, "routes", [])
            cnt = len(routes)
            total += cnt
            status = "OK" if cnt >= expected else "WARN"
            if cnt < expected:
                all_ok = False
            print(f"  [{status}] {mod_name}: {cnt} 个端点 (预期 >= {expected})")
        except Exception as e:
            print(f"  [FAIL] {mod_name}: {e}")
            all_ok = False
    print(f"  第22轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/demo_mode_console.html",
        "api_server/range_integration_console.html",
        "api_server/performance_final_console.html",
        "api_server/security_final_console.html",
    ]
    all_ok = True
    for page in pages:
        full = os.path.join(PROJECT_ROOT, page)
        if not os.path.exists(full):
            print(f"  [FAIL] {page}: 文件不存在")
            all_ok = False
            continue
        try:
            with open(full, "r", encoding="utf-8") as f:
                content = f.read()
            size = len(content)
            ok = size > 5000 and "<html" in content.lower() and "<script" in content.lower()
            if ok:
                print(f"  [OK] {page} ({size} 字节)")
            else:
                print(f"  [WARN] {page} ({size}B): 内容不完整")
                all_ok = False
        except UnicodeDecodeError:
            print(f"  [FAIL] {page}: UTF-8编码错误")
            all_ok = False
    return all_ok


def verify_app_import():
    print(f"\n=== app.py导入验证 ===")
    try:
        for mod in list(sys.modules.keys()):
            if mod.startswith("api_server") or mod.startswith("demo_mode") or mod.startswith("range_integration") or mod.startswith("performance_final") or mod.startswith("security_final"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        print(f"  [OK] app.py导入成功，总路由数: {len(routes)}")
        r22_prefixes = ["/api/v1/demo-mode", "/api/v1/range-integration", "/api/v1/performance-final", "/api/v1/security-final"]
        for prefix in r22_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        page_routes = ["/demo-mode", "/range-integration", "/performance-final", "/security-final"]
        for pr in page_routes:
            found = any(getattr(r, "path", "") == pr for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 前端页面 {pr}: {'已注册' if found else '未找到'}")
        return True
    except Exception as e:
        print(f"  [FAIL] app.py导入失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print("=" * 60)
    print("第22轮升级集成与验证脚本（最终轮）")
    print("=" * 60)
    files_ok = verify_files_exist()
    routes_ok = inject_routes()
    imports_ok = verify_imports()
    api_ok = verify_api_routes()
    html_ok = verify_html_pages()
    app_ok = verify_app_import()
    print("\n" + "=" * 60)
    print("验证总结")
    print("=" * 60)
    print(f"  文件存在: {'PASS' if files_ok else 'FAIL'}")
    print(f"  路由注入: {'PASS' if routes_ok else 'FAIL'}")
    print(f"  模块导入: {'PASS' if imports_ok else 'FAIL'}")
    print(f"  API路由:  {'PASS' if api_ok else 'FAIL'}")
    print(f"  前端页面: {'PASS' if html_ok else 'FAIL'}")
    print(f"  app导入:  {'PASS' if app_ok else 'FAIL'}")
    all_pass = files_ok and routes_ok and imports_ok and api_ok and html_ok and app_ok
    print(f"\n  总体结果: {'ALL PASS' if all_pass else 'HAS FAILURES'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
