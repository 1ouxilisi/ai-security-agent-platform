# -*- coding: utf-8 -*-
"""方向3+方向4 集成与验证脚本：极致用户体验 + 性能极致优化。

用法: python integrate_d3_d4_super_ux_perf.py
"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 方向3：极致用户体验（超级首页）路由（26 端点） ==============
try:
    from api_server.super_homepage_routes import router as super_homepage_router
    app.include_router(super_homepage_router)
    log.info("方向3 超级首页路由已注册：首页聚合/智能引导/全局搜索/快速操作/主题导航，共26个端点")
except Exception as e:
    log.warning(f"方向3 超级首页路由注册失败: {e}")


# ============== 方向4：性能极致优化路由（30 端点） ==============
try:
    from api_server.perf_ultra_routes import router as perf_ultra_router
    app.include_router(perf_ultra_router)
    log.info("方向4 性能极致优化路由已注册：启动/缓存/队列/DB/监控/静态，共30个端点")
except Exception as e:
    log.warning(f"方向4 性能极致优化路由注册失败: {e}")


# ============== 方向3+4：新前端页面路由（2个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_D34
    _PAGES_D34 = [
        ("/super-home", "super_homepage_console.html", "超级首页（极致用户体验）"),
        ("/perf-ultra", "perf_ultra_console.html", "性能极致优化控制台"),
    ]
    for _route, _fname, _desc in _PAGES_D34:
        def _make_page_handler_d34(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_d34():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_D34(content=_f.read())
                return _HTMLR_D34(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_d34
        _make_page_handler_d34()
    log.info("方向3+4 前端页面已注册：/super-home /perf-ultra")
except Exception as e:
    log.warning(f"方向3+4 前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "方向3：极致用户体验（超级首页）路由" in content:
        print("[INFO] 方向3+4 路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 方向3+4 路由注册代码已注入 app.py")
    return True


def verify_files_exist():
    print("\n" + "=" * 60)
    print("【文件存在验证】")
    print("=" * 60)
    expected = [
        "super_homepage/__init__.py",
        "super_homepage/homepage_config.py",
        "super_homepage/smart_guide.py",
        "super_homepage/global_search.py",
        "super_homepage/quick_actions.py",
        "super_homepage/ux_dashboard.py",
        "performance_ultra/__init__.py",
        "performance_ultra/lazy_loader.py",
        "performance_ultra/response_cache.py",
        "performance_ultra/async_queue.py",
        "performance_ultra/db_optimizer.py",
        "performance_ultra/perf_monitor.py",
        "performance_ultra/perf_dashboard.py",
        "api_server/super_homepage_routes.py",
        "api_server/perf_ultra_routes.py",
        "api_server/super_homepage_console.html",
        "api_server/perf_ultra_console.html",
    ]
    missing = []
    total = 0
    for fp in expected:
        full = os.path.join(PROJECT_ROOT, fp)
        if os.path.exists(full):
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                n = len(f.read())
            total += n
            flag = "OK"
            if fp.endswith(".html") and n < 15000:
                flag = "WARN(<15KB)"
            print(f"  [{flag}] {fp} ({n} 字节)")
        else:
            missing.append(fp)
            print(f"  [MISSING] {fp}")
    print(f"\n共 {len(expected)} 文件，缺失 {len(missing)}，合计 {total} 字节")
    return len(missing) == 0


def verify_imports():
    print("\n" + "=" * 60)
    print("【模块导入验证】")
    print("=" * 60)
    modules = [
        "super_homepage",
        "super_homepage.homepage_config",
        "super_homepage.smart_guide",
        "super_homepage.global_search",
        "super_homepage.quick_actions",
        "super_homepage.ux_dashboard",
        "performance_ultra",
        "performance_ultra.lazy_loader",
        "performance_ultra.response_cache",
        "performance_ultra.async_queue",
        "performance_ultra.db_optimizer",
        "performance_ultra.perf_monitor",
        "performance_ultra.perf_dashboard",
        "api_server.super_homepage_routes",
        "api_server.perf_ultra_routes",
    ]
    passed = failed = 0
    for m in modules:
        try:
            importlib.import_module(m)
            print(f"  [OK] {m}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {m}: {e}")
            failed += 1
    print(f"\n{len(modules)} 模块，通过 {passed}，失败 {failed}")
    return failed == 0


def verify_endpoints():
    print("\n" + "=" * 60)
    print("【API 端点计数】")
    print("=" * 60)
    checks = [
        ("api_server.super_homepage_routes", 20),
        ("api_server.perf_ultra_routes", 20),
    ]
    all_ok = True
    for mod, need in checks:
        try:
            m = importlib.import_module(mod)
            cnt = len(getattr(m.router, "routes", []))
            ok_flag = cnt >= need
            print(f"  [{'OK' if ok_flag else 'WARN'}] {mod}: {cnt} 端点 (>= {need})")
            all_ok &= ok_flag
        except Exception as e:
            print(f"  [FAIL] {mod}: {e}")
            all_ok = False
    return all_ok


def verify_smoke():
    print("\n" + "=" * 60)
    print("【业务冒烟】")
    print("=" * 60)
    try:
        # UX：搜索 + 引导
        from super_homepage.global_search import get_global_search
        r = get_global_search().search("sql")
        assert r["total"] >= 1, "搜索无结果"
        from super_homepage.smart_guide import get_smart_guide_manager
        st = get_smart_guide_manager().should_start("u1")
        assert st is True
        get_smart_guide_manager().complete("u1")
        print("  [OK] 全局搜索 + 智能引导")

        # Perf：LRU 缓存命中
        from performance_ultra.response_cache import get_response_cache
        c = get_response_cache()
        v1, h1 = c.get_or_set("smoke", lambda: 42)
        v2, h2 = c.get_or_set("smoke", lambda: 42)
        assert h1 is False and h2 is True, "缓存命中逻辑错误"
        print("  [OK] LRU 缓存命中")

        # Perf：分位计算
        from performance_ultra.perf_monitor import get_perf_monitor
        mon = get_perf_monitor()
        for ms in [10, 20, 30, 40, 60]:
            mon.record("/smoke", ms)
        p = mon.pct()
        assert p["p95"] > 0
        print(f"  [OK] 分位计算 P50={p['p50']} P95={p['p95']}")

        # 异步队列
        from performance_ultra.async_queue import get_async_queue
        q = get_async_queue()
        tid = q.enqueue(lambda: "done", kind="smoke")
        assert tid
        print("  [OK] 异步队列入队")
        return True
    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"  [FAIL] {e}")
        return False


def main():
    print("=" * 60)
    print("方向3+4 集成：极致用户体验 + 性能极致优化")
    print("=" * 60)
    f = verify_files_exist()
    inj = inject_routes()
    imp = verify_imports()
    ep = verify_endpoints()
    smk = verify_smoke()
    print("\n" + "=" * 60)
    print("总结")
    print("=" * 60)
    print(f"  文件存在: {'PASS' if f else 'FAIL'}")
    print(f"  路由注入: {'PASS' if inj else 'FAIL'}")
    print(f"  模块导入: {'PASS' if imp else 'FAIL'}")
    print(f"  API端点:  {'PASS' if ep else 'FAIL'}")
    print(f"  业务冒烟: {'PASS' if smk else 'FAIL'}")
    allp = all([f, inj, imp, ep, smk])
    print(f"\n  总体: {'ALL PASS' if allp else 'HAS FAILURES'}")
    return 0 if allp else 1


if __name__ == "__main__":
    sys.exit(main())
