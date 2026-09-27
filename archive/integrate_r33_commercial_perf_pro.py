# -*- coding: utf-8 -*-
"""方向4(商业成熟度大升级) + 方向6(性能大升级) 集成与验证脚本。

用法: python integrate_r33_commercial_perf_pro.py
"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 方向4：商业成熟度大升级路由（40+ 端点） ==============
try:
    from api_server.commercial_pro_routes import router as commercial_pro_router
    app.include_router(commercial_pro_router)
    log.info("方向4 商业成熟度路由已注册：License/客户门户/计费/SLA，共40+端点")
except Exception as e:
    log.warning(f"方向4 商业成熟度路由注册失败: {e}")


# ============== 方向6：性能大升级路由（28+ 端点） ==============
try:
    from api_server.performance_pro_routes import router as performance_pro_router
    app.include_router(performance_pro_router)
    log.info("方向6 性能大升级路由已注册：启动/响应/并发/DB/静态，共28+端点")
except Exception as e:
    log.warning(f"方向6 性能大升级路由注册失败: {e}")


# ============== 方向4+6：新前端页面路由（2个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_R33
    _PAGES_R33 = [
        ("/commercial-pro", "commercial_pro_console.html", "商业成熟度大升级控制台"),
        ("/performance-pro", "performance_pro_console.html", "性能大升级控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R33:
        def _make_page_handler_r33(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r33():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_R33(content=_f.read())
                return _HTMLR_R33(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r33
        _make_page_handler_r33()
    log.info("方向4+6 前端页面已注册：/commercial-pro /performance-pro")
except Exception as e:
    log.warning(f"方向4+6 前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "方向4：商业成熟度大升级路由" in content:
        print("[INFO] 方向4+6 路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 方向4+6 路由注册代码已注入 app.py")
    return True


def verify_files_exist():
    print("\n" + "=" * 60)
    print("【文件存在验证】")
    print("=" * 60)
    expected = [
        "commercial_pro/__init__.py",
        "commercial_pro/license_real.py",
        "commercial_pro/customer_portal.py",
        "commercial_pro/billing_system.py",
        "commercial_pro/sla_monitor.py",
        "commercial_pro/commercial_dashboard.py",
        "performance_pro/__init__.py",
        "performance_pro/startup_optimizer.py",
        "performance_pro/response_optimizer.py",
        "performance_pro/concurrency_controller.py",
        "performance_pro/db_optimizer_v2.py",
        "performance_pro/static_optimizer.py",
        "performance_pro/perf_pro_dashboard.py",
        "api_server/commercial_pro_routes.py",
        "api_server/performance_pro_routes.py",
        "api_server/commercial_pro_console.html",
        "api_server/performance_pro_console.html",
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
        "commercial_pro",
        "commercial_pro.license_real",
        "commercial_pro.customer_portal",
        "commercial_pro.billing_system",
        "commercial_pro.sla_monitor",
        "commercial_pro.commercial_dashboard",
        "performance_pro",
        "performance_pro.startup_optimizer",
        "performance_pro.response_optimizer",
        "performance_pro.concurrency_controller",
        "performance_pro.db_optimizer_v2",
        "performance_pro.static_optimizer",
        "performance_pro.perf_pro_dashboard",
        "api_server.commercial_pro_routes",
        "api_server.performance_pro_routes",
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
        ("api_server.commercial_pro_routes", 30),
        ("api_server.performance_pro_routes", 25),
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
        # --- 方向4 商业化 ---
        from commercial_pro.license_real import get_license_manager, generate_machine_code
        lm = get_license_manager()
        mc = generate_machine_code()["machine_code"]
        lic = lm.issue("冒烟客户", "pro", seats=3, duration_days=90)
        act = lm.activate(lic["license_key"], mc)
        assert act["success"], "激活失败"
        v = lm.verify(lic["license_key"], mc)
        assert v["valid"] and v["tier"] == "pro", "License 校验失败"
        print("  [OK] 真实 License：机器码+签发+激活+RSA验签+分级")

        from commercial_pro.customer_portal import get_customer_portal
        cp = get_customer_portal()
        reg = cp.register("smoke@test.ai", "secret123")
        cid = reg["customer_id"]
        tok = cp.login("smoke@test.ai", "secret123")["token"]
        who = cp.whoami(tok)
        assert who["customer_id"] == cid
        p = cp.create_project(cid, "冒烟项目", "https://smoke.test", "web")
        projs = cp.list_projects(cid)
        assert len(projs) >= 1
        print("  [OK] 客户门户：注册/登录/项目隔离/报告")

        from commercial_pro.billing_system import get_billing_system
        bs = get_billing_system()
        sub = bs.subscribe(cid, "pro", "monthly")
        inv_id = sub["invoice_id"]
        bs.pay(inv_id, "alipay")
        bs.confirm_payment(inv_id)
        rec = bs.record_scan(cid, 3)
        assert "charge_cny" in rec
        print("  [OK] 计费系统：订阅/支付预留/按次计费/账单")

        from commercial_pro.sla_monitor import get_sla_monitor
        sm = get_sla_monitor()
        sm.probe(True, 12)
        sm.probe(False, 9001)
        rec = sm.auto_recover()
        assert rec["recovered"] >= 1
        bk = sm.backup("冒烟备份")
        assert sm.restore(bk["backup_id"])
        sp = sm.status_page()
        assert sp["components"]
        print("  [OK] SLA：探针/自动恢复/备份恢复/状态页")

        # --- 方向6 性能 ---
        from performance_pro.startup_optimizer import get_startup_optimizer
        so = get_startup_optimizer()
        sim = so.simulate_startup()
        assert sim["saved_pct"] > 0 and sim["meets_target"]
        print(f"  [OK] 启动优化：全量{sim['full_load_ms']}ms → 懒加载{sim['lazy_load_ms']}ms")

        from performance_pro.response_optimizer import get_response_optimizer
        ro = get_response_optimizer()
        v1, h1 = ro.get_or_set("smoke", lambda: {"x": 1})
        v2, h2 = ro.get_or_set("smoke", lambda: {"x": 1})
        assert h1 is False and h2 is True
        for ms in [8, 12, 20, 45, 60]:
            ro.record("/api/smoke", ms)
        p = ro.overall_pct()
        assert p["p95"] > 0
        print(f"  [OK] 响应优化：LRU+TTL命中, P50={p['p50']} P95={p['p95']}")

        from performance_pro.concurrency_controller import get_concurrency_controller
        cc = get_concurrency_controller()
        st = cc.stress(50)
        assert st["submitted"] == 50
        print("  [OK] 并发控制：50 任务压测不崩")

        from performance_pro.db_optimizer_v2 import get_db_optimizer_v2
        db = get_db_optimizer_v2()
        assert len(db.recommend_indexes()) >= 3
        ex = db.analyze_query("SELECT * FROM vuln_findings WHERE severity='high'")
        assert "type" in ex
        print("  [OK] DB优化V2：索引推荐+EXPLAIN+缓存层")

        from performance_pro.static_optimizer import get_static_optimizer
        stc = get_static_optimizer()
        assert stc.summary()["saved_pct"] > 50
        print("  [OK] 静态资源：gzip/brotli/缓存头/CDN")
        return True
    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"  [FAIL] {e}")
        return False


def main():
    print("=" * 60)
    print("方向4+6 集成：商业成熟度大升级 + 性能大升级")
    print("=" * 60)
    f = verify_files_exist()
    imp = verify_imports()
    inj = inject_routes()
    ep = verify_endpoints()
    smk = verify_smoke()
    print("\n" + "=" * 60)
    print("总结")
    print("=" * 60)
    print(f"  文件存在: {'PASS' if f else 'FAIL'}")
    print(f"  模块导入: {'PASS' if imp else 'FAIL'}")
    print(f"  路由注入: {'PASS' if inj else 'FAIL'}")
    print(f"  API端点:  {'PASS' if ep else 'FAIL'}")
    print(f"  业务冒烟: {'PASS' if smk else 'FAIL'}")
    allp = all([f, imp, inj, ep, smk])
    print(f"\n  总体: {'ALL PASS' if allp else 'HAS FAILURES'}")
    return 0 if allp else 1


if __name__ == "__main__":
    sys.exit(main())
