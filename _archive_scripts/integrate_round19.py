# -*- coding: utf-8 -*-
"""第19轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第19轮升级方向1：性能优化大提升路由（30+端点） ==============
try:
    from api_server.performance_routes import router as performance_router
    app.include_router(performance_router)
    log.info("第19轮性能优化路由已注册：查询优化/API性能/并发异步/启动内存/数据库/性能仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第19轮性能优化路由注册失败: {e}")


# ============== 第19轮升级方向2：安全加固大提升路由（30+端点） ==============
try:
    from api_server.self_security_routes import router as self_security_router
    app.include_router(self_security_router)
    log.info("第19轮安全加固路由已注册：自身渗透/代码审计/API加固/数据安全/运行时防护/安全仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第19轮安全加固路由注册失败: {e}")


# ============== 第19轮升级方向3：文档体系大提升路由（30+端点） ==============
try:
    from api_server.docs_system_routes import router as docs_system_router
    app.include_router(docs_system_router)
    log.info("第19轮文档体系路由已注册：架构文档/API文档/用户手册/部署运维/知识库/文档管理，共30+个端点")
except Exception as e:
    log.warning(f"第19轮文档体系路由注册失败: {e}")


# ============== 第19轮升级方向4：测试体系与CI/CD路由（30+端点） ==============
try:
    from api_server.testing_routes import router as testing_router
    app.include_router(testing_router)
    log.info("第19轮测试体系与CI/CD路由已注册：单元测试/集成测试/性能测试/安全测试/CI-CD流水线/测试仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第19轮测试体系与CI/CD路由注册失败: {e}")


# ============== 第19轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR19
    _PAGES_R19 = [
        ("/performance", "performance_console.html", "性能优化控制台"),
        ("/self-security", "self_security_console.html", "安全加固控制台"),
        ("/docs-center", "docs_system_console.html", "文档体系控制台"),
        ("/testing", "testing_console.html", "测试体系与CI/CD控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R19:
        def _make_page_handler_r19(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r19():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR19(content=_f.read())
                return _HTMLR19(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r19
        _make_page_handler_r19()
    log.info("第19轮新前端页面已注册：/performance /self-security /docs-center /testing")
except Exception as e:
    log.warning(f"第19轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第19轮升级方向1：性能优化大提升路由" in content:
        print("[INFO] 第19轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第19轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "performance.query_optimizer", "performance.api_performance",
        "performance.concurrency_optimizer", "performance.startup_memory",
        "performance.database_performance", "performance.performance_dashboard",
        "self_security.self_pentest", "self_security.code_security_audit",
        "self_security.api_security_hardening", "self_security.data_security_privacy",
        "self_security.runtime_protection", "self_security.security_dashboard",
        "docs_system.architecture_docs", "docs_system.api_docs_center",
        "docs_system.user_guides", "docs_system.deployment_ops_docs",
        "docs_system.knowledge_base", "docs_system.docs_management",
        "testing.unit_testing", "testing.integration_testing",
        "testing.performance_testing", "testing.security_testing",
        "testing.cicd_pipeline", "testing.test_dashboard",
        "api_server.performance_routes", "api_server.self_security_routes",
        "api_server.docs_system_routes", "api_server.testing_routes",
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
        "performance/__init__.py", "performance/query_optimizer.py",
        "performance/api_performance.py", "performance/concurrency_optimizer.py",
        "performance/startup_memory.py", "performance/database_performance.py",
        "performance/performance_dashboard.py",
        "self_security/__init__.py", "self_security/self_pentest.py",
        "self_security/code_security_audit.py", "self_security/api_security_hardening.py",
        "self_security/data_security_privacy.py", "self_security/runtime_protection.py",
        "self_security/security_dashboard.py",
        "docs_system/__init__.py", "docs_system/architecture_docs.py",
        "docs_system/api_docs_center.py", "docs_system/user_guides.py",
        "docs_system/deployment_ops_docs.py", "docs_system/knowledge_base.py",
        "docs_system/docs_management.py",
        "testing/__init__.py", "testing/unit_testing.py",
        "testing/integration_testing.py", "testing/performance_testing.py",
        "testing/security_testing.py", "testing/cicd_pipeline.py",
        "testing/test_dashboard.py",
        "api_server/performance_routes.py", "api_server/self_security_routes.py",
        "api_server/docs_system_routes.py", "api_server/testing_routes.py",
        "api_server/performance_console.html", "api_server/self_security_console.html",
        "api_server/docs_system_console.html", "api_server/testing_console.html",
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
        ("api_server.performance_routes", "performance", 30),
        ("api_server.self_security_routes", "self_security", 30),
        ("api_server.docs_system_routes", "docs_system", 30),
        ("api_server.testing_routes", "testing", 30),
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
    print(f"  第19轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/performance_console.html",
        "api_server/self_security_console.html",
        "api_server/docs_system_console.html",
        "api_server/testing_console.html",
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
            if mod.startswith("api_server") or mod.startswith("performance") or mod.startswith("self_security") or mod.startswith("docs_system") or mod.startswith("testing"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        print(f"  [OK] app.py导入成功，总路由数: {len(routes)}")
        r19_prefixes = ["/api/v1/performance", "/api/v1/self-security", "/api/v1/docs-center", "/api/v1/testing"]
        for prefix in r19_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        page_routes = ["/performance", "/self-security", "/docs-center", "/testing"]
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
    print("第19轮升级集成与验证脚本")
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
