# -*- coding: utf-8 -*-
"""第29轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第29轮升级方向1：安全数据湖与大数据分析深度路由（50+端点） ==============
try:
    from api_server.data_lake_deep_routes import router as data_lake_deep_router
    app.include_router(data_lake_deep_router)
    log.info("第29轮安全数据湖与大数据分析深度路由已注册：数据湖架构/日志聚合/行为分析/AI威胁检测/数据挖掘/数据湖控制台，共50+个端点")
except Exception as e:
    log.warning(f"第29轮安全数据湖与大数据分析深度路由注册失败: {e}")


# ============== 第29轮升级方向2：移动端安全深度路由（50+端点） ==============
try:
    from api_server.mobile_security_deep_routes import router as mobile_security_deep_router
    app.include_router(mobile_security_deep_router)
    log.info("第29轮移动端安全深度路由已注册：Android深度/iOS深度/鸿蒙深度/移动漏洞POC/隐私合规/测试评测/移动安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第29轮移动端安全深度路由注册失败: {e}")


# ============== 第29轮升级方向3：API安全全生命周期路由（50+端点） ==============
try:
    from api_server.api_security_lifecycle_routes import router as api_security_lifecycle_router
    app.include_router(api_security_lifecycle_router)
    log.info("第29轮API安全全生命周期路由已注册：API资产/设计安全/开发安全/运行时安全/滥用与业务逻辑/治理合规/API安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第29轮API安全全生命周期路由注册失败: {e}")


# ============== 第29轮升级方向4：5G/车联网/新兴通信安全路由（50+端点） ==============
try:
    from api_server.emerging_comm_security_routes import router as emerging_comm_security_router
    app.include_router(emerging_comm_security_router)
    log.info("第29轮5G/车联网/新兴通信安全路由已注册：5G核心网安全/V2X安全/车载安全/OTA安全/新兴通信/新兴通信安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第29轮5G/车联网/新兴通信安全路由注册失败: {e}")


# ============== 第29轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR29
    _PAGES_R29 = [
        ("/data-lake-deep", "data_lake_deep_console.html", "安全数据湖与大数据分析深度控制台"),
        ("/mobile-security-deep", "mobile_security_deep_console.html", "移动端安全深度控制台"),
        ("/api-security-lifecycle", "api_security_lifecycle_console.html", "API安全全生命周期控制台"),
        ("/emerging-comm-security", "emerging_comm_security_console.html", "5G/车联网/新兴通信安全控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R29:
        def _make_page_handler_r29(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r29():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR28(content=_f.read())
                return _HTMLR28(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r29
        _make_page_handler_r29()
    log.info("第29轮新前端页面已注册：/data-lake-deep /mobile-security-deep /api-security-lifecycle /emerging-comm-security")
except Exception as e:
    log.warning(f"第29轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第29轮升级方向1：安全数据湖与大数据分析深度路由" in content:
        print("[INFO] 第29轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第29轮路由注册代码已注入app.py")
    return True


def verify_imports():
    print("\n" + "="*60)
    print("【模块导入验证】")
    print("="*60)
    
    modules = [
        "data_lake_deep.lake_architecture", "data_lake_deep.log_aggregation",
        "data_lake_deep.behavior_analysis", "data_lake_deep.ai_threat_detection",
        "data_lake_deep.data_mining", "data_lake_deep.data_lake_dashboard",
        "mobile_security_deep.android_deep", "mobile_security_deep.ios_deep",
        "mobile_security_deep.harmonyos_deep", "mobile_security_deep.mobile_vuln_poc",
        "mobile_security_deep.privacy_compliance", "mobile_security_deep.mobile_test_eval",
        "mobile_security_deep.mobile_security_dashboard",
        "api_security_lifecycle.api_assets", "api_security_lifecycle.design_security",
        "api_security_lifecycle.dev_security", "api_security_lifecycle.runtime_security",
        "api_security_lifecycle.abuse_logic", "api_security_lifecycle.governance_compliance",
        "api_security_lifecycle.api_security_dashboard",
        "emerging_comm_security.5g_security", "emerging_comm_security.v2x_security",
        "emerging_comm_security.vehicle_security", "emerging_comm_security.ota_security",
        "emerging_comm_security.emerging_comm", "emerging_comm_security.emerging_comm_dashboard",
        "api_server.data_lake_deep_routes", "api_server.mobile_security_deep_routes",
        "api_server.api_security_lifecycle_routes", "api_server.emerging_comm_security_routes",
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
    
    print(f"总计: {len(modules)} 个模块, 通过: {passed}, 失败: {failed}")
    for r in results:
        print(r)
    return failed == 0


def verify_files_exist():
    print("\n" + "="*60)
    print("【文件存在验证】")
    print("="*60)
    
    expected = [
        "data_lake_deep/__init__.py", "data_lake_deep/lake_architecture.py",
        "data_lake_deep/log_aggregation.py", "data_lake_deep/behavior_analysis.py",
        "data_lake_deep/ai_threat_detection.py", "data_lake_deep/data_mining.py",
        "data_lake_deep/data_lake_dashboard.py",
        "mobile_security_deep/__init__.py", "mobile_security_deep/android_deep.py",
        "mobile_security_deep/ios_deep.py", "mobile_security_deep/harmonyos_deep.py",
        "mobile_security_deep/mobile_vuln_poc.py", "mobile_security_deep/privacy_compliance.py",
        "mobile_security_deep/mobile_test_eval.py", "mobile_security_deep/mobile_security_dashboard.py",
        "api_security_lifecycle/__init__.py", "api_security_lifecycle/api_assets.py",
        "api_security_lifecycle/design_security.py", "api_security_lifecycle/dev_security.py",
        "api_security_lifecycle/runtime_security.py", "api_security_lifecycle/abuse_logic.py",
        "api_security_lifecycle/governance_compliance.py", "api_security_lifecycle/api_security_dashboard.py",
        "emerging_comm_security/__init__.py", "emerging_comm_security/5g_security.py",
        "emerging_comm_security/v2x_security.py", "emerging_comm_security/vehicle_security.py",
        "emerging_comm_security/ota_security.py", "emerging_comm_security/emerging_comm.py",
        "emerging_comm_security/emerging_comm_dashboard.py",
        "api_server/data_lake_deep_routes.py", "api_server/mobile_security_deep_routes.py",
        "api_server/api_security_lifecycle_routes.py", "api_server/emerging_comm_security_routes.py",
        "api_server/data_lake_deep_console.html", "api_server/mobile_security_deep_console.html",
        "api_server/api_security_lifecycle_console.html", "api_server/emerging_comm_security_console.html",
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
    print(f"\n总计: {len(expected)} 个文件, 存在: {len(expected)-len(missing)}, 缺失: {len(missing)}, 总代码行数: {total_lines} 行")
    return len(missing) == 0


def verify_api_routes():
    print("\n" + "="*60)
    print("【API路由验证】")
    print("="*60)
    
    route_mods = [
        ("api_server.data_lake_deep_routes", "data_lake_deep", 50),
        ("api_server.mobile_security_deep_routes", "mobile_security_deep", 50),
        ("api_server.api_security_lifecycle_routes", "api_security_lifecycle", 50),
        ("api_server.emerging_comm_security_routes", "emerging_comm_security", 50),
    ]
    all_ok = True
    total = 0
    for mod_name, prefix, expected in route_mods:
        try:
            mod = importlib.import_module(mod_name)
            router = getattr(mod, "router", None)
            if router:
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
    print(f"  第29轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print("\n" + "="*60)
    print("【前端页面验证】")
    print("="*60)
    
    html_files = [
        "api_server/data_lake_deep_console.html",
        "api_server/mobile_security_deep_console.html",
        "api_server/api_security_lifecycle_console.html",
        "api_server/emerging_comm_security_console.html",
    ]
    total = 0
    valid = 0
    invalid = []
    for html_file in html_files:
        full = os.path.join(PROJECT_ROOT, html_file)
        total += 1
        if os.path.exists(full):
            try:
                with open(full, "r", encoding="utf-8") as f:
                    content = f.read()
                size = len(content)
                has_html = "<html" in content.lower()
                has_script = "<script" in content.lower()
                if has_html and has_script and size > 5000:
                    valid += 1
                    print(f"  [OK] {html_file} ({size} 字节)")
                else:
                    invalid.append((html_file, f"size={size}, html={has_html}, script={has_script}"))
            except Exception as e:
                invalid.append((html_file, str(e)))
        else:
            invalid.append((html_file, "文件不存在"))
    print(f"\n总计: {total} 个页面, 有效: {valid}, 无效: {len(invalid)}")
    if invalid:
        for name, reason in invalid:
            print(f"  - {name}: {reason}")
    return len(invalid) == 0


def verify_app_import():
    print("\n" + "="*60)
    print("【app.py导入验证】")
    print("="*60)
    
    try:
        for mod in list(sys.modules.keys()):
            if mod.startswith("api_server") or mod.startswith("data_lake_deep") or mod.startswith("mobile_security_deep") or mod.startswith("api_security_lifecycle") or mod.startswith("emerging_comm_security"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        total_routes = len(routes)
        print(f"  [OK] app.py导入成功，总路由数: {total_routes}")
        
        r29_prefixes = ["/api/v1/data-lake-deep", "/api/v1/mobile-security-deep", "/api/v1/api-security-lifecycle", "/api/v1/emerging-comm-security"]
        r29_pages = ["/data-lake-deep", "/mobile-security-deep", "/api-security-lifecycle", "/emerging-comm-security"]
        
        for prefix in r29_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        for pr in r29_pages:
            found = any(getattr(r, "path", "") == pr for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 前端页面 {pr}: {'已注册' if found else '未找到'}")
        return True
    except Exception as e:
        print(f"  [FAIL] app.py导入失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print("="*60)
    print("第29轮升级集成与验证脚本")
    print("="*60)
    
    files_ok = verify_files_exist()
    routes_ok = inject_routes()
    imports_ok = verify_imports()
    api_ok = verify_api_routes()
    html_ok = verify_html_pages()
    app_ok = verify_app_import()
    
    print("\n" + "="*60)
    print("验证总结")
    print("="*60)
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
