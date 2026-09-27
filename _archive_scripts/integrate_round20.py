# -*- coding: utf-8 -*-
"""第20轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第20轮升级方向1：一键部署与安装包路由（30+端点） ==============
try:
    from api_server.deploy_routes import router as deploy_router
    app.include_router(deploy_router)
    log.info("第20轮一键部署路由已注册：环境检测/一键安装/配置向导/备份恢复/多环境部署/部署管理，共30+个端点")
except Exception as e:
    log.warning(f"第20轮一键部署路由注册失败: {e}")


# ============== 第20轮升级方向2：Web渗透评估做深路由（30+端点） ==============
try:
    from api_server.web_pentest_deep_routes import router as web_pentest_deep_router
    app.include_router(web_pentest_deep_router)
    log.info("第20轮Web渗透做深路由已注册：高级侦察/注入检测/认证授权/业务逻辑/漏洞验证/渗透控制台，共30+个端点")
except Exception as e:
    log.warning(f"第20轮Web渗透做深路由注册失败: {e}")


# ============== 第20轮升级方向3：移动APK分析做深路由（30+端点） ==============
try:
    from api_server.mobile_deep_routes import router as mobile_deep_router
    app.include_router(mobile_deep_router)
    log.info("第20轮移动APK做深路由已注册：APK解析/漏洞检测/隐私合规/恶意软件/动态分析/移动控制台，共30+个端点")
except Exception as e:
    log.warning(f"第20轮移动APK做深路由注册失败: {e}")


# ============== 第20轮升级方向4：报告引擎做深路由（30+端点） ==============
try:
    from api_server.report_engine_deep_routes import router as report_engine_deep_router
    app.include_router(report_engine_deep_router)
    log.info("第20轮报告引擎做深路由已注册：模板体系/内容生成/图表可视化/质量审核/导出分发/报告管理，共30+个端点")
except Exception as e:
    log.warning(f"第20轮报告引擎做深路由注册失败: {e}")


# ============== 第20轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR20
    _PAGES_R20 = [
        ("/deploy", "deploy_console.html", "一键部署控制台"),
        ("/web-pentest-deep", "web_pentest_deep_console.html", "Web渗透做深控制台"),
        ("/mobile-deep", "mobile_deep_console.html", "移动APK做深控制台"),
        ("/report-engine-deep", "report_engine_deep_console.html", "报告引擎做深控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R20:
        def _make_page_handler_r20(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r20():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR20(content=_f.read())
                return _HTMLR20(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r20
        _make_page_handler_r20()
    log.info("第20轮新前端页面已注册：/deploy /web-pentest-deep /mobile-deep /report-engine-deep")
except Exception as e:
    log.warning(f"第20轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第20轮升级方向1：一键部署与安装包路由" in content:
        print("[INFO] 第20轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第20轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "deploy.env_detector", "deploy.installer", "deploy.config_wizard",
        "deploy.backup_recovery", "deploy.multi_env_deploy", "deploy.deploy_dashboard",
        "web_pentest_deep.advanced_recon", "web_pentest_deep.injection_deep",
        "web_pentest_deep.auth_authorization", "web_pentest_deep.business_logic",
        "web_pentest_deep.exploit_verify", "web_pentest_deep.web_pentest_dashboard",
        "mobile_deep.apk_deep_parser", "mobile_deep.security_vuln_detector",
        "mobile_deep.privacy_compliance", "mobile_deep.malware_analysis",
        "mobile_deep.dynamic_analysis", "mobile_deep.mobile_dashboard",
        "report_engine_deep.template_system", "report_engine_deep.content_generator",
        "report_engine_deep.chart_visualization", "report_engine_deep.quality_review",
        "report_engine_deep.export_distribution", "report_engine_deep.report_dashboard",
        "api_server.deploy_routes", "api_server.web_pentest_deep_routes",
        "api_server.mobile_deep_routes", "api_server.report_engine_deep_routes",
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
        "deploy/__init__.py", "deploy/env_detector.py", "deploy/installer.py",
        "deploy/config_wizard.py", "deploy/backup_recovery.py", "deploy/multi_env_deploy.py",
        "deploy/deploy_dashboard.py",
        "web_pentest_deep/__init__.py", "web_pentest_deep/advanced_recon.py",
        "web_pentest_deep/injection_deep.py", "web_pentest_deep/auth_authorization.py",
        "web_pentest_deep/business_logic.py", "web_pentest_deep/exploit_verify.py",
        "web_pentest_deep/web_pentest_dashboard.py",
        "mobile_deep/__init__.py", "mobile_deep/apk_deep_parser.py",
        "mobile_deep/security_vuln_detector.py", "mobile_deep/privacy_compliance.py",
        "mobile_deep/malware_analysis.py", "mobile_deep/dynamic_analysis.py",
        "mobile_deep/mobile_dashboard.py",
        "report_engine_deep/__init__.py", "report_engine_deep/template_system.py",
        "report_engine_deep/content_generator.py", "report_engine_deep/chart_visualization.py",
        "report_engine_deep/quality_review.py", "report_engine_deep/export_distribution.py",
        "report_engine_deep/report_dashboard.py",
        "api_server/deploy_routes.py", "api_server/web_pentest_deep_routes.py",
        "api_server/mobile_deep_routes.py", "api_server/report_engine_deep_routes.py",
        "api_server/deploy_console.html", "api_server/web_pentest_deep_console.html",
        "api_server/mobile_deep_console.html", "api_server/report_engine_deep_console.html",
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
        ("api_server.deploy_routes", "deploy", 30),
        ("api_server.web_pentest_deep_routes", "web_pentest_deep", 30),
        ("api_server.mobile_deep_routes", "mobile_deep", 30),
        ("api_server.report_engine_deep_routes", "report_engine_deep", 30),
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
    print(f"  第20轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/deploy_console.html",
        "api_server/web_pentest_deep_console.html",
        "api_server/mobile_deep_console.html",
        "api_server/report_engine_deep_console.html",
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
            if mod.startswith("api_server") or mod.startswith("deploy") or mod.startswith("web_pentest_deep") or mod.startswith("mobile_deep") or mod.startswith("report_engine_deep"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        print(f"  [OK] app.py导入成功，总路由数: {len(routes)}")
        r20_prefixes = ["/api/v1/deploy", "/api/v1/web-pentest-deep", "/api/v1/mobile-deep", "/api/v1/report-engine-deep"]
        for prefix in r20_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        page_routes = ["/deploy", "/web-pentest-deep", "/mobile-deep", "/report-engine-deep"]
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
    print("第20轮升级集成与验证脚本")
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
