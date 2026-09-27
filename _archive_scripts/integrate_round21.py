# -*- coding: utf-8 -*-
"""第21轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第21轮升级方向1：License授权系统路由（30+端点） ==============
try:
    from api_server.license_system_routes import router as license_system_router
    app.include_router(license_system_router)
    log.info("第21轮License授权系统路由已注册：License生成/设备绑定/功能权限/续费升级/防盗版/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第21轮License授权系统路由注册失败: {e}")


# ============== 第21轮升级方向2：品牌官网落地页路由（30+端点） ==============
try:
    from api_server.brand_website_routes import router as brand_website_router
    app.include_router(brand_website_router)
    log.info("第21轮品牌官网落地页路由已注册：内容管理/产品展示/定价购买/文档支持/博客营销/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第21轮品牌官网落地页路由注册失败: {e}")


# ============== 第21轮升级方向3：客户管理CRM路由（30+端点） ==============
try:
    from api_server.crm_system_routes import router as crm_system_router
    app.include_router(crm_system_router)
    log.info("第21轮客户管理CRM路由已注册：客户管理/销售漏斗/沟通活动/产品定价/客户服务/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第21轮客户管理CRM路由注册失败: {e}")


# ============== 第21轮升级方向4：交互式教程路由（30+端点） ==============
try:
    from api_server.interactive_tutorial_routes import router as interactive_tutorial_router
    app.include_router(interactive_tutorial_router)
    log.info("第21轮交互式教程路由已注册：教程内容/交互环境/学习路径/进度评估/场景实战/运营控制台，共30+个端点")
except Exception as e:
    log.warning(f"第21轮交互式教程路由注册失败: {e}")


# ============== 第21轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR21
    _PAGES_R21 = [
        ("/license-system", "license_system_console.html", "License授权系统控制台"),
        ("/brand-website", "brand_website_console.html", "品牌官网落地页控制台"),
        ("/crm-system", "crm_system_console.html", "客户管理CRM控制台"),
        ("/interactive-tutorial", "interactive_tutorial_console.html", "交互式教程控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R21:
        def _make_page_handler_r21(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r21():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR21(content=_f.read())
                return _HTMLR21(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r21
        _make_page_handler_r21()
    log.info("第21轮新前端页面已注册：/license-system /brand-website /crm-system /interactive-tutorial")
except Exception as e:
    log.warning(f"第21轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第21轮升级方向1：License授权系统路由" in content:
        print("[INFO] 第21轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第21轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "license_system.license_generator", "license_system.device_binding",
        "license_system.feature_control", "license_system.billing_upgrade",
        "license_system.anti_piracy", "license_system.license_dashboard",
        "brand_website.content_manager", "brand_website.product_showcase",
        "brand_website.pricing_purchase", "brand_website.docs_support",
        "brand_website.blog_marketing", "brand_website.brand_dashboard",
        "crm_system.customer_manager", "crm_system.sales_pipeline",
        "crm_system.communication_activity", "crm_system.product_pricing",
        "crm_system.customer_service", "crm_system.crm_dashboard",
        "interactive_tutorial.tutorial_content", "interactive_tutorial.interactive_env",
        "interactive_tutorial.learning_path", "interactive_tutorial.progress_evaluation",
        "interactive_tutorial.scenario_practice", "interactive_tutorial.tutorial_dashboard",
        "api_server.license_system_routes", "api_server.brand_website_routes",
        "api_server.crm_system_routes", "api_server.interactive_tutorial_routes",
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
        "license_system/__init__.py", "license_system/license_generator.py",
        "license_system/device_binding.py", "license_system/feature_control.py",
        "license_system/billing_upgrade.py", "license_system/anti_piracy.py",
        "license_system/license_dashboard.py",
        "brand_website/__init__.py", "brand_website/content_manager.py",
        "brand_website/product_showcase.py", "brand_website/pricing_purchase.py",
        "brand_website/docs_support.py", "brand_website/blog_marketing.py",
        "brand_website/brand_dashboard.py",
        "crm_system/__init__.py", "crm_system/customer_manager.py",
        "crm_system/sales_pipeline.py", "crm_system/communication_activity.py",
        "crm_system/product_pricing.py", "crm_system/customer_service.py",
        "crm_system/crm_dashboard.py",
        "interactive_tutorial/__init__.py", "interactive_tutorial/tutorial_content.py",
        "interactive_tutorial/interactive_env.py", "interactive_tutorial/learning_path.py",
        "interactive_tutorial/progress_evaluation.py", "interactive_tutorial/scenario_practice.py",
        "interactive_tutorial/tutorial_dashboard.py",
        "api_server/license_system_routes.py", "api_server/brand_website_routes.py",
        "api_server/crm_system_routes.py", "api_server/interactive_tutorial_routes.py",
        "api_server/license_system_console.html", "api_server/brand_website_console.html",
        "api_server/crm_system_console.html", "api_server/interactive_tutorial_console.html",
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
        ("api_server.license_system_routes", "license_system", 30),
        ("api_server.brand_website_routes", "brand_website", 30),
        ("api_server.crm_system_routes", "crm_system", 30),
        ("api_server.interactive_tutorial_routes", "interactive_tutorial", 30),
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
    print(f"  第21轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/license_system_console.html",
        "api_server/brand_website_console.html",
        "api_server/crm_system_console.html",
        "api_server/interactive_tutorial_console.html",
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
            if mod.startswith("api_server") or mod.startswith("license_system") or mod.startswith("brand_website") or mod.startswith("crm_system") or mod.startswith("interactive_tutorial"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        print(f"  [OK] app.py导入成功，总路由数: {len(routes)}")
        r21_prefixes = ["/api/v1/license-system", "/api/v1/brand-website", "/api/v1/crm-system", "/api/v1/interactive-tutorial"]
        for prefix in r21_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        page_routes = ["/license-system", "/brand-website", "/crm-system", "/interactive-tutorial"]
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
    print("第21轮升级集成与验证脚本")
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
