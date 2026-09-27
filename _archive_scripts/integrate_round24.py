# -*- coding: utf-8 -*-
"""第24轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第24轮升级方向1：自动化红蓝对抗与攻击模拟平台路由（50+端点） ==============
try:
    from api_server.red_blue_team_routes import router as red_blue_team_router
    app.include_router(red_blue_team_router)
    log.info("第24轮自动化红蓝对抗与攻击模拟平台路由已注册：攻击模拟/防御验证/对抗管理/攻击可视化/攻击工具/对抗控制台，共50+个端点")
except Exception as e:
    log.warning(f"第24轮自动化红蓝对抗与攻击模拟平台路由注册失败: {e}")


# ============== 第24轮升级方向2：SOAR深度平台路由（50+端点） ==============
try:
    from api_server.soar_deep_routes import router as soar_deep_router
    app.include_router(soar_deep_router)
    log.info("第24轮SOAR深度平台路由已注册：剧本编排/响应动作/告警分诊/案例管理/威胁情报联动/SOAR控制台，共50+个端点")
except Exception as e:
    log.warning(f"第24轮SOAR深度平台路由注册失败: {e}")


# ============== 第24轮升级方向3：数据安全与隐私保护深度平台路由（50+端点） ==============
try:
    from api_server.data_security_deep_routes import router as data_security_deep_router
    app.include_router(data_security_deep_router)
    log.info("第24轮数据安全与隐私保护深度平台路由已注册：数据分类分级/DLP防泄漏/隐私计算加密/访问审计/隐私合规/数据安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第24轮数据安全与隐私保护深度平台路由注册失败: {e}")


# ============== 第24轮升级方向4：跨平台客户端与开发者生态路由（50+端点） ==============
try:
    from api_server.developer_ecosystem_routes import router as developer_ecosystem_router
    app.include_router(developer_ecosystem_router)
    log.info("第24轮跨平台客户端与开发者生态路由已注册：CLI工具/桌面客户端/IDE插件/Python SDK/开发者门户/开放API，共50+个端点")
except Exception as e:
    log.warning(f"第24轮跨平台客户端与开发者生态路由注册失败: {e}")


# ============== 第24轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR24
    _PAGES_R24 = [
        ("/red-blue-team", "red_blue_team_console.html", "自动化红蓝对抗与攻击模拟平台控制台"),
        ("/soar-deep", "soar_deep_console.html", "SOAR深度平台控制台"),
        ("/data-security-deep", "data_security_deep_console.html", "数据安全与隐私保护深度平台控制台"),
        ("/developer-ecosystem", "developer_ecosystem_console.html", "跨平台客户端与开发者生态控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R24:
        def _make_page_handler_r24(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r24():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR24(content=_f.read())
                return _HTMLR24(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r24
        _make_page_handler_r24()
    log.info("第24轮新前端页面已注册：/red-blue-team /soar-deep /data-security-deep /developer-ecosystem")
except Exception as e:
    log.warning(f"第24轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第24轮升级方向1：自动化红蓝对抗与攻击模拟平台路由" in content:
        print("[INFO] 第24轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第24轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "red_blue_team.attack_simulator", "red_blue_team.defense_validator",
        "red_blue_team.exercise_manager", "red_blue_team.attack_visualization",
        "red_blue_team.attack_tools", "red_blue_team.exercise_dashboard",
        "soar_deep.playbook_engine", "soar_deep.response_actions",
        "soar_deep.alert_triage", "soar_deep.case_management",
        "soar_deep.threat_intel_integration", "soar_deep.soar_dashboard",
        "data_security_deep.data_classification", "data_security_deep.dlp_engine",
        "data_security_deep.privacy_compute", "data_security_deep.access_audit",
        "data_security_deep.privacy_compliance", "data_security_deep.data_security_dashboard",
        "developer_ecosystem.cli_tool", "developer_ecosystem.desktop_client",
        "developer_ecosystem.ide_plugin", "developer_ecosystem.python_sdk",
        "developer_ecosystem.developer_portal", "developer_ecosystem.open_api",
        "api_server.red_blue_team_routes", "api_server.soar_deep_routes",
        "api_server.data_security_deep_routes", "api_server.developer_ecosystem_routes",
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
        "red_blue_team/__init__.py", "red_blue_team/attack_simulator.py",
        "red_blue_team/defense_validator.py", "red_blue_team/exercise_manager.py",
        "red_blue_team/attack_visualization.py", "red_blue_team/attack_tools.py",
        "red_blue_team/exercise_dashboard.py",
        "soar_deep/__init__.py", "soar_deep/playbook_engine.py",
        "soar_deep/response_actions.py", "soar_deep/alert_triage.py",
        "soar_deep/case_management.py", "soar_deep/threat_intel_integration.py",
        "soar_deep/soar_dashboard.py",
        "data_security_deep/__init__.py", "data_security_deep/data_classification.py",
        "data_security_deep/dlp_engine.py", "data_security_deep/privacy_compute.py",
        "data_security_deep/access_audit.py", "data_security_deep/privacy_compliance.py",
        "data_security_deep/data_security_dashboard.py",
        "developer_ecosystem/__init__.py", "developer_ecosystem/cli_tool.py",
        "developer_ecosystem/desktop_client.py", "developer_ecosystem/ide_plugin.py",
        "developer_ecosystem/python_sdk.py", "developer_ecosystem/developer_portal.py",
        "developer_ecosystem/open_api.py",
        "api_server/red_blue_team_routes.py", "api_server/soar_deep_routes.py",
        "api_server/data_security_deep_routes.py", "api_server/developer_ecosystem_routes.py",
        "api_server/red_blue_team_console.html", "api_server/soar_deep_console.html",
        "api_server/data_security_deep_console.html", "api_server/developer_ecosystem_console.html",
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
        ("api_server.red_blue_team_routes", "red_blue_team", 50),
        ("api_server.soar_deep_routes", "soar_deep", 50),
        ("api_server.data_security_deep_routes", "data_security_deep", 50),
        ("api_server.developer_ecosystem_routes", "developer_ecosystem", 50),
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
    print(f"  第24轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/red_blue_team_console.html",
        "api_server/soar_deep_console.html",
        "api_server/data_security_deep_console.html",
        "api_server/developer_ecosystem_console.html",
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
            if mod.startswith("api_server") or mod.startswith("red_blue_team") or mod.startswith("soar_deep") or mod.startswith("data_security_deep") or mod.startswith("developer_ecosystem"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        print(f"  [OK] app.py导入成功，总路由数: {len(routes)}")
        r24_prefixes = ["/api/v1/red-blue-team", "/api/v1/soar-deep", "/api/v1/data-security-deep", "/api/v1/developer-ecosystem"]
        for prefix in r24_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        page_routes = ["/red-blue-team", "/soar-deep", "/data-security-deep", "/developer-ecosystem"]
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
    print("第24轮升级集成与验证脚本")
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
