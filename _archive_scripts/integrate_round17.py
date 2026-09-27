# -*- coding: utf-8 -*-
"""第17轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第17轮升级方向1：威胁狩猎专业级路由（30+端点） ==============
try:
    from api_server.threat_hunt_routes import router as threat_hunt_router
    app.include_router(threat_hunt_router)
    log.info("第17轮威胁狩猎专业级路由已注册：狩猎查询/假设驱动/行为分析/IOC富化/数据管理/报告度量，共30+个端点")
except Exception as e:
    log.warning(f"第17轮威胁狩猎专业级路由注册失败: {e}")


# ============== 第17轮升级方向2：网络流量分析NTA/NDR路由（30+端点） ==============
try:
    from api_server.network_analysis_routes import router as network_analysis_router
    app.include_router(network_analysis_router)
    log.info("第17轮网络流量分析路由已注册：流量捕获/异常检测/行为分析/威胁规则/流量取证/NDR仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第17轮网络流量分析路由注册失败: {e}")


# ============== 第17轮升级方向3：身份安全与IAM深化路由（30+端点） ==============
try:
    from api_server.identity_security_routes import router as identity_security_router
    app.include_router(identity_security_router)
    log.info("第17轮身份安全与IAM路由已注册：身份治理/权限审计/威胁检测/特权管理/访问认证/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第17轮身份安全与IAM路由注册失败: {e}")


# ============== 第17轮升级方向4：终端安全EDR路由（30+端点） ==============
try:
    from api_server.endpoint_security_routes import router as endpoint_security_router
    app.include_router(endpoint_security_router)
    log.info("第17轮终端安全EDR路由已注册：终端资产/进程行为/恶意软件/威胁响应/漏洞补丁/EDR仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第17轮终端安全EDR路由注册失败: {e}")


# ============== 第17轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR17
    _PAGES_R17 = [
        ("/threat-hunt", "threat_hunt_console.html", "威胁狩猎专业级控制台"),
        ("/network-analysis", "network_analysis_console.html", "网络流量分析NTA/NDR控制台"),
        ("/identity-security", "identity_security_console.html", "身份安全与IAM控制台"),
        ("/endpoint-security", "endpoint_security_console.html", "终端安全EDR控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R17:
        def _make_page_handler_r17(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r17():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR17(content=_f.read())
                return _HTMLR17(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r17
        _make_page_handler_r17()
    log.info("第17轮新前端页面已注册：/threat-hunt /network-analysis /identity-security /endpoint-security")
except Exception as e:
    log.warning(f"第17轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第17轮升级方向1：威胁狩猎专业级路由" in content:
        print("[INFO] 第17轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第17轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "threat_hunt.hunt_query_engine", "threat_hunt.hypothesis_driven_hunt",
        "threat_hunt.behavior_analysis", "threat_hunt.ioc_enrichment",
        "threat_hunt.hunt_data_manager", "threat_hunt.hunt_report_metrics",
        "network_analysis.traffic_capture", "network_analysis.anomaly_detection",
        "network_analysis.network_behavior", "network_analysis.threat_rules",
        "network_analysis.traffic_forensics", "network_analysis.ndr_dashboard",
        "identity_security.identity_governance", "identity_security.permission_audit",
        "identity_security.identity_threat_detection", "identity_security.privileged_access",
        "identity_security.access_authentication", "identity_security.identity_dashboard",
        "endpoint_security.endpoint_asset", "endpoint_security.process_behavior",
        "endpoint_security.malware_detection", "endpoint_security.threat_response",
        "endpoint_security.vulnerability_patch", "endpoint_security.edr_dashboard",
        "api_server.threat_hunt_routes", "api_server.network_analysis_routes",
        "api_server.identity_security_routes", "api_server.endpoint_security_routes",
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
        "threat_hunt/__init__.py", "threat_hunt/hunt_query_engine.py",
        "threat_hunt/hypothesis_driven_hunt.py", "threat_hunt/behavior_analysis.py",
        "threat_hunt/ioc_enrichment.py", "threat_hunt/hunt_data_manager.py",
        "threat_hunt/hunt_report_metrics.py",
        "network_analysis/__init__.py", "network_analysis/traffic_capture.py",
        "network_analysis/anomaly_detection.py", "network_analysis/network_behavior.py",
        "network_analysis/threat_rules.py", "network_analysis/traffic_forensics.py",
        "network_analysis/ndr_dashboard.py",
        "identity_security/__init__.py", "identity_security/identity_governance.py",
        "identity_security/permission_audit.py", "identity_security/identity_threat_detection.py",
        "identity_security/privileged_access.py", "identity_security/access_authentication.py",
        "identity_security/identity_dashboard.py",
        "endpoint_security/__init__.py", "endpoint_security/endpoint_asset.py",
        "endpoint_security/process_behavior.py", "endpoint_security/malware_detection.py",
        "endpoint_security/threat_response.py", "endpoint_security/vulnerability_patch.py",
        "endpoint_security/edr_dashboard.py",
        "api_server/threat_hunt_routes.py", "api_server/network_analysis_routes.py",
        "api_server/identity_security_routes.py", "api_server/endpoint_security_routes.py",
        "api_server/threat_hunt_console.html", "api_server/network_analysis_console.html",
        "api_server/identity_security_console.html", "api_server/endpoint_security_console.html",
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
        ("api_server.threat_hunt_routes", "threat_hunt", 30),
        ("api_server.network_analysis_routes", "network_analysis", 30),
        ("api_server.identity_security_routes", "identity_security", 30),
        ("api_server.endpoint_security_routes", "endpoint_security", 30),
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
    print(f"  第17轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/threat_hunt_console.html",
        "api_server/network_analysis_console.html",
        "api_server/identity_security_console.html",
        "api_server/endpoint_security_console.html",
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
            if mod.startswith("api_server") or mod.startswith("threat_hunt") or mod.startswith("network_analysis") or mod.startswith("identity_security") or mod.startswith("endpoint_security"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        print(f"  [OK] app.py导入成功，总路由数: {len(routes)}")
        r17_prefixes = ["/api/v1/threat-hunt", "/api/v1/network-analysis", "/api/v1/identity-security", "/api/v1/endpoint-security"]
        for prefix in r17_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        page_routes = ["/threat-hunt", "/network-analysis", "/identity-security", "/endpoint-security"]
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
    print("第17轮升级集成与验证脚本")
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
