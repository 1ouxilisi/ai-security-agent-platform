# -*- coding: utf-8 -*-
"""第25轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第25轮升级方向1：高级威胁检测与响应(UEBA+ML)路由（50+端点） ==============
try:
    from api_server.advanced_threat_routes import router as advanced_threat_router
    app.include_router(advanced_threat_router)
    log.info("第25轮高级威胁检测与响应(UEBA+ML)路由已注册：UEBA/ML异常检测/APT检测/攻击链分析/威胁狩猎/高级威胁控制台，共50+个端点")
except Exception as e:
    log.warning(f"第25轮高级威胁检测与响应(UEBA+ML)路由注册失败: {e}")


# ============== 第25轮升级方向2：云原生安全深度(CNAPP)路由（50+端点） ==============
try:
    from api_server.cloud_native_security_routes import router as cloud_native_security_router
    app.include_router(cloud_native_security_router)
    log.info("第25轮云原生安全深度(CNAPP)路由已注册：K8s运行时/容器安全/服务网格/CWPP/CSPM/云原生安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第25轮云原生安全深度(CNAPP)路由注册失败: {e}")


# ============== 第25轮升级方向3：安全度量与成熟度平台路由（50+端点） ==============
try:
    from api_server.security_metrics_deep_routes import router as security_metrics_deep_router
    app.include_router(security_metrics_deep_router)
    log.info("第25轮安全度量与成熟度平台路由已注册：成熟度评估/KPI-KRI/ROI/效能度量/文化评估/安全度量控制台，共50+个端点")
except Exception as e:
    log.warning(f"第25轮安全度量与成熟度平台路由注册失败: {e}")


# ============== 第25轮升级方向4：国际化与全球部署路由（50+端点） ==============
try:
    from api_server.globalization_routes import router as globalization_router
    app.include_router(globalization_router)
    log.info("第25轮国际化与全球部署路由已注册：多语言国际化/区域合规/国际支付/全球部署CDN/本地化/国际化控制台，共50+个端点")
except Exception as e:
    log.warning(f"第25轮国际化与全球部署路由注册失败: {e}")


# ============== 第25轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR25
    _PAGES_R25 = [
        ("/advanced-threat", "advanced_threat_console.html", "高级威胁检测与响应(UEBA+ML)控制台"),
        ("/cloud-native-security", "cloud_native_security_console.html", "云原生安全深度(CNAPP)控制台"),
        ("/security-metrics", "security_metrics_deep_console.html", "安全度量与成熟度平台控制台"),
        ("/globalization", "globalization_console.html", "国际化与全球部署控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R25:
        def _make_page_handler_r25(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r25():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR25(content=_f.read())
                return _HTMLR25(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r25
        _make_page_handler_r25()
    log.info("第25轮新前端页面已注册：/advanced-threat /cloud-native-security /security-metrics /globalization")
except Exception as e:
    log.warning(f"第25轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第25轮升级方向1：高级威胁检测与响应(UEBA+ML)路由" in content:
        print("[INFO] 第25轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第25轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "advanced_threat.ueba_engine", "advanced_threat.ml_anomaly",
        "advanced_threat.apt_detection", "advanced_threat.attack_chain",
        "advanced_threat.threat_hunt", "advanced_threat.advanced_threat_dashboard",
        "cloud_native_security.k8s_runtime", "cloud_native_security.container_security",
        "cloud_native_security.service_mesh", "cloud_native_security.cwpp",
        "cloud_native_security.cspm", "cloud_native_security.cnapp_dashboard",
        "security_metrics_deep.maturity_assessment", "security_metrics_deep.kpi_kri",
        "security_metrics_deep.security_roi", "security_metrics_deep.security_efficiency",
        "security_metrics_deep.security_culture", "security_metrics_deep.metrics_dashboard",
        "globalization.i18n_engine", "globalization.regional_compliance",
        "globalization.global_payment", "globalization.global_deployment",
        "globalization.localization", "globalization.globalization_dashboard",
        "api_server.advanced_threat_routes", "api_server.cloud_native_security_routes",
        "api_server.security_metrics_deep_routes", "api_server.globalization_routes",
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
        "advanced_threat/__init__.py", "advanced_threat/ueba_engine.py",
        "advanced_threat/ml_anomaly.py", "advanced_threat/apt_detection.py",
        "advanced_threat/attack_chain.py", "advanced_threat/threat_hunt.py",
        "advanced_threat/advanced_threat_dashboard.py",
        "cloud_native_security/__init__.py", "cloud_native_security/k8s_runtime.py",
        "cloud_native_security/container_security.py", "cloud_native_security/service_mesh.py",
        "cloud_native_security/cwpp.py", "cloud_native_security/cspm.py",
        "cloud_native_security/cnapp_dashboard.py",
        "security_metrics_deep/__init__.py", "security_metrics_deep/maturity_assessment.py",
        "security_metrics_deep/kpi_kri.py", "security_metrics_deep/security_roi.py",
        "security_metrics_deep/security_efficiency.py", "security_metrics_deep/security_culture.py",
        "security_metrics_deep/metrics_dashboard.py",
        "globalization/__init__.py", "globalization/i18n_engine.py",
        "globalization/regional_compliance.py", "globalization/global_payment.py",
        "globalization/global_deployment.py", "globalization/localization.py",
        "globalization/globalization_dashboard.py",
        "api_server/advanced_threat_routes.py", "api_server/cloud_native_security_routes.py",
        "api_server/security_metrics_deep_routes.py", "api_server/globalization_routes.py",
        "api_server/advanced_threat_console.html", "api_server/cloud_native_security_console.html",
        "api_server/security_metrics_deep_console.html", "api_server/globalization_console.html",
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
        ("api_server.advanced_threat_routes", "advanced_threat", 50),
        ("api_server.cloud_native_security_routes", "cloud_native_security", 50),
        ("api_server.security_metrics_deep_routes", "security_metrics_deep", 50),
        ("api_server.globalization_routes", "globalization", 50),
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
    print(f"  第25轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/advanced_threat_console.html",
        "api_server/cloud_native_security_console.html",
        "api_server/security_metrics_deep_console.html",
        "api_server/globalization_console.html",
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
            if mod.startswith("api_server") or mod.startswith("advanced_threat") or mod.startswith("cloud_native_security") or mod.startswith("security_metrics_deep") or mod.startswith("globalization"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        print(f"  [OK] app.py导入成功，总路由数: {len(routes)}")
        r25_prefixes = ["/api/v1/advanced-threat", "/api/v1/cloud-native-security", "/api/v1/security-metrics", "/api/v1/globalization"]
        for prefix in r25_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        page_routes = ["/advanced-threat", "/cloud-native-security", "/security-metrics", "/globalization"]
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
    print("第25轮升级集成与验证脚本")
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
