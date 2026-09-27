# -*- coding: utf-8 -*-
"""
第13轮升级集成脚本
功能：
1. 在app.py中注册4个新路由（数据安全/零信任/蜜罐欺骗/暗网监控DRP）
2. 在app.py中注册4个新前端页面
3. 验证所有新模块导入
4. 验证API路由注册
5. 生成验证报告
"""

import os
import sys
import importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第13轮升级：数据安全与隐私保护路由（30+端点） ==============
try:
    from api_server.data_security_routes import router as data_security_router
    app.include_router(data_security_router)
    log.info("第13轮数据安全与隐私保护路由已注册：数据分类/DLP/隐私合规/加密密钥/访问控制/综合评估，共30+个端点")
except Exception as e:
    log.warning(f"第13轮数据安全与隐私保护路由注册失败: {e}")


# ============== 第13轮升级：零信任安全架构路由（30+端点） ==============
try:
    from api_server.zero_trust_routes import router as zero_trust_router
    app.include_router(zero_trust_router)
    log.info("第13轮零信任安全架构路由已注册：身份访问/持续验证/微隔离/设备信任/应用API安全/成熟度评估，共30+个端点")
except Exception as e:
    log.warning(f"第13轮零信任安全架构路由注册失败: {e}")


# ============== 第13轮升级：蜜罐与欺骗技术路由（30+端点） ==============
try:
    from api_server.deception_routes import router as deception_router
    app.include_router(deception_router)
    log.info("第13轮蜜罐与欺骗技术路由已注册：蜜罐管理/攻击检测/威胁情报/诱饵面包屑/蜜网分布式/综合运营，共30+个端点")
except Exception as e:
    log.warning(f"第13轮蜜罐与欺骗技术路由注册失败: {e}")


# ============== 第13轮升级：暗网监控与数字风险保护(DRP)路由（30+端点） ==============
try:
    from api_server.darkweb_monitor_routes import router as darkweb_monitor_router
    app.include_router(darkweb_monitor_router)
    log.info("第13轮暗网监控与DRP路由已注册：暗网情报/凭证泄露/品牌保护/数据泄露分析/威胁Actor/综合运营，共30+个端点")
except Exception as e:
    log.warning(f"第13轮暗网监控与DRP路由注册失败: {e}")


# ============== 第13轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR13

    _PAGES_R13 = [
        ("/data-security", "data_security_console.html", "数据安全与隐私保护控制台"),
        ("/zero-trust", "zero_trust_console.html", "零信任安全架构控制台"),
        ("/deception", "deception_console.html", "蜜罐与欺骗技术控制台"),
        ("/darkweb-monitor", "darkweb_monitor_console.html", "暗网监控与DRP控制台"),
    ]

    for _route, _fname, _desc in _PAGES_R13:
        def _make_page_handler_r13(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r13():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR13(content=_f.read())
                return _HTMLR13(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r13
        _make_page_handler_r13()

    log.info("第13轮新前端页面已注册：/data-security /zero-trust /deception /darkweb-monitor")
except Exception as e:
    log.warning(f"第13轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第13轮升级：数据安全与隐私保护路由" in content:
        print("[INFO] 第13轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第13轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "data_security.data_classification",
        "data_security.dlp_engine",
        "data_security.privacy_compliance",
        "data_security.encryption_key_management",
        "data_security.access_control",
        "data_security.data_security_workflow",
        "zero_trust.identity_access",
        "zero_trust.continuous_verification",
        "zero_trust.microsegmentation",
        "zero_trust.device_trust",
        "zero_trust.application_api_security",
        "zero_trust.zero_trust_maturity",
        "deception.honeypot_manager",
        "deception.attack_detector",
        "deception.threat_intel_generator",
        "deception.decoy_breadcrumb",
        "deception.honeynet_distributed",
        "deception.deception_operations",
        "darkweb_monitor.darkweb_intel",
        "darkweb_monitor.credential_leak",
        "darkweb_monitor.brand_protection",
        "darkweb_monitor.data_breach_analysis",
        "darkweb_monitor.threat_actor_analysis",
        "darkweb_monitor.drp_operations",
        "api_server.data_security_routes",
        "api_server.zero_trust_routes",
        "api_server.deception_routes",
        "api_server.darkweb_monitor_routes",
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
    expected_files = [
        "data_security/__init__.py",
        "data_security/data_classification.py",
        "data_security/dlp_engine.py",
        "data_security/privacy_compliance.py",
        "data_security/encryption_key_management.py",
        "data_security/access_control.py",
        "data_security/data_security_workflow.py",
        "zero_trust/__init__.py",
        "zero_trust/identity_access.py",
        "zero_trust/continuous_verification.py",
        "zero_trust.microsegmentation.py",
        "zero_trust.device_trust.py",
        "zero_trust.application_api_security.py",
        "zero_trust.zero_trust_maturity.py",
        "deception/__init__.py",
        "deception/honeypot_manager.py",
        "deception.attack_detector.py",
        "deception.threat_intel_generator.py",
        "deception.decoy_breadcrumb.py",
        "deception.honeynet_distributed.py",
        "deception.deception_operations.py",
        "darkweb_monitor/__init__.py",
        "darkweb_monitor/darkweb_intel.py",
        "darkweb_monitor/credential_leak.py",
        "darkweb_monitor/brand_protection.py",
        "darkweb_monitor/data_breach_analysis.py",
        "darkweb_monitor/threat_actor_analysis.py",
        "darkweb_monitor/drp_operations.py",
        "api_server/data_security_routes.py",
        "api_server/zero_trust_routes.py",
        "api_server/deception_routes.py",
        "api_server/darkweb_monitor_routes.py",
        "api_server/data_security_console.html",
        "api_server/zero_trust_console.html",
        "api_server/deception_console.html",
        "api_server/darkweb_monitor_console.html",
    ]
    print(f"\n=== 文件存在验证 ===")
    missing = []
    total_lines = 0
    for fpath in expected_files:
        full_path = os.path.join(PROJECT_ROOT, fpath)
        if os.path.exists(full_path):
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = len(f.readlines())
            total_lines += lines
            print(f"  [OK] {fpath} ({lines} 行)")
        else:
            missing.append(fpath)
            print(f"  [MISSING] {fpath}")
    print(f"\n总计: {len(expected_files)} 个文件, 存在: {len(expected_files)-len(missing)}, 缺失: {len(missing)}, 总代码行数: {total_lines} 行")
    return len(missing) == 0


def verify_api_routes():
    print(f"\n=== API路由验证 ===")
    route_modules = [
        ("api_server.data_security_routes", "data_security", 30),
        ("api_server.zero_trust_routes", "zero_trust", 30),
        ("api_server.deception_routes", "deception", 30),
        ("api_server.darkweb_monitor_routes", "darkweb_monitor", 30),
    ]
    all_ok = True
    for mod_name, prefix, expected_count in route_modules:
        try:
            mod = importlib.import_module(mod_name)
            router = getattr(mod, "router", None)
            if router is None:
                print(f"  [FAIL] {mod_name}: 未找到router对象")
                all_ok = False
                continue
            routes = getattr(router, "routes", [])
            actual_count = len(routes)
            status = "OK" if actual_count >= expected_count else "WARN"
            if actual_count < expected_count:
                all_ok = False
            print(f"  [{status}] {mod_name}: {actual_count} 个端点 (预期 >= {expected_count})")
        except Exception as e:
            print(f"  [FAIL] {mod_name}: {e}")
            all_ok = False
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/data_security_console.html",
        "api_server/zero_trust_console.html",
        "api_server/deception_console.html",
        "api_server/darkweb_monitor_console.html",
    ]
    all_ok = True
    for page in pages:
        full_path = os.path.join(PROJECT_ROOT, page)
        if not os.path.exists(full_path):
            print(f"  [FAIL] {page}: 文件不存在")
            all_ok = False
            continue
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            size = len(content)
            has_html = "<html" in content.lower() or "<!DOCTYPE" in content
            has_body = "<body" in content.lower()
            has_script = "<script" in content.lower()
            has_tab = "tab" in content.lower() or "nav" in content.lower()
            non_empty = size > 5000
            checks = [("UTF-8", True), ("HTML", has_html), ("Body", has_body), ("JS", has_script), ("Tab", has_tab), (">5KB", non_empty)]
            failed = [name for name, ok in checks if not ok]
            if failed:
                print(f"  [WARN] {page} ({size}B): 缺少 {', '.join(failed)}")
                all_ok = False
            else:
                print(f"  [OK] {page} ({size} 字节)")
        except UnicodeDecodeError:
            print(f"  [FAIL] {page}: UTF-8编码错误")
            all_ok = False
        except Exception as e:
            print(f"  [FAIL] {page}: {e}")
            all_ok = False
    return all_ok


def main():
    print("=" * 60)
    print("第13轮升级集成与验证脚本")
    print("=" * 60)
    files_ok = verify_files_exist()
    routes_ok = inject_routes()
    imports_ok = verify_imports()
    api_ok = verify_api_routes()
    html_ok = verify_html_pages()
    print("\n" + "=" * 60)
    print("验证总结")
    print("=" * 60)
    print(f"  文件存在: {'PASS' if files_ok else 'FAIL'}")
    print(f"  路由注入: {'PASS' if routes_ok else 'FAIL'}")
    print(f"  模块导入: {'PASS' if imports_ok else 'FAIL'}")
    print(f"  API路由:  {'PASS' if api_ok else 'FAIL'}")
    print(f"  前端页面: {'PASS' if html_ok else 'FAIL'}")
    all_pass = files_ok and routes_ok and imports_ok and api_ok and html_ok
    print(f"\n  总体结果: {'ALL PASS' if all_pass else 'HAS FAILURES'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
