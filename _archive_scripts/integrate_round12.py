# -*- coding: utf-8 -*-
"""
第12轮升级集成脚本
功能：
1. 在app.py中注册4个新路由（IoT安全/工控安全/无线网络安全/API安全专业级）
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

# 第12轮新增路由注册代码
ROUTES_CODE = '''

# ============== 第12轮升级：物联网(IoT)安全深化路由（30+端点） ==============
try:
    from api_server.iot_security_routes import router as iot_security_router
    app.include_router(iot_security_router)
    log.info("第12轮物联网安全深化路由已注册：设备发现/固件分析/协议安全/默认凭据/通信安全/漏洞检测/综合评估，共30+个端点")
except Exception as e:
    log.warning(f"第12轮物联网安全深化路由注册失败: {e}")


# ============== 第12轮升级：工控安全(ICS/SCADA)深化路由（30+端点） ==============
try:
    from api_server.ics_security_routes import router as ics_security_router
    app.include_router(ics_security_router)
    log.info("第12轮工控安全深化路由已注册：资产发现/协议分析/漏洞检测/基线检查/异常检测/威胁情报/综合评估，共30+个端点")
except Exception as e:
    log.warning(f"第12轮工控安全深化路由注册失败: {e}")


# ============== 第12轮升级：无线网络安全深化路由（30+端点） ==============
try:
    from api_server.wireless_security_routes import router as wireless_security_router
    app.include_router(wireless_security_router)
    log.info("第12轮无线网络安全深化路由已注册：WiFi扫描/WiFi安全/邪恶孪生/蓝牙安全/Zigbee安全/频谱分析/综合评估，共30+个端点")
except Exception as e:
    log.warning(f"第12轮无线网络安全深化路由注册失败: {e}")


# ============== 第12轮升级：API安全专业级深化路由（30+端点） ==============
try:
    from api_server.api_security_pro_routes import router as api_security_pro_router
    app.include_router(api_security_pro_router)
    log.info("第12轮API安全专业级深化路由已注册：OpenAPI解析/认证授权/注入测试/业务逻辑/安全配置/Fuzz测试/综合扫描，共30+个端点")
except Exception as e:
    log.warning(f"第12轮API安全专业级深化路由注册失败: {e}")


# ============== 第12轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR12

    _PAGES_R12 = [
        ("/iot-security", "iot_security_console.html", "物联网安全控制台"),
        ("/ics-security", "ics_security_console.html", "工控安全控制台"),
        ("/wireless-security", "wireless_security_console.html", "无线网络安全控制台"),
        ("/api-security-pro", "api_security_pro_console.html", "API安全专业级控制台"),
    ]

    for _route, _fname, _desc in _PAGES_R12:
        def _make_page_handler_r12(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r12():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR12(content=_f.read())
                return _HTMLR12(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r12
        _make_page_handler_r12()

    log.info("第12轮新前端页面已注册：/iot-security /ics-security /wireless-security /api-security-pro")
except Exception as e:
    log.warning(f"第12轮新前端页面注册失败: {e}")

'''


def inject_routes():
    """将第12轮路由注册代码注入到app.py中（在全局异常处理器之前）"""
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False

    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()

    if "第12轮升级：物联网(IoT)安全深化路由" in content:
        print("[INFO] 第12轮路由已存在，跳过注入")
        return True

    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False

    content = content.replace(marker, ROUTES_CODE + "\n" + marker)

    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)

    print("[OK] 第12轮路由注册代码已注入app.py")
    return True


def verify_imports():
    """验证所有新模块导入"""
    modules = [
        # IoT安全
        "iot_security.device_discovery",
        "iot_security.firmware_analyzer",
        "iot_security.protocol_security",
        "iot_security.default_credentials",
        "iot_security.communication_security",
        "iot_security.vulnerability_detector",
        "iot_security.iot_assessment_workflow",
        # 工控安全
        "ics_security.asset_discovery",
        "ics_security.protocol_analyzer",
        "ics_security.vulnerability_detector",
        "ics_security.baseline_checker",
        "ics_security.anomaly_detector",
        "ics_security.ics_assessment_workflow",
        "ics_security.threat_intel",
        # 无线网络安全
        "wireless_security.wifi_scanner",
        "wireless_security.wifi_security",
        "wireless_security.evil_twin_detector",
        "wireless_security.bluetooth_security",
        "wireless_security.zigbee_security",
        "wireless_security.wireless_assessment_workflow",
        "wireless_security.spectrum_analyzer",
        # API安全专业级
        "api_security_pro.openapi_parser",
        "api_security_pro.auth_authorization",
        "api_security_pro.injection_tester",
        "api_security_pro.business_logic",
        "api_security_pro.security_config",
        "api_security_pro.api_scan_workflow",
        "api_security_pro.fuzz_engine",
        # API路由
        "api_server.iot_security_routes",
        "api_server.ics_security_routes",
        "api_server.wireless_security_routes",
        "api_server.api_security_pro_routes",
    ]

    results = []
    passed = 0
    failed = 0

    for mod_name in modules:
        try:
            importlib.import_module(mod_name)
            results.append(f"  [OK] {mod_name}")
            passed += 1
        except Exception as e:
            results.append(f"  [FAIL] {mod_name}: {e}")
            failed += 1

    print(f"\n=== 模块导入验证 ===")
    print(f"总计: {len(modules)} 个模块")
    print(f"通过: {passed} 个")
    print(f"失败: {failed} 个")
    for r in results:
        print(r)

    return failed == 0


def verify_files_exist():
    """验证所有新文件存在"""
    expected_files = [
        # IoT安全
        "iot_security/__init__.py",
        "iot_security/device_discovery.py",
        "iot_security/firmware_analyzer.py",
        "iot_security/protocol_security.py",
        "iot_security/default_credentials.py",
        "iot_security/communication_security.py",
        "iot_security/vulnerability_detector.py",
        "iot_security/iot_assessment_workflow.py",
        # 工控安全
        "ics_security/__init__.py",
        "ics_security/asset_discovery.py",
        "ics_security/protocol_analyzer.py",
        "ics_security/vulnerability_detector.py",
        "ics_security/baseline_checker.py",
        "ics_security/anomaly_detector.py",
        "ics_security/ics_assessment_workflow.py",
        "ics_security/threat_intel.py",
        # 无线网络安全
        "wireless_security/__init__.py",
        "wireless_security/wifi_scanner.py",
        "wireless_security/wifi_security.py",
        "wireless_security/evil_twin_detector.py",
        "wireless_security/bluetooth_security.py",
        "wireless_security/zigbee_security.py",
        "wireless_security/wireless_assessment_workflow.py",
        "wireless_security/spectrum_analyzer.py",
        # API安全专业级
        "api_security_pro/__init__.py",
        "api_security_pro/openapi_parser.py",
        "api_security_pro/auth_authorization.py",
        "api_security_pro/injection_tester.py",
        "api_security_pro/business_logic.py",
        "api_security_pro/security_config.py",
        "api_security_pro/api_scan_workflow.py",
        "api_security_pro/fuzz_engine.py",
        # API路由
        "api_server/iot_security_routes.py",
        "api_server/ics_security_routes.py",
        "api_server/wireless_security_routes.py",
        "api_server/api_security_pro_routes.py",
        # 前端页面
        "api_server/iot_security_console.html",
        "api_server/ics_security_console.html",
        "api_server/wireless_security_console.html",
        "api_server/api_security_pro_console.html",
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

    print(f"\n总计: {len(expected_files)} 个文件")
    print(f"存在: {len(expected_files) - len(missing)} 个")
    print(f"缺失: {len(missing)} 个")
    print(f"总代码行数: {total_lines} 行")

    return len(missing) == 0


def verify_api_routes():
    """验证API路由可以从模块中获取"""
    print(f"\n=== API路由验证 ===")
    route_modules = [
        ("api_server.iot_security_routes", "iot_security", 30),
        ("api_server.ics_security_routes", "ics_security", 30),
        ("api_server.wireless_security_routes", "wireless_security", 30),
        ("api_server.api_security_pro_routes", "api_security_pro", 30),
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
    """验证前端页面非空白且UTF-8编码正常"""
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/iot_security_console.html",
        "api_server/ics_security_console.html",
        "api_server/wireless_security_console.html",
        "api_server/api_security_pro_console.html",
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

            checks = [
                ("UTF-8可读", True),
                ("HTML结构", has_html),
                ("Body标签", has_body),
                ("JavaScript", has_script),
                ("Tab/导航", has_tab),
                ("非空白(>5KB)", non_empty),
            ]
            failed = [name for name, ok in checks if not ok]
            if failed:
                print(f"  [WARN] {page} ({size} 字节): 缺少 {', '.join(failed)}")
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
    print("第12轮升级集成与验证脚本")
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
