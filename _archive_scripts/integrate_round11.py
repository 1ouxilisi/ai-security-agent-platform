# -*- coding: utf-8 -*-
"""
第11轮升级集成脚本
功能：
1. 在app.py中注册4个新路由（云安全V2/代码审计V2/取证V2/插件系统）
2. 在app.py中注册4个新前端页面
3. 验证所有新模块导入
4. 验证API路由注册
5. 生成验证报告
"""

import os
import sys
import importlib
import traceback

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

# 第11轮新增路由注册代码
ROUTES_CODE = '''

# ============== 第11轮升级：云安全深化V2路由（28端点） ==============
try:
    from api_server.cloud_security_v2_routes import router as cloud_security_v2_router
    app.include_router(cloud_security_v2_router)
    log.info("第11轮云安全深化V2路由已注册：AWS/Azure/阿里云/GCP配置检查/容器扫描/K8s安全/云资产/云威胁，共28个端点")
except Exception as e:
    log.warning(f"第11轮云安全深化V2路由注册失败: {e}")


# ============== 第11轮升级：代码审计深化V2路由（25端点） ==============
try:
    from api_server.code_audit_v2_routes import router as code_audit_v2_router
    app.include_router(code_audit_v2_router)
    log.info("第11轮代码审计深化V2路由已注册：SAST/Semgrep/SCA/代码质量/安全编码/综合审计，共25个端点")
except Exception as e:
    log.warning(f"第11轮代码审计深化V2路由注册失败: {e}")


# ============== 第11轮升级：取证分析深化V2路由（28端点） ==============
try:
    from api_server.forensics_v2_routes import router as forensics_v2_router
    app.include_router(forensics_v2_router)
    log.info("第11轮取证分析深化V2路由已注册：内存/磁盘/网络/日志取证/综合取证/证据管理，共28个端点")
except Exception as e:
    log.warning(f"第11轮取证分析深化V2路由注册失败: {e}")


# ============== 第11轮升级：插件扩展系统路由（30端点） ==============
try:
    from api_server.plugin_system_routes import router as plugin_system_router
    app.include_router(plugin_system_router)
    log.info("第11轮插件扩展系统路由已注册：插件管理/市场/SDK/安全/运行时，共30个端点")
except Exception as e:
    log.warning(f"第11轮插件扩展系统路由注册失败: {e}")


# ============== 第11轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR11

    _PAGES_R11 = [
        ("/cloud-security-v2", "cloud_security_v2_console.html", "云安全深化控制台"),
        ("/code-audit-v2", "code_audit_v2_console.html", "代码审计深化控制台"),
        ("/forensics-v2", "forensics_v2_console.html", "取证分析深化控制台"),
        ("/plugins-console", "plugin_system_console.html", "插件扩展系统控制台"),
    ]

    for _route, _fname, _desc in _PAGES_R11:
        def _make_page_handler_r11(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r11():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR11(content=_f.read())
                return _HTMLR11(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r11
        _make_page_handler_r11()

    log.info("第11轮新前端页面已注册：/cloud-security-v2 /code-audit-v2 /forensics-v2 /plugins-console")
except Exception as e:
    log.warning(f"第11轮新前端页面注册失败: {e}")

'''


def inject_routes():
    """将第11轮路由注册代码注入到app.py中（在全局异常处理器之前）"""
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False

    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()

    # 检查是否已经注入过
    if "第11轮升级：云安全深化V2路由" in content:
        print("[INFO] 第11轮路由已存在，跳过注入")
        return True

    # 找到全局异常处理器的位置，在其之前插入
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False

    content = content.replace(marker, ROUTES_CODE + "\n" + marker)

    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)

    print("[OK] 第11轮路由注册代码已注入app.py")
    return True


def verify_imports():
    """验证所有新模块导入"""
    modules = [
        # 云安全
        "cloud_security.aws_audit",
        "cloud_security.azure_audit",
        "cloud_security.aliyun_audit",
        "cloud_security.gcp_audit",
        "cloud_security.container_scanner",
        "cloud_security.k8s_security",
        "cloud_security.cloud_asset_discovery",
        "cloud_security.cloud_threat_detection",
        # 代码审计
        "code_audit.sast_engine",
        "code_audit.semgrep_integration",
        "code_audit.sca_engine",
        "code_audit.code_quality",
        "code_audit.secure_coding",
        "code_audit.code_audit_workflow",
        # 取证分析
        "forensics.memory_forensics",
        "forensics.disk_forensics",
        "forensics.network_forensics",
        "forensics.log_forensics",
        "forensics.forensics_workflow",
        # 插件系统
        "plugin_system.plugin_manager",
        "plugin_system.plugin_marketplace",
        "plugin_system.plugin_sdk",
        "plugin_system.plugin_security",
        "plugin_system.plugin_runtime",
        # API路由
        "api_server.cloud_security_v2_routes",
        "api_server.code_audit_v2_routes",
        "api_server.forensics_v2_routes",
        "api_server.plugin_system_routes",
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
        # 云安全核心
        "cloud_security/aws_audit.py",
        "cloud_security/azure_audit.py",
        "cloud_security/aliyun_audit.py",
        "cloud_security/gcp_audit.py",
        "cloud_security/container_scanner.py",
        "cloud_security/k8s_security.py",
        "cloud_security/cloud_asset_discovery.py",
        "cloud_security/cloud_threat_detection.py",
        # 代码审计核心
        "code_audit/sast_engine.py",
        "code_audit/semgrep_integration.py",
        "code_audit/sca_engine.py",
        "code_audit/code_quality.py",
        "code_audit/secure_coding.py",
        "code_audit/code_audit_workflow.py",
        # 取证分析核心
        "forensics/memory_forensics.py",
        "forensics/disk_forensics.py",
        "forensics/network_forensics.py",
        "forensics/log_forensics.py",
        "forensics/forensics_workflow.py",
        # 插件系统核心
        "plugin_system/__init__.py",
        "plugin_system/plugin_manager.py",
        "plugin_system/plugin_marketplace.py",
        "plugin_system/plugin_sdk.py",
        "plugin_system/plugin_security.py",
        "plugin_system/plugin_runtime.py",
        # API路由
        "api_server/cloud_security_v2_routes.py",
        "api_server/code_audit_v2_routes.py",
        "api_server/forensics_v2_routes.py",
        "api_server/plugin_system_routes.py",
        # 前端页面
        "api_server/cloud_security_v2_console.html",
        "api_server/code_audit_v2_console.html",
        "api_server/forensics_v2_console.html",
        "api_server/plugin_system_console.html",
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
        ("api_server.cloud_security_v2_routes", "cloud_security_v2", 28),
        ("api_server.code_audit_v2_routes", "code_audit_v2", 25),
        ("api_server.forensics_v2_routes", "forensics_v2", 28),
        ("api_server.plugin_system_routes", "plugin_system", 30),
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
        "api_server/cloud_security_v2_console.html",
        "api_server/code_audit_v2_console.html",
        "api_server/forensics_v2_console.html",
        "api_server/plugin_system_console.html",
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
    print("第11轮升级集成与验证脚本")
    print("=" * 60)

    # 1. 验证文件存在
    files_ok = verify_files_exist()

    # 2. 注入路由
    routes_ok = inject_routes()

    # 3. 验证模块导入
    imports_ok = verify_imports()

    # 4. 验证API路由
    api_ok = verify_api_routes()

    # 5. 验证前端页面
    html_ok = verify_html_pages()

    # 总结
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
