# -*- coding: utf-8 -*-
"""第15轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第15轮升级：供应链安全深化路由（30+端点） ==============
try:
    from api_server.supply_chain_routes import router as supply_chain_router
    app.include_router(supply_chain_router)
    log.info("第15轮供应链安全深化路由已注册：SBOM管理/组件分析/漏洞检测/许可证合规/供应商风险/综合评估，共30+个端点")
except Exception as e:
    log.warning(f"第15轮供应链安全深化路由注册失败: {e}")


# ============== 第15轮升级：SOAR安全编排自动化与响应路由（30+端点） ==============
try:
    from api_server.soar_routes import router as soar_router
    app.include_router(soar_router)
    log.info("第15轮SOAR安全编排路由已注册：剧本编排/动作库/告警分诊/案例管理/执行监控/运营度量，共30+个端点")
except Exception as e:
    log.warning(f"第15轮SOAR安全编排路由注册失败: {e}")


# ============== 第15轮升级：开放API平台与开发者中心路由（30+端点） ==============
try:
    from api_server.developer_portal_routes import router as developer_portal_router
    app.include_router(developer_portal_router)
    log.info("第15轮开放API平台路由已注册：API文档/SDK工具/沙箱/应用密钥/用量计费/社区支持，共30+个端点")
except Exception as e:
    log.warning(f"第15轮开放API平台路由注册失败: {e}")


# ============== 第15轮升级：安全度量与KPI体系路由（30+端点） ==============
try:
    from api_server.security_metrics_routes import router as security_metrics_router
    app.include_router(security_metrics_router)
    log.info("第15轮安全度量与KPI体系路由已注册：成熟度模型/KPI指标库/风险评分/运营效率/合规审计/高管仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第15轮安全度量与KPI体系路由注册失败: {e}")


# ============== 第15轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR15
    _PAGES_R15 = [
        ("/supply-chain", "supply_chain_console.html", "供应链安全深化控制台"),
        ("/soar", "soar_console.html", "SOAR安全编排自动化控制台"),
        ("/developer-portal", "developer_portal_console.html", "开放API平台与开发者中心控制台"),
        ("/security-metrics", "security_metrics_console.html", "安全度量与KPI体系控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R15:
        def _make_page_handler_r15(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r15():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR15(content=_f.read())
                return _HTMLR15(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r15
        _make_page_handler_r15()
    log.info("第15轮新前端页面已注册：/supply-chain /soar /developer-portal /security-metrics")
except Exception as e:
    log.warning(f"第15轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第15轮升级：供应链安全深化路由" in content:
        print("[INFO] 第15轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第15轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "supply_chain.sbom_manager", "supply_chain.component_analyzer",
        "supply_chain.vulnerability_detector", "supply_chain.license_compliance",
        "supply_chain.supplier_risk", "supply_chain.supply_chain_workflow",
        "soar.playbook_engine", "soar.action_library",
        "soar.alert_triage", "soar.case_manager",
        "soar.execution_engine", "soar.soar_metrics",
        "soar.soar_workflow",
        "developer_portal.api_docs", "developer_portal.sdk_tools",
        "developer_portal.sandbox_manager", "developer_portal.app_key_manager",
        "developer_portal.usage_billing", "developer_portal.community_support",
        "developer_portal.portal_workflow",
        "security_metrics.maturity_model", "security_metrics.kpi_library",
        "security_metrics.risk_scoring", "security_metrics.operational_efficiency",
        "security_metrics.compliance_audit", "security_metrics.executive_dashboard",
        "security_metrics.metrics_workflow",
        "api_server.supply_chain_routes", "api_server.soar_routes",
        "api_server.developer_portal_routes", "api_server.security_metrics_routes",
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
        "supply_chain/__init__.py", "supply_chain/sbom_manager.py",
        "supply_chain/component_analyzer.py", "supply_chain/vulnerability_detector.py",
        "supply_chain/license_compliance.py", "supply_chain/supplier_risk.py",
        "supply_chain/supply_chain_workflow.py",
        "soar/__init__.py", "soar/playbook_engine.py",
        "soar/action_library.py", "soar/alert_triage.py",
        "soar/case_manager.py", "soar/execution_engine.py",
        "soar/soar_metrics.py", "soar/soar_workflow.py",
        "developer_portal/__init__.py", "developer_portal/api_docs.py",
        "developer_portal/sdk_tools.py", "developer_portal/sandbox_manager.py",
        "developer_portal/app_key_manager.py", "developer_portal/usage_billing.py",
        "developer_portal/community_support.py", "developer_portal/portal_workflow.py",
        "security_metrics/__init__.py", "security_metrics/maturity_model.py",
        "security_metrics/kpi_library.py", "security_metrics/risk_scoring.py",
        "security_metrics/operational_efficiency.py", "security_metrics/compliance_audit.py",
        "security_metrics/executive_dashboard.py", "security_metrics/metrics_workflow.py",
        "api_server/supply_chain_routes.py", "api_server/soar_routes.py",
        "api_server/developer_portal_routes.py", "api_server/security_metrics_routes.py",
        "api_server/supply_chain_console.html", "api_server/soar_console.html",
        "api_server/developer_portal_console.html", "api_server/security_metrics_console.html",
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
        ("api_server.supply_chain_routes", "supply_chain", 30),
        ("api_server.soar_routes", "soar", 30),
        ("api_server.developer_portal_routes", "developer_portal", 30),
        ("api_server.security_metrics_routes", "security_metrics", 30),
    ]
    all_ok = True
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
            status = "OK" if cnt >= expected else "WARN"
            if cnt < expected:
                all_ok = False
            print(f"  [{status}] {mod_name}: {cnt} 个端点 (预期 >= {expected})")
        except Exception as e:
            print(f"  [FAIL] {mod_name}: {e}")
            all_ok = False
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/supply_chain_console.html",
        "api_server/soar_console.html",
        "api_server/developer_portal_console.html",
        "api_server/security_metrics_console.html",
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


def main():
    print("=" * 60)
    print("第15轮升级集成与验证脚本")
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
