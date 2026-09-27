# -*- coding: utf-8 -*-
"""第23轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第23轮升级方向1：AI大模型智能决策引擎路由（40+端点） ==============
try:
    from api_server.ai_intelligence_routes import router as ai_intelligence_router
    app.include_router(ai_intelligence_router)
    log.info("第23轮AI大模型智能决策引擎路由已注册：自然语言助手/智能扫描决策/POC生成/智能报告/AI知识库/AI控制台，共40+个端点")
except Exception as e:
    log.warning(f"第23轮AI大模型智能决策引擎路由注册失败: {e}")


# ============== 第23轮升级方向2：分布式扫描与任务调度路由（40+端点） ==============
try:
    from api_server.distributed_scan_routes import router as distributed_scan_router
    app.include_router(distributed_scan_router)
    log.info("第23轮分布式扫描与任务调度路由已注册：集群架构/任务管理/代理池/断点续扫/资源管理/分布式控制台，共40+个端点")
except Exception as e:
    log.warning(f"第23轮分布式扫描与任务调度路由注册失败: {e}")


# ============== 第23轮升级方向3：威胁情报与攻击面管理路由（40+端点） ==============
try:
    from api_server.threat_intel_routes import router as threat_intel_router
    app.include_router(threat_intel_router)
    log.info("第23轮威胁情报与攻击面管理路由已注册：情报源/IOC管理/攻击面/漏洞情报/威胁Actor/情报控制台，共40+个端点")
except Exception as e:
    log.warning(f"第23轮威胁情报与攻击面管理路由注册失败: {e}")


# ============== 第23轮升级方向4：企业级多租户与计费路由（40+端点） ==============
try:
    from api_server.enterprise_saas_routes import router as enterprise_saas_router
    app.include_router(enterprise_saas_router)
    log.info("第23轮企业级多租户与计费路由已注册：多租户架构/订阅计费/客户门户/SSO身份/审计合规/企业控制台，共40+个端点")
except Exception as e:
    log.warning(f"第23轮企业级多租户与计费路由注册失败: {e}")


# ============== 第23轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR23
    _PAGES_R23 = [
        ("/ai-intelligence", "ai_intelligence_console.html", "AI大模型智能决策引擎控制台"),
        ("/distributed-scan", "distributed_scan_console.html", "分布式扫描与任务调度控制台"),
        ("/threat-intel", "threat_intel_console.html", "威胁情报与攻击面管理控制台"),
        ("/enterprise-saas", "enterprise_saas_console.html", "企业级多租户与计费控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R23:
        def _make_page_handler_r23(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r23():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR23(content=_f.read())
                return _HTMLR23(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r23
        _make_page_handler_r23()
    log.info("第23轮新前端页面已注册：/ai-intelligence /distributed-scan /threat-intel /enterprise-saas")
except Exception as e:
    log.warning(f"第23轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第23轮升级方向1：AI大模型智能决策引擎路由" in content:
        print("[INFO] 第23轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第23轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "ai_intelligence.nl_assistant", "ai_intelligence.scan_decision",
        "ai_intelligence.poc_generator", "ai_intelligence.smart_report",
        "ai_intelligence.ai_knowledge_base", "ai_intelligence.ai_dashboard",
        "distributed_scan.cluster_arch", "distributed_scan.task_manager",
        "distributed_scan.proxy_pool", "distributed_scan.resume_scan",
        "distributed_scan.resource_manager", "distributed_scan.cluster_dashboard",
        "threat_intel.intel_sources", "threat_intel.ioc_manager",
        "threat_intel.attack_surface", "threat_intel.vuln_intel",
        "threat_intel.threat_actor", "threat_intel.intel_dashboard",
        "enterprise_saas.multi_tenant", "enterprise_saas.billing_system",
        "enterprise_saas.customer_portal", "enterprise_saas.sso_identity",
        "enterprise_saas.audit_compliance", "enterprise_saas.enterprise_dashboard",
        "api_server.ai_intelligence_routes", "api_server.distributed_scan_routes",
        "api_server.threat_intel_routes", "api_server.enterprise_saas_routes",
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
        "ai_intelligence/__init__.py", "ai_intelligence/nl_assistant.py",
        "ai_intelligence/scan_decision.py", "ai_intelligence/poc_generator.py",
        "ai_intelligence/smart_report.py", "ai_intelligence/ai_knowledge_base.py",
        "ai_intelligence/ai_dashboard.py",
        "distributed_scan/__init__.py", "distributed_scan/cluster_arch.py",
        "distributed_scan/task_manager.py", "distributed_scan/proxy_pool.py",
        "distributed_scan/resume_scan.py", "distributed_scan/resource_manager.py",
        "distributed_scan/cluster_dashboard.py",
        "threat_intel/__init__.py", "threat_intel/intel_sources.py",
        "threat_intel/ioc_manager.py", "threat_intel/attack_surface.py",
        "threat_intel/vuln_intel.py", "threat_intel/threat_actor.py",
        "threat_intel/intel_dashboard.py",
        "enterprise_saas/__init__.py", "enterprise_saas/multi_tenant.py",
        "enterprise_saas/billing_system.py", "enterprise_saas/customer_portal.py",
        "enterprise_saas/sso_identity.py", "enterprise_saas/audit_compliance.py",
        "enterprise_saas/enterprise_dashboard.py",
        "api_server/ai_intelligence_routes.py", "api_server/distributed_scan_routes.py",
        "api_server/threat_intel_routes.py", "api_server/enterprise_saas_routes.py",
        "api_server/ai_intelligence_console.html", "api_server/distributed_scan_console.html",
        "api_server/threat_intel_console.html", "api_server/enterprise_saas_console.html",
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
        ("api_server.ai_intelligence_routes", "ai_intelligence", 40),
        ("api_server.distributed_scan_routes", "distributed_scan", 40),
        ("api_server.threat_intel_routes", "threat_intel", 40),
        ("api_server.enterprise_saas_routes", "enterprise_saas", 40),
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
    print(f"  第23轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/ai_intelligence_console.html",
        "api_server/distributed_scan_console.html",
        "api_server/threat_intel_console.html",
        "api_server/enterprise_saas_console.html",
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
            if mod.startswith("api_server") or mod.startswith("ai_intelligence") or mod.startswith("distributed_scan") or mod.startswith("threat_intel") or mod.startswith("enterprise_saas"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        print(f"  [OK] app.py导入成功，总路由数: {len(routes)}")
        r23_prefixes = ["/api/v1/ai-intelligence", "/api/v1/distributed-scan", "/api/v1/threat-intel", "/api/v1/enterprise-saas"]
        for prefix in r23_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        page_routes = ["/ai-intelligence", "/distributed-scan", "/threat-intel", "/enterprise-saas"]
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
    print("第23轮升级集成与验证脚本")
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
