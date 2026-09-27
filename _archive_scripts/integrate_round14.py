# -*- coding: utf-8 -*-
"""第14轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第14轮升级：DevSecOps全链路安全路由（30+端点） ==============
try:
    from api_server.devsecops_routes import router as devsecops_router
    app.include_router(devsecops_router)
    log.info("第14轮DevSecOps全链路安全路由已注册：流水线安全/代码仓库/构建制品/部署运行时/安全门禁/成熟度评估，共30+个端点")
except Exception as e:
    log.warning(f"第14轮DevSecOps全链路安全路由注册失败: {e}")


# ============== 第14轮升级：安全培训与意识平台路由（30+端点） ==============
try:
    from api_server.security_training_routes import router as security_training_router
    app.include_router(security_training_router)
    log.info("第14轮安全培训与意识平台路由已注册：课程管理/实验环境/考试认证/钓鱼演练/意识评估/运营管理，共30+个端点")
except Exception as e:
    log.warning(f"第14轮安全培训与意识平台路由注册失败: {e}")


# ============== 第14轮升级：专业报告引擎路由（30+端点） ==============
try:
    from api_server.report_engine_routes import router as report_engine_router
    app.include_router(report_engine_router)
    log.info("第14轮专业报告引擎路由已注册：模板库/智能生成/质量校验/多格式导出/协作审批/报告分析，共30+个端点")
except Exception as e:
    log.warning(f"第14轮专业报告引擎路由注册失败: {e}")


# ============== 第14轮升级：安全服务交付平台路由（30+端点） ==============
try:
    from api_server.service_delivery_routes import router as service_delivery_router
    app.include_router(service_delivery_router)
    log.info("第14轮安全服务交付平台路由已注册：项目管理/客户门户/工时计费/SLA管理/交付物/团队资源，共30+个端点")
except Exception as e:
    log.warning(f"第14轮安全服务交付平台路由注册失败: {e}")


# ============== 第14轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR14
    _PAGES_R14 = [
        ("/devsecops", "devsecops_console.html", "DevSecOps全链路安全控制台"),
        ("/security-training", "security_training_console.html", "安全培训与意识平台控制台"),
        ("/report-engine", "report_engine_console.html", "专业报告引擎控制台"),
        ("/service-delivery", "service_delivery_console.html", "安全服务交付平台控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R14:
        def _make_page_handler_r14(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r14():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR14(content=_f.read())
                return _HTMLR14(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r14
        _make_page_handler_r14()
    log.info("第14轮新前端页面已注册：/devsecops /security-training /report-engine /service-delivery")
except Exception as e:
    log.warning(f"第14轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第14轮升级：DevSecOps全链路安全路由" in content:
        print("[INFO] 第14轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第14轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "devsecops.pipeline_security", "devsecops.repo_security",
        "devsecops.build_artifact_security", "devsecops.deployment_runtime_security",
        "devsecops.security_gate", "devsecops.devsecops_maturity",
        "devsecops.devsecops_workflow",
        "security_training.course_manager", "security_training.lab_environment",
        "security_training.exam_certification", "security_training.phishing_simulation",
        "security_training.awareness_assessment", "security_training.training_operations",
        "security_training.training_workflow",
        "report_engine.template_library", "report_engine.smart_generator",
        "report_engine.quality_checker", "report_engine.multi_format_export",
        "report_engine.collaboration_approval", "report_engine.report_analytics",
        "report_engine.report_workflow",
        "service_delivery.project_manager", "service_delivery.customer_portal",
        "service_delivery.time_billing", "service_delivery.sla_manager",
        "service_delivery.deliverable_manager", "service_delivery.team_resource",
        "service_delivery.delivery_workflow",
        "api_server.devsecops_routes", "api_server.security_training_routes",
        "api_server.report_engine_routes", "api_server.service_delivery_routes",
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
        "devsecops/__init__.py", "devsecops/pipeline_security.py",
        "devsecops/repo_security.py", "devsecops/build_artifact_security.py",
        "devsecops/deployment_runtime_security.py", "devsecops/security_gate.py",
        "devsecops/devsecops_maturity.py", "devsecops/devsecops_workflow.py",
        "security_training/__init__.py", "security_training/course_manager.py",
        "security_training/lab_environment.py", "security_training/exam_certification.py",
        "security_training/phishing_simulation.py", "security_training/awareness_assessment.py",
        "security_training/training_operations.py", "security_training/training_workflow.py",
        "report_engine/__init__.py", "report_engine/template_library.py",
        "report_engine/smart_generator.py", "report_engine.quality_checker.py",
        "report_engine/multi_format_export.py", "report_engine/collaboration_approval.py",
        "report_engine/report_analytics.py", "report_engine/report_workflow.py",
        "service_delivery/__init__.py", "service_delivery/project_manager.py",
        "service_delivery/customer_portal.py", "service_delivery/time_billing.py",
        "service_delivery/sla_manager.py", "service_delivery/deliverable_manager.py",
        "service_delivery/team_resource.py", "service_delivery/delivery_workflow.py",
        "api_server/devsecops_routes.py", "api_server/security_training_routes.py",
        "api_server/report_engine_routes.py", "api_server/service_delivery_routes.py",
        "api_server/devsecops_console.html", "api_server/security_training_console.html",
        "api_server/report_engine_console.html", "api_server/service_delivery_console.html",
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
        ("api_server.devsecops_routes", "devsecops", 30),
        ("api_server.security_training_routes", "security_training", 30),
        ("api_server.report_engine_routes", "report_engine", 30),
        ("api_server.service_delivery_routes", "service_delivery", 30),
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
        "api_server/devsecops_console.html",
        "api_server/security_training_console.html",
        "api_server/report_engine_console.html",
        "api_server/service_delivery_console.html",
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
    print("第14轮升级集成与验证脚本")
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
