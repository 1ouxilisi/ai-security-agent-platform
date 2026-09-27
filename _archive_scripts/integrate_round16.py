# -*- coding: utf-8 -*-
"""第16轮升级完整集成与验证脚本（注入方向1/2/4 + 验证全部）"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

# 需要注入的路由代码（方向1、2、4 + 4个前端页面，方向3已由种子数据子代理注入）
ROUTES_CODE = '''

# ============== 第16轮升级方向1：端到端工作流真实打通路由（32个端点） ==============
try:
    from api_server.workflow_v2_routes import router as workflow_v2_router
    app.include_router(workflow_v2_router)
    log.info("第16轮端到端工作流路由已注册：一键评估/执行追踪/场景模板/可视化DAG/批量调度/端到端验证，共32个端点")
except Exception as e:
    log.warning(f"第16轮端到端工作流路由注册失败: {e}")


# ============== 第16轮升级方向2：前端交互深度提升路由（55个端点） ==============
try:
    from api_server.frontend_v2_routes import router as frontend_v2_router
    app.include_router(frontend_v2_router)
    log.info("第16轮前端交互深度提升路由已注册：任务面板/交互式报告/数据CRUD/通知中心/性能优化/导航布局，共55个端点")
except Exception as e:
    log.warning(f"第16轮前端交互深度提升路由注册失败: {e}")


# ============== 第16轮升级方向4：外部工具检测与性能优化路由（36个端点） ==============
try:
    from api_server.tool_runtime_routes import router as tool_runtime_router
    app.include_router(tool_runtime_router)
    log.info("第16轮工具运行时与性能路由已注册：工具检测/智能降级/安装引导/性能监控/系统健康/启动优化，共36个端点")
except Exception as e:
    log.warning(f"第16轮工具运行时与性能路由注册失败: {e}")


# ============== 第16轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR16
    _PAGES_R16 = [
        ("/workflow-executor", "workflow_executor_console.html", "端到端工作流执行器控制台"),
        ("/task-console", "task_console_console.html", "统一任务控制台"),
        ("/system-health", "system_health_console.html", "系统健康与工具运行时控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R16:
        def _make_page_handler_r16(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r16():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR16(content=_f.read())
                return _HTMLR16(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r16
        _make_page_handler_r16()
    log.info("第16轮新前端页面已注册：/workflow-executor /task-console /system-health（/seed-manager已由方向3注册）")
except Exception as e:
    log.warning(f"第16轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第16轮升级方向1：端到端工作流真实打通路由" in content:
        print("[INFO] 第16轮方向1/2/4路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第16轮方向1/2/4路由+前端页面已注入app.py")
    return True


def verify_imports():
    modules = [
        "workflow_v2.workflow_engine", "workflow_v2.execution_tracker",
        "workflow_v2.scenario_templates", "workflow_v2.workflow_visualization",
        "workflow_v2.batch_scheduler", "workflow_v2.e2e_verifier",
        "api_server.frontend_v2.common", "api_server.frontend_v2.task_panel",
        "api_server.frontend_v2.interactive_report", "api_server.frontend_v2.data_crud",
        "api_server.frontend_v2.notification_center", "api_server.frontend_v2.frontend_optimizer",
        "api_server.frontend_v2.navigation_layout",
        "seed_data.seed_manager", "seed_data.vulnerability_seeds",
        "seed_data.knowledge_seeds", "seed_data.tool_template_seeds",
        "seed_data.report_kpi_compliance_seeds", "seed_data.initialization_wizard",
        "tool_runtime.tool_detector", "tool_runtime.smart_fallback",
        "tool_runtime.install_guide", "tool_runtime.performance_monitor",
        "tool_runtime.system_health", "tool_runtime.startup_optimizer",
        "api_server.workflow_v2_routes", "api_server.frontend_v2_routes",
        "api_server.seed_data_routes", "api_server.tool_runtime_routes",
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
        "workflow_v2/__init__.py", "workflow_v2/workflow_engine.py",
        "workflow_v2/execution_tracker.py", "workflow_v2/scenario_templates.py",
        "workflow_v2/workflow_visualization.py", "workflow_v2/batch_scheduler.py",
        "workflow_v2/e2e_verifier.py",
        "api_server/frontend_v2/__init__.py", "api_server/frontend_v2/common.py",
        "api_server/frontend_v2/task_panel.py", "api_server/frontend_v2/interactive_report.py",
        "api_server/frontend_v2/data_crud.py", "api_server/frontend_v2/notification_center.py",
        "api_server/frontend_v2/frontend_optimizer.py", "api_server/frontend_v2/navigation_layout.py",
        "seed_data/__init__.py", "seed_data/seed_manager.py",
        "seed_data/vulnerability_seeds.py", "seed_data/knowledge_seeds.py",
        "seed_data/tool_template_seeds.py", "seed_data/report_kpi_compliance_seeds.py",
        "seed_data/initialization_wizard.py",
        "tool_runtime/__init__.py", "tool_runtime/tool_detector.py",
        "tool_runtime/smart_fallback.py", "tool_runtime/install_guide.py",
        "tool_runtime/performance_monitor.py", "tool_runtime/system_health.py",
        "tool_runtime/startup_optimizer.py",
        "api_server/workflow_v2_routes.py", "api_server/frontend_v2_routes.py",
        "api_server/seed_data_routes.py", "api_server/tool_runtime_routes.py",
        "api_server/workflow_executor_console.html", "api_server/task_console_console.html",
        "api_server/seed_manager_console.html", "api_server/system_health_console.html",
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
        ("api_server.workflow_v2_routes", "workflow_v2", 30),
        ("api_server.frontend_v2_routes", "frontend_v2", 30),
        ("api_server.seed_data_routes", "seed_data", 30),
        ("api_server.tool_runtime_routes", "tool_runtime", 30),
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
    print(f"  第16轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/workflow_executor_console.html",
        "api_server/task_console_console.html",
        "api_server/seed_manager_console.html",
        "api_server/system_health_console.html",
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
        # 清除可能的缓存
        for mod in list(sys.modules.keys()):
            if mod.startswith("api_server") or mod.startswith("workflow_v2") or mod.startswith("seed_data") or mod.startswith("tool_runtime"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        print(f"  [OK] app.py导入成功，总路由数: {len(routes)}")
        # 检查第16轮路由是否注册
        r16_prefixes = ["/api/v1/workflow-executor", "/api/v1/task-console", "/api/v1/seed-manager", "/api/v1/system-health"]
        for prefix in r16_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        # 检查前端页面
        page_routes = ["/workflow-executor", "/task-console", "/seed-manager", "/system-health"]
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
    print("第16轮升级完整集成与验证脚本")
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
