# -*- coding: utf-8 -*-
"""第26轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第26轮升级方向1：安全大模型与AI Agent深度平台路由（50+端点） ==============
try:
    from api_server.security_llm_routes import router as security_llm_router
    app.include_router(security_llm_router)
    log.info("第26轮安全大模型与AI Agent深度平台路由已注册：大模型管理/Agent引擎/代码生成/问答系统/智能报告/大模型控制台，共50+个端点")
except Exception as e:
    log.warning(f"第26轮安全大模型与AI Agent深度平台路由注册失败: {e}")


# ============== 第26轮升级方向2：安全自动化与DevSecOps深度平台路由（50+端点） ==============
try:
    from api_server.devsecops_deep_routes import router as devsecops_deep_router
    app.include_router(devsecops_deep_router)
    log.info("第26轮安全自动化与DevSecOps深度平台路由已注册：CI/CD安全/SAST深度/依赖深度/容器深度/IaC安全/安全即代码/DevSecOps控制台，共50+个端点")
except Exception as e:
    log.warning(f"第26轮安全自动化与DevSecOps深度平台路由注册失败: {e}")


# ============== 第26轮升级方向3：安全运营中心(SOC)深度平台路由（50+端点） ==============
try:
    from api_server.soc_deep_routes import router as soc_deep_router
    app.include_router(soc_deep_router)
    log.info("第26轮安全运营中心(SOC)深度平台路由已注册：SIEM日志/关联规则/告警分诊/事件响应/威胁情报/SOC度量/SOC控制台，共50+个端点")
except Exception as e:
    log.warning(f"第26轮安全运营中心(SOC)深度平台路由注册失败: {e}")


# ============== 第26轮升级方向4：安全培训与认证平台深度路由（50+端点） ==============
try:
    from api_server.security_training_deep_routes import router as security_training_deep_router
    app.include_router(security_training_deep_router)
    log.info("第26轮安全培训与认证平台深度路由已注册：课程体系/实验环境/考试认证/能力评估/企业培训/安全意识/培训控制台，共50+个端点")
except Exception as e:
    log.warning(f"第26轮安全培训与认证平台深度路由注册失败: {e}")


# ============== 第26轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR26
    _PAGES_R26 = [
        ("/security-llm", "security_llm_console.html", "安全大模型与AI Agent深度平台控制台"),
        ("/devsecops-deep", "devsecops_deep_console.html", "安全自动化与DevSecOps深度平台控制台"),
        ("/soc-deep", "soc_deep_console.html", "安全运营中心(SOC)深度平台控制台"),
        ("/security-training-deep", "security_training_deep_console.html", "安全培训与认证平台深度控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R26:
        def _make_page_handler_r26(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r26():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR26(content=_f.read())
                return _HTMLR26(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r26
        _make_page_handler_r26()
    log.info("第26轮新前端页面已注册：/security-llm /devsecops-deep /soc-deep /security-training-deep")
except Exception as e:
    log.warning(f"第26轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第26轮升级方向1：安全大模型与AI Agent深度平台路由" in content:
        print("[INFO] 第26轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第26轮路由注册代码已注入app.py")
    return True


def verify_imports():
    print("\n" + "="*60)
    print("【模块导入验证】")
    print("="*60)
    
    modules = [
        "security_llm.llm_manager", "security_llm.agent_engine",
        "security_llm.code_generator", "security_llm.qa_system",
        "security_llm.smart_report", "security_llm.llm_dashboard",
        "devsecops_deep.cicd_security", "devsecops_deep.sast_deep",
        "devsecops_deep.dependency_deep", "devsecops_deep.container_deep",
        "devsecops_deep.iac_security", "devsecops_deep.security_as_code",
        "devsecops_deep.devsecops_dashboard",
        "soc_deep.siem_logging", "soc_deep.correlation_engine",
        "soc_deep.alert_triage_deep", "soc_deep.incident_response_deep",
        "soc_deep.threat_intel_soc", "soc_deep.soc_metrics",
        "soc_deep.soc_dashboard",
        "security_training_deep.course_system", "security_training_deep.lab_environment",
        "security_training_deep.exam_certification", "security_training_deep.competency_assessment",
        "security_training_deep.enterprise_training", "security_training_deep.security_awareness",
        "security_training_deep.training_dashboard",
        "api_server.security_llm_routes", "api_server.devsecops_deep_routes",
        "api_server.soc_deep_routes", "api_server.security_training_deep_routes",
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
    
    print(f"总计: {len(modules)} 个模块, 通过: {passed}, 失败: {failed}")
    for r in results:
        print(r)
    return failed == 0


def verify_files_exist():
    print("\n" + "="*60)
    print("【文件存在验证】")
    print("="*60)
    
    expected = [
        "security_llm/__init__.py", "security_llm/llm_manager.py",
        "security_llm/agent_engine.py", "security_llm/code_generator.py",
        "security_llm/qa_system.py", "security_llm/smart_report.py",
        "security_llm/llm_dashboard.py",
        "devsecops_deep/__init__.py", "devsecops_deep/cicd_security.py",
        "devsecops_deep/sast_deep.py", "devsecops_deep/dependency_deep.py",
        "devsecops_deep/container_deep.py", "devsecops_deep/iac_security.py",
        "devsecops_deep/security_as_code.py", "devsecops_deep/devsecops_dashboard.py",
        "soc_deep/__init__.py", "soc_deep/siem_logging.py",
        "soc_deep/correlation_engine.py", "soc_deep/alert_triage_deep.py",
        "soc_deep/incident_response_deep.py", "soc_deep/threat_intel_soc.py",
        "soc_deep/soc_metrics.py", "soc_deep/soc_dashboard.py",
        "security_training_deep/__init__.py", "security_training_deep/course_system.py",
        "security_training_deep/lab_environment.py", "security_training_deep/exam_certification.py",
        "security_training_deep/competency_assessment.py", "security_training_deep/enterprise_training.py",
        "security_training_deep/security_awareness.py", "security_training_deep/training_dashboard.py",
        "api_server/security_llm_routes.py", "api_server/devsecops_deep_routes.py",
        "api_server/soc_deep_routes.py", "api_server/security_training_deep_routes.py",
        "api_server/security_llm_console.html", "api_server/devsecops_deep_console.html",
        "api_server/soc_deep_console.html", "api_server/security_training_deep_console.html",
    ]
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
    print("\n" + "="*60)
    print("【API路由验证】")
    print("="*60)
    
    route_mods = [
        ("api_server.security_llm_routes", "security_llm", 50),
        ("api_server.devsecops_deep_routes", "devsecops_deep", 50),
        ("api_server.soc_deep_routes", "soc_deep", 50),
        ("api_server.security_training_deep_routes", "security_training_deep", 50),
    ]
    all_ok = True
    total = 0
    for mod_name, prefix, expected in route_mods:
        try:
            mod = importlib.import_module(mod_name)
            router = getattr(mod, "router", None)
            if router:
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
    print(f"  第26轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print("\n" + "="*60)
    print("【前端页面验证】")
    print("="*60)
    
    html_files = [
        "api_server/security_llm_console.html",
        "api_server/devsecops_deep_console.html",
        "api_server/soc_deep_console.html",
        "api_server/security_training_deep_console.html",
    ]
    total = 0
    valid = 0
    invalid = []
    for html_file in html_files:
        full = os.path.join(PROJECT_ROOT, html_file)
        total += 1
        if os.path.exists(full):
            try:
                with open(full, "r", encoding="utf-8") as f:
                    content = f.read()
                size = len(content)
                has_html = "<html" in content.lower()
                has_script = "<script" in content.lower()
                if has_html and has_script and size > 5000:
                    valid += 1
                    print(f"  [OK] {html_file} ({size} 字节)")
                else:
                    invalid.append((html_file, f"size={size}, html={has_html}, script={has_script}"))
            except Exception as e:
                invalid.append((html_file, str(e)))
        else:
            invalid.append((html_file, "文件不存在"))
    print(f"\n总计: {total} 个页面, 有效: {valid}, 无效: {len(invalid)}")
    if invalid:
        for name, reason in invalid:
            print(f"  - {name}: {reason}")
    return len(invalid) == 0


def verify_app_import():
    print("\n" + "="*60)
    print("【app.py导入验证】")
    print("="*60)
    
    try:
        for mod in list(sys.modules.keys()):
            if mod.startswith("api_server") or mod.startswith("security_llm") or mod.startswith("devsecops_deep") or mod.startswith("soc_deep") or mod.startswith("security_training_deep"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        total_routes = len(routes)
        print(f"  [OK] app.py导入成功，总路由数: {total_routes}")
        
        r26_prefixes = ["/api/v1/security-llm", "/api/v1/devsecops-deep", "/api/v1/soc-deep", "/api/v1/security-training-deep"]
        r26_pages = ["/security-llm", "/devsecops-deep", "/soc-deep", "/security-training-deep"]
        
        for prefix in r26_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        for pr in r26_pages:
            found = any(getattr(r, "path", "") == pr for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 前端页面 {pr}: {'已注册' if found else '未找到'}")
        return True
    except Exception as e:
        print(f"  [FAIL] app.py导入失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print("="*60)
    print("第26轮升级集成与验证脚本")
    print("="*60)
    
    files_ok = verify_files_exist()
    routes_ok = inject_routes()
    imports_ok = verify_imports()
    api_ok = verify_api_routes()
    html_ok = verify_html_pages()
    app_ok = verify_app_import()
    
    print("\n" + "="*60)
    print("验证总结")
    print("="*60)
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
