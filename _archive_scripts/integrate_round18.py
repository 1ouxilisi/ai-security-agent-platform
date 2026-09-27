# -*- coding: utf-8 -*-
"""第18轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第18轮升级方向1：邮件安全路由（30+端点） ==============
try:
    from api_server.email_security_routes import router as email_security_router
    app.include_router(email_security_router)
    log.info("第18轮邮件安全路由已注册：钓鱼检测/BEC检测/邮件认证/附件沙箱/威胁情报/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第18轮邮件安全路由注册失败: {e}")


# ============== 第18轮升级方向2：容器与Kubernetes安全路由（30+端点） ==============
try:
    from api_server.container_security_routes import router as container_security_router
    app.include_router(container_security_router)
    log.info("第18轮容器与K8s安全路由已注册：镜像扫描/运行时安全/K8s配置审计/K8s运行时/基础设施/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第18轮容器与K8s安全路由注册失败: {e}")


# ============== 第18轮升级方向3：漏洞赏金/SRC管理平台路由（30+端点） ==============
try:
    from api_server.bug_bounty_routes import router as bug_bounty_router
    app.include_router(bug_bounty_router)
    log.info("第18轮漏洞赏金/SRC平台路由已注册：项目管理/漏洞提交/白帽社区/赏金财务/漏洞生命周期/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第18轮漏洞赏金/SRC平台路由注册失败: {e}")


# ============== 第18轮升级方向4：CTF训练平台路由（30+端点） ==============
try:
    from api_server.ctf_platform_routes import router as ctf_platform_router
    app.include_router(ctf_platform_router)
    log.info("第18轮CTF训练平台路由已注册：题目靶场/竞赛赛事/解题验证/学习路径/战队管理/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第18轮CTF训练平台路由注册失败: {e}")


# ============== 第18轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR18
    _PAGES_R18 = [
        ("/email-security", "email_security_console.html", "邮件安全控制台"),
        ("/container-security", "container_security_console.html", "容器与Kubernetes安全控制台"),
        ("/bug-bounty", "bug_bounty_console.html", "漏洞赏金/SRC管理平台控制台"),
        ("/ctf-platform", "ctf_platform_console.html", "CTF训练平台控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R18:
        def _make_page_handler_r18(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r18():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR18(content=_f.read())
                return _HTMLR18(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r18
        _make_page_handler_r18()
    log.info("第18轮新前端页面已注册：/email-security /container-security /bug-bounty /ctf-platform")
except Exception as e:
    log.warning(f"第18轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第18轮升级方向1：邮件安全路由" in content:
        print("[INFO] 第18轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第18轮路由注册代码已注入app.py")
    return True


def verify_imports():
    modules = [
        "email_security.phishing_detector", "email_security.bec_detector",
        "email_security.email_authentication", "email_security.attachment_sandbox",
        "email_security.email_threat_intel", "email_security.email_dashboard",
        "container_security.image_scanner", "container_security.runtime_security",
        "container_security.k8s_config_audit", "container_security.k8s_runtime_security",
        "container_security.infrastructure_security", "container_security.container_dashboard",
        "bug_bounty.program_manager", "bug_bounty.submission_workflow",
        "bug_bounty.hunter_community", "bug_bounty.bounty_finance",
        "bug_bounty.vulnerability_lifecycle", "bug_bounty.src_dashboard",
        "api_server.ctf_platform.challenge_manager", "api_server.ctf_platform.competition_manager",
        "api_server.ctf_platform.challenge_solver", "api_server.ctf_platform.learning_path",
        "api_server.ctf_platform.team_manager", "api_server.ctf_platform.ctf_dashboard",
        "api_server.email_security_routes", "api_server.container_security_routes",
        "api_server.bug_bounty_routes", "api_server.ctf_platform_routes",
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
        "email_security/__init__.py", "email_security/phishing_detector.py",
        "email_security/bec_detector.py", "email_security/email_authentication.py",
        "email_security/attachment_sandbox.py", "email_security/email_threat_intel.py",
        "email_security/email_dashboard.py",
        "container_security/__init__.py", "container_security/image_scanner.py",
        "container_security/runtime_security.py", "container_security/k8s_config_audit.py",
        "container_security/k8s_runtime_security.py", "container_security/infrastructure_security.py",
        "container_security/container_dashboard.py",
        "bug_bounty/__init__.py", "bug_bounty/program_manager.py",
        "bug_bounty/submission_workflow.py", "bug_bounty/hunter_community.py",
        "bug_bounty/bounty_finance.py", "bug_bounty/vulnerability_lifecycle.py",
        "bug_bounty/src_dashboard.py",
        "api_server/ctf_platform/__init__.py", "api_server/ctf_platform/challenge_manager.py",
        "api_server/ctf_platform/competition_manager.py", "api_server/ctf_platform/challenge_solver.py",
        "api_server/ctf_platform/learning_path.py", "api_server/ctf_platform/team_manager.py",
        "api_server/ctf_platform/ctf_dashboard.py",
        "api_server/email_security_routes.py", "api_server/container_security_routes.py",
        "api_server/bug_bounty_routes.py", "api_server/ctf_platform_routes.py",
        "api_server/email_security_console.html", "api_server/container_security_console.html",
        "api_server/bug_bounty_console.html", "api_server/ctf_platform_console.html",
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
        ("api_server.email_security_routes", "email_security", 30),
        ("api_server.container_security_routes", "container_security", 30),
        ("api_server.bug_bounty_routes", "bug_bounty", 30),
        ("api_server.ctf_platform_routes", "ctf_platform", 30),
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
    print(f"  第18轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print(f"\n=== 前端页面验证 ===")
    pages = [
        "api_server/email_security_console.html",
        "api_server/container_security_console.html",
        "api_server/bug_bounty_console.html",
        "api_server/ctf_platform_console.html",
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
            if mod.startswith("api_server") or mod.startswith("email_security") or mod.startswith("container_security") or mod.startswith("bug_bounty") or mod.startswith("ctf_platform"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        print(f"  [OK] app.py导入成功，总路由数: {len(routes)}")
        r18_prefixes = ["/api/v1/email-security", "/api/v1/container-security", "/api/v1/bug-bounty", "/api/v1/ctf-platform"]
        for prefix in r18_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        page_routes = ["/email-security", "/container-security", "/bug-bounty", "/ctf-platform"]
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
    print("第18轮升级集成与验证脚本")
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
