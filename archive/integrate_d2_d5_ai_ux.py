# -*- coding: utf-8 -*-
"""方向2（AI能力大升级）+ 方向5（用户体验大升级）集成与验证脚本。

用法: python integrate_d2_d5_ai_ux.py
"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 方向2：AI 能力大升级路由（26 端点） ==============
try:
    from api_server.ai_upgrade_routes import router as ai_upgrade_router
    app.include_router(ai_upgrade_router)
    log.info("方向2 AI能力大升级路由已注册：LLM接入/漏洞分析/报告生成/智能问答/攻击链/SRC，共26个端点")
except Exception as e:
    log.warning(f"方向2 AI能力大升级路由注册失败: {e}")


# ============== 方向5：用户体验大升级路由（26 端点） ==============
try:
    from api_server.ux_upgrade_routes import router as ux_upgrade_router
    app.include_router(ux_upgrade_router)
    log.info("方向5 用户体验大升级路由已注册：超级首页/智能引导/移动端/暗色主题/全局搜索，共26个端点")
except Exception as e:
    log.warning(f"方向5 用户体验大升级路由注册失败: {e}")


# ============== 方向2+5：新前端页面路由（2个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_D25
    _PAGES_D25 = [
        ("/ai-upgrade", "ai_upgrade_console.html", "AI 能力升级控制台"),
        ("/ux-upgrade", "ux_upgrade_console.html", "UX 升级控制台"),
    ]
    for _route, _fname, _desc in _PAGES_D25:
        def _make_page_handler_d25(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_d25():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_D25(content=_f.read())
                return _HTMLR_D25(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_d25
        _make_page_handler_d25()
    log.info("方向2+5 前端页面已注册：/ai-upgrade /ux-upgrade")
except Exception as e:
    log.warning(f"方向2+5 前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "方向2：AI 能力大升级路由" in content:
        print("[INFO] 方向2+5 路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 方向2+5 路由注册代码已注入 app.py")
    return True


def verify_files_exist():
    print("\n" + "=" * 60)
    print("【文件存在验证】")
    print("=" * 60)
    expected = [
        "ai_upgrade/__init__.py",
        "ai_upgrade/llm_integration.py",
        "ai_upgrade/vuln_analyzer.py",
        "ai_upgrade/report_writer.py",
        "ai_upgrade/smart_qa.py",
        "ai_upgrade/src_assistant.py",
        "ai_upgrade/ai_upgrade_dashboard.py",
        "ux_upgrade/__init__.py",
        "ux_upgrade/super_homepage_v2.py",
        "ux_upgrade/smart_guide_v2.py",
        "ux_upgrade/mobile_adaptive.py",
        "ux_upgrade/dark_theme.py",
        "ux_upgrade/global_search_v2.py",
        "ux_upgrade/ux_upgrade_dashboard.py",
        "api_server/ai_upgrade_routes.py",
        "api_server/ux_upgrade_routes.py",
        "api_server/ai_upgrade_console.html",
        "api_server/ux_upgrade_console.html",
    ]
    missing = []
    total = 0
    for fp in expected:
        full = os.path.join(PROJECT_ROOT, fp)
        if os.path.exists(full):
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                n = len(f.read())
            total += n
            flag = "OK"
            print(f"  [{flag}] {fp} ({n} 字节)")
        else:
            missing.append(fp)
            print(f"  [MISSING] {fp}")
    print(f"\n共 {len(expected)} 文件，缺失 {len(missing)}，合计 {total} 字节")
    return len(missing) == 0


def verify_imports():
    print("\n" + "=" * 60)
    print("【模块导入验证】")
    print("=" * 60)
    modules = [
        "ai_upgrade", "ai_upgrade.llm_integration", "ai_upgrade.vuln_analyzer",
        "ai_upgrade.report_writer", "ai_upgrade.smart_qa",
        "ai_upgrade.src_assistant", "ai_upgrade.ai_upgrade_dashboard",
        "ux_upgrade", "ux_upgrade.super_homepage_v2", "ux_upgrade.smart_guide_v2",
        "ux_upgrade.mobile_adaptive", "ux_upgrade.dark_theme",
        "ux_upgrade.global_search_v2", "ux_upgrade.ux_upgrade_dashboard",
        "api_server.ai_upgrade_routes", "api_server.ux_upgrade_routes",
    ]
    passed = failed = 0
    for m in modules:
        try:
            importlib.import_module(m)
            print(f"  [OK] {m}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {m}: {e}")
            failed += 1
    print(f"\n{len(modules)} 模块，通过 {passed}，失败 {failed}")
    return failed == 0


def verify_endpoints():
    print("\n" + "=" * 60)
    print("【API 端点计数】")
    print("=" * 60)
    checks = [
        ("api_server.ai_upgrade_routes", 25),
        ("api_server.ux_upgrade_routes", 25),
    ]
    all_ok = True
    for mod, need in checks:
        try:
            m = importlib.import_module(mod)
            cnt = len(getattr(m.router, "routes", []))
            ok_flag = cnt >= need
            print(f"  [{'OK' if ok_flag else 'WARN'}] {mod}: {cnt} 端点 (>= {need})")
            all_ok &= ok_flag
        except Exception as e:
            print(f"  [FAIL] {mod}: {e}")
            all_ok = False
    return all_ok


def verify_smoke():
    print("\n" + "=" * 60)
    print("【业务冒烟】")
    print("=" * 60)
    try:
        # AI：漏洞分析
        from ai_upgrade.vuln_analyzer import get_vuln_analyzer
        r = get_vuln_analyzer().analyze_one(
            {"name": "SQL注入", "type": "sql_injection", "has_poc": True})
        assert r["severity"] in ("critical", "high")
        print(f"  [OK] 漏洞智能分析 -> {r['severity']} CVSS={r['cvss_score']}")

        # AI：报告生成
        from ai_upgrade.report_writer import get_report_writer
        rep = get_report_writer().generate("demo.com", [
            {"name": "SQL注入", "type": "sql_injection"},
            {"name": "SSRF", "type": "ssrf"}])
        assert rep["overview"]["total"] == 2
        print(f"  [OK] 报告自动生成 engine={rep['engine']}")

        # AI：智能问答
        from ai_upgrade.smart_qa import get_smart_qa
        a = get_smart_qa().ask("这个网站有什么风险？")
        assert a["answer"]
        print(f"  [OK] 智能问答 engine={a['engine']}")

        # AI：攻击链规划 + 动态调整
        from ai_upgrade.ai_upgrade_dashboard import get_ai_dashboard
        ch = get_ai_dashboard().plan_chain("demo.com", [
            {"name": "SQL注入", "type": "sql_injection"}])
        assert len(ch["steps"]) >= 5
        adj = get_ai_dashboard().adjust_step(ch["chain_id"], 1, "waf 拦截")
        assert adj["success"]
        print(f"  [OK] 攻击链规划 {len(ch['steps'])} 步 + 动态调整")

        # AI：SRC
        from ai_upgrade.src_assistant import get_src_assistant
        t = get_src_assistant().analyze_target("example.com")
        assert t["attack_surfaces"]
        sub = get_src_assistant().write_submission(
            "example.com", {"name": "未授权API", "type": "weak_auth"}, "butian")
        assert sub["title"]
        print("  [OK] SRC 攻击面分析 + 提交报告生成")

        # UX：首页/搜索/主题/引导/移动端
        from ux_upgrade.super_homepage_v2 import get_homepage_v2
        assert get_homepage_v2().quick_action("quick_scan")["launched"]
        from ux_upgrade.global_search_v2 import get_global_search_v2
        assert get_global_search_v2().search("sql")["total"] >= 1
        from ux_upgrade.dark_theme import get_dark_theme
        assert get_dark_theme().current()["mode"] == "dark"
        from ux_upgrade.smart_guide_v2 import get_smart_guide_v2
        assert get_smart_guide_v2().should_start("u_smoke") is True
        from ux_upgrade.mobile_adaptive import get_mobile_adaptive
        assert get_mobile_adaptive().detect(375)["is_mobile"] is True
        print("  [OK] UX：首页/全局搜索/暗色主题/智能引导/移动端")
        return True
    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"  [FAIL] {e}")
        return False


def main():
    print("=" * 60)
    print("方向2+5 集成：AI 能力大升级 + 用户体验大升级")
    print("=" * 60)
    f = verify_files_exist()
    imp = verify_imports()
    ep = verify_endpoints()
    smk = verify_smoke()
    inj = inject_routes()
    print("\n" + "=" * 60)
    print("总结")
    print("=" * 60)
    print(f"  文件存在: {'PASS' if f else 'FAIL'}")
    print(f"  模块导入: {'PASS' if imp else 'FAIL'}")
    print(f"  API端点:  {'PASS' if ep else 'FAIL'}")
    print(f"  业务冒烟: {'PASS' if smk else 'FAIL'}")
    print(f"  路由注入: {'PASS' if inj else 'FAIL'}")
    allp = all([f, imp, ep, smk, inj])
    print(f"\n  总体: {'ALL PASS' if allp else 'HAS FAILURES'}")
    return 0 if allp else 1


if __name__ == "__main__":
    sys.exit(main())
