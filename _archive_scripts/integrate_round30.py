# -*- coding: utf-8 -*-
"""第30轮升级集成与验证脚本：P1-1 Web渗透全流程 + P2 报告质量提升"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第30轮 P1-1：Web 渗透全流程做透路由（30+端点） ==============
try:
    from api_server.web_pentest_full_routes import router as web_pentest_full_router
    app.include_router(web_pentest_full_router)
    log.info("第30轮P1-1 Web渗透全流程路由已注册：指纹识别/目录扫描/漏洞扫描/利用验证/渗透报告，共30+个端点")
except Exception as e:
    log.warning(f"第30轮P1-1 Web渗透全流程路由注册失败: {e}")


# ============== 第30轮 P2：专业安全报告引擎路由（20+端点） ==============
try:
    from api_server.report_pro_routes import router as report_pro_router
    app.include_router(report_pro_router)
    log.info("第30轮P2 专业安全报告引擎路由已注册：报告生成/历史/对比/图表/导出，共20+个端点")
except Exception as e:
    log.warning(f"第30轮P2 专业安全报告引擎路由注册失败: {e}")


# ============== 第30轮：新前端页面路由（2个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR30
    _PAGES_R30 = [
        ("/web-pentest-full", "web_pentest_full_console.html", "Web渗透全流程控制台"),
        ("/report-pro", "report_pro_console.html", "专业安全报告引擎控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R30:
        def _make_page_handler_r30(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r30():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR30(content=_f.read())
                return _HTMLR30(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r30
        _make_page_handler_r30()
    log.info("第30轮新前端页面已注册：/web-pentest-full /report-pro")
except Exception as e:
    log.warning(f"第30轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第30轮 P1-1：Web 渗透全流程做透路由" in content:
        print("[INFO] 第30轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第30轮路由注册代码已注入app.py")
    return True


def verify_files_exist():
    print("\n" + "=" * 60)
    print("【文件存在验证】")
    print("=" * 60)
    expected = [
        "web_pentest_full/__init__.py",
        "web_pentest_full/fingerprint.py",
        "web_pentest_full/dir_scan.py",
        "web_pentest_full/vuln_scan.py",
        "web_pentest_full/exploit_verify.py",
        "web_pentest_full/pentest_report.py",
        "web_pentest_full/pentest_workflow.py",
        "report_pro/__init__.py",
        "report_pro/report_templates.py",
        "report_pro/report_charts.py",
        "report_pro/report_generator.py",
        "report_pro/report_exporter.py",
        "api_server/web_pentest_full_routes.py",
        "api_server/report_pro_routes.py",
        "api_server/web_pentest_full_console.html",
        "api_server/report_pro_console.html",
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
    print(f"\n总计: {len(expected)} 个文件, 存在: {len(expected)-len(missing)}, "
          f"缺失: {len(missing)}, 总代码行数: {total_lines} 行")
    return len(missing) == 0


def verify_imports():
    print("\n" + "=" * 60)
    print("【模块导入验证】")
    print("=" * 60)
    modules = [
        "web_pentest_full",
        "web_pentest_full.fingerprint",
        "web_pentest_full.dir_scan",
        "web_pentest_full.vuln_scan",
        "web_pentest_full.exploit_verify",
        "web_pentest_full.pentest_report",
        "web_pentest_full.pentest_workflow",
        "report_pro",
        "report_pro.report_templates",
        "report_pro.report_charts",
        "report_pro.report_generator",
        "report_pro.report_exporter",
        "api_server.web_pentest_full_routes",
        "api_server.report_pro_routes",
    ]
    passed = failed = 0
    for mod_name in modules:
        try:
            importlib.import_module(mod_name)
            print(f"  [OK] {mod_name}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {mod_name}: {e}")
            failed += 1
    print(f"\n总计: {len(modules)} 个模块, 通过: {passed}, 失败: {failed}")
    return failed == 0


def verify_api_routes():
    print("\n" + "=" * 60)
    print("【API路由端点计数】")
    print("=" * 60)
    checks = [
        ("api_server.web_pentest_full_routes", "/api/v1/web-pentest-full", 30),
        ("api_server.report_pro_routes", "/api/v1/report-pro", 20),
    ]
    all_ok = True
    for mod_name, _prefix, expected in checks:
        try:
            mod = importlib.import_module(mod_name)
            router = getattr(mod, "router", None)
            if router:
                cnt = len(getattr(router, "routes", []))
                ok_flag = cnt >= expected
                print(f"  [{'OK' if ok_flag else 'WARN'}] {mod_name}: "
                      f"{cnt} 个端点 (预期 >= {expected})")
                if not ok_flag:
                    all_ok = False
        except Exception as e:
            print(f"  [FAIL] {mod_name}: {e}")
            all_ok = False
    return all_ok


def verify_html_pages():
    print("\n" + "=" * 60)
    print("【前端页面验证】")
    print("=" * 60)
    files = [
        "api_server/web_pentest_full_console.html",
        "api_server/report_pro_console.html",
    ]
    ok_cnt = 0
    for f in files:
        full = os.path.join(PROJECT_ROOT, f)
        if os.path.exists(full):
            with open(full, "r", encoding="utf-8") as fh:
                c = fh.read()
            if "<html" in c.lower() and "<script" in c.lower() \
               and len(c) > 5000:
                print(f"  [OK] {f} ({len(c)} 字节)")
                ok_cnt += 1
            else:
                print(f"  [WARN] {f}: 内容不完整 ({len(c)} 字节)")
        else:
            print(f"  [MISSING] {f}")
    return ok_cnt == len(files)


def verify_workflow_units():
    """冒烟：单独跑一次 report_pro 生成，不打外网。"""
    print("\n" + "=" * 60)
    print("【report_pro 单元冒烟】")
    print("=" * 60)
    try:
        from report_pro.report_generator import ReportGenerator, ReportData
        gen = ReportGenerator()
        data = ReportData(
            title="冒烟测试", target="http://example.com",
            findings=[
                {"name": "SQL注入", "severity": "critical",
                 "cvss_score": 9.8, "cwe": "CWE-89"},
                {"name": "XSS", "severity": "medium",
                 "cvss_score": 6.1, "cwe": "CWE-79"},
            ],
            assets=[{"name": "web-01", "critical": 1, "high": 0,
                     "medium": 1, "low": 0}],
        )
        html = gen.generate_html(data)
        md = gen.generate_markdown(data)
        js = gen.generate_json(data)
        assert "<html" in html.lower() and "SQL注入" in html
        assert "# 冒烟测试" in md
        import json as _json
        obj = _json.loads(js)
        assert obj["overall_risk"] == "critical"
        print(f"  [OK] HTML {len(html)} 字节 / MD {len(md)} 字节 / "
              f"JSON {len(js)} 字节")
        return True
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  [FAIL] {e}")
        return False


def main():
    print("=" * 60)
    print("第30轮升级集成与验证脚本")
    print("P1-1 Web渗透全流程做透 + P2 报告质量提升")
    print("=" * 60)
    files_ok = verify_files_exist()
    inj_ok = inject_routes()
    imports_ok = verify_imports()
    routes_ok = verify_api_routes()
    html_ok = verify_html_pages()
    unit_ok = verify_workflow_units()

    print("\n" + "=" * 60)
    print("验证总结")
    print("=" * 60)
    print(f"  文件存在: {'PASS' if files_ok else 'FAIL'}")
    print(f"  路由注入: {'PASS' if inj_ok else 'FAIL'}")
    print(f"  模块导入: {'PASS' if imports_ok else 'FAIL'}")
    print(f"  API路由:  {'PASS' if routes_ok else 'FAIL'}")
    print(f"  前端页面: {'PASS' if html_ok else 'FAIL'}")
    print(f"  单元冒烟: {'PASS' if unit_ok else 'FAIL'}")
    all_pass = all([files_ok, inj_ok, imports_ok, routes_ok,
                    html_ok, unit_ok])
    print(f"\n  总体结果: {'ALL PASS' if all_pass else 'HAS FAILURES'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
