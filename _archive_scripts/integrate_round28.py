# -*- coding: utf-8 -*-
"""第28轮升级方向1：真实工具集成深度增强 — 集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第28轮升级方向1：真实工具集成深度增强路由（60+端点） ==============
try:
    from api_server.real_tools_deep_routes import router as real_tools_deep_router
    app.include_router(real_tools_deep_router)
    log.info("第28轮真实工具集成深度增强路由已注册：Nmap深度/SQLMap深度/Metasploit深度/Nikto/Hydra/John/nuclei/工具编排/控制台数据聚合，共60+个端点")
except Exception as e:
    log.warning(f"第28轮真实工具集成深度增强路由注册失败: {e}")


# ============== 第28轮升级：新前端页面路由 ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR28
    _PAGES_R28 = [
        ("/real-tools-deep", "real_tools_deep_console.html", "真实工具集成深度增强控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R28:
        def _make_page_handler_r28(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r28():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR28(content=_f.read())
                return _HTMLR28(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r28
        _make_page_handler_r28()
    log.info("第28轮新前端页面已注册：/real-tools-deep")
except Exception as e:
    log.warning(f"第28轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第28轮升级方向1：真实工具集成深度增强路由" in content:
        print("[INFO] 第28轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第28轮路由注册代码已注入app.py")
    return True


def verify_imports():
    print("\n" + "=" * 60)
    print("【模块导入验证】")
    print("=" * 60)

    modules = [
        "real_tools_deep",
        "real_tools_deep.nmap_deep",
        "real_tools_deep.sqlmap_deep",
        "real_tools_deep.metasploit_deep",
        "real_tools_deep.other_tools",
        "real_tools_deep.tool_orchestration",
        "real_tools_deep.real_tools_dashboard",
        "api_server.real_tools_deep_routes",
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
    print("\n" + "=" * 60)
    print("【文件存在验证】")
    print("=" * 60)

    expected = [
        "real_tools_deep/__init__.py",
        "real_tools_deep/nmap_deep.py",
        "real_tools_deep/sqlmap_deep.py",
        "real_tools_deep/metasploit_deep.py",
        "real_tools_deep/other_tools.py",
        "real_tools_deep/tool_orchestration.py",
        "real_tools_deep/real_tools_dashboard.py",
        "api_server/real_tools_deep_routes.py",
        "api_server/real_tools_deep_console.html",
    ]
    missing = []
    total_lines = 0
    total_size = 0
    for fpath in expected:
        full = os.path.join(PROJECT_ROOT, fpath)
        if os.path.exists(full):
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.count("\n") + 1
            size = len(content.encode("utf-8"))
            total_lines += lines
            total_size += size
            print(f"  [OK] {fpath} ({lines} 行, {size} 字节)")
        else:
            missing.append(fpath)
            print(f"  [MISSING] {fpath}")
    print(f"\n总计: {len(expected)} 个文件, 存在: {len(expected)-len(missing)}, "
          f"缺失: {len(missing)}, 总代码行数: {total_lines} 行, 总大小: {total_size} 字节")
    return len(missing) == 0


def verify_api_routes():
    print("\n" + "=" * 60)
    print("【API路由验证】")
    print("=" * 60)

    try:
        mod = importlib.import_module("api_server.real_tools_deep_routes")
        router = getattr(mod, "router", None)
        if router:
            routes = getattr(router, "routes", [])
            cnt = len(routes)
            status = "OK" if cnt >= 50 else "WARN"
            print(f"  [{status}] real_tools_deep_routes: {cnt} 个端点 (预期 >= 50)")
            # 打印所有端点
            for r in routes:
                methods = getattr(r, "methods", set())
                path = getattr(r, "path", "")
                print(f"       {','.join(methods):10s} {path}")
            return cnt >= 50
        else:
            print("  [FAIL] router not found")
            return False
    except Exception as e:
        print(f"  [FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_html_page():
    print("\n" + "=" * 60)
    print("【前端页面验证】")
    print("=" * 60)

    html_file = "api_server/real_tools_deep_console.html"
    full = os.path.join(PROJECT_ROOT, html_file)
    if not os.path.exists(full):
        print(f"  [FAIL] {html_file} 不存在")
        return False
    with open(full, "r", encoding="utf-8") as f:
        content = f.read()
    size = len(content.encode("utf-8"))
    has_html = "<html" in content.lower()
    has_script = "<script" in content.lower()
    has_dark_theme = "#0d1117" in content or "#161b22" in content
    has_tabs = content.count("tab-panel") >= 8
    size_ok = size > 15000
    print(f"  文件大小: {size} 字节 ({'OK' if size_ok else 'FAIL'}, 需要>15KB)")
    print(f"  HTML标签: {'OK' if has_html else 'FAIL'}")
    print(f"  JS脚本: {'OK' if has_script else 'FAIL'}")
    print(f"  深色主题: {'OK' if has_dark_theme else 'FAIL'}")
    print(f"  Tab面板数: {content.count('tab-panel')} (需>=8)")
    return size_ok and has_html and has_script and has_dark_theme and has_tabs


def verify_py_compile():
    print("\n" + "=" * 60)
    print("【py_compile 语法检查】")
    print("=" * 60)
    import py_compile
    py_files = [
        "real_tools_deep/__init__.py",
        "real_tools_deep/nmap_deep.py",
        "real_tools_deep/sqlmap_deep.py",
        "real_tools_deep/metasploit_deep.py",
        "real_tools_deep/other_tools.py",
        "real_tools_deep/tool_orchestration.py",
        "real_tools_deep/real_tools_dashboard.py",
        "api_server/real_tools_deep_routes.py",
    ]
    all_ok = True
    for fpath in py_files:
        full = os.path.join(PROJECT_ROOT, fpath)
        try:
            py_compile.compile(full, doraise=True)
            print(f"  [OK] {fpath}")
        except py_compile.PyCompileError as e:
            print(f"  [FAIL] {fpath}: {e}")
            all_ok = False
    return all_ok


def smoke_test():
    print("\n" + "=" * 60)
    print("【功能冒烟测试】")
    print("=" * 60)
    try:
        from real_tools_deep import nmap_deep, sqlmap_deep, metasploit_deep, other_tools, tool_orchestration
        from real_tools_deep.real_tools_dashboard import get_dashboard

        # Nmap 命令构建
        b = nmap_deep.NmapCommandBuilder()
        b.add_target("192.168.1.1").set_scan_type("syn").set_port_range("1-1000").set_timing_template(3)
        cmd = b.build()
        print(f"  [OK] Nmap命令构建: {cmd}")

        # Nmap 模拟扫描
        scanner = nmap_deep.get_scanner()
        result = scanner.scan(["192.168.1.1"])
        print(f"  [OK] Nmap模拟扫描: {len(result.get('parsed',{}).get('hosts',[]))} 台主机")

        # Nmap XML 解析
        parsed = nmap_deep.NmapXMLParser.parse("")
        print(f"  [OK] Nmap XML解析: hosts={len(parsed.get('hosts',[]))}")

        # Nmap 报告生成
        report = nmap_deep.get_report_generator().generate(result)
        print(f"  [OK] Nmap报告生成: risk={report['summary']['risk_label']}")

        # SQLMap 命令构建
        sb = sqlmap_deep.SQLMapCommandBuilder()
        sb.set_target_url("http://t.com/?id=1").set_technique("BEUSTQ").set_level(1).set_risk(1).set_batch()
        scmd = sb.build()
        print(f"  [OK] SQLMap命令构建: {scmd}")

        # SQLMap 模拟扫描
        ss = sqlmap_deep.get_scanner()
        sresult = ss.scan("http://t.com/?id=1")
        print(f"  [OK] SQLMap模拟扫描: injection={sresult.get('parsed',{}).get('injection_found')}")

        # Metasploit 模块搜索
        client = metasploit_deep.get_client()
        exploits = client.module_search("exploits")
        print(f"  [OK] MSF模块搜索: {len(exploits)} 个exploit")

        # Metasploit 模拟利用
        exp = client.execute_exploit("exploit/windows/smb/ms17_010_eternalblue", {"RHOSTS": "10.0.0.1"}, "meterpreter/reverse_tcp")
        print(f"  [OK] MSF模拟利用: {exp.get('status')}")

        # 其他工具版本
        mgr = other_tools.get_manager()
        versions = mgr.get_all_versions()
        print(f"  [OK] 其他工具版本: {list(versions.keys())}")

        # 工作流创建与执行
        engine = tool_orchestration.get_engine()
        inst = engine.create_instance("测试工作流", "recon_workflow", "192.168.1.1")
        exec_result = engine.execute_instance(inst.instance_id)
        print(f"  [OK] 工作流执行: status={exec_result.get('status')}, progress={exec_result.get('progress')}%")

        # Dashboard 总览
        dash = get_dashboard()
        overview = dash.get_overview()
        print(f"  [OK] Dashboard总览: tools={list(overview.get('tools',{}).keys())}")

        print("\n  全部冒烟测试通过!")
        return True
    except Exception as e:
        print(f"  [FAIL] 冒烟测试异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print("=" * 60)
    print("第28轮升级方向1：真实工具集成深度增强 — 集成与验证")
    print("=" * 60)

    files_ok = verify_files_exist()
    compile_ok = verify_py_compile()
    imports_ok = verify_imports()
    api_ok = verify_api_routes()
    html_ok = verify_html_page()
    routes_ok = inject_routes()
    smoke_ok = smoke_test()

    print("\n" + "=" * 60)
    print("验证总结")
    print("=" * 60)
    print(f"  文件存在:   {'PASS' if files_ok else 'FAIL'}")
    print(f"  py_compile: {'PASS' if compile_ok else 'FAIL'}")
    print(f"  模块导入:   {'PASS' if imports_ok else 'FAIL'}")
    print(f"  API路由:    {'PASS' if api_ok else 'FAIL'}")
    print(f"  前端页面:   {'PASS' if html_ok else 'FAIL'}")
    print(f"  路由注入:   {'PASS' if routes_ok else 'FAIL'}")
    print(f"  冒烟测试:   {'PASS' if smoke_ok else 'FAIL'}")
    all_pass = all([files_ok, compile_ok, imports_ok, api_ok, html_ok, routes_ok, smoke_ok])
    print(f"\n  总体结果: {'ALL PASS' if all_pass else 'HAS FAILURES'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
