# -*- coding: utf-8 -*-
"""方向5：真实工具一键安装 + 真实靶场一键部署 + 真实 LLM Key 配置引导
统一集成脚本（幂等）。

用法:
    python integrate_tools_lab_llm.py
"""
import os
import sys
import importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

MARK = "# ============== 全局异常处理器"
INJECT_TAG = "# ============== 方向5：工具安装器/靶场部署/LLM配置 路由"

ROUTES_CODE = '''

''' + INJECT_TAG + ''' ==============
try:
    from api_server.tools_installer_routes import router as _tools_installer_router
    app.include_router(_tools_installer_router)
    log.info("方向5 工具一键安装路由已注册")
except Exception as _e:
    log.warning(f"方向5 工具安装路由注册失败: {_e}")

try:
    from api_server.target_lab_real_routes import router as _target_lab_real_router
    app.include_router(_target_lab_real_router)
    log.info("方向5 真实靶场部署路由已注册")
except Exception as _e:
    log.warning(f"方向5 靶场路由注册失败: {_e}")

try:
    from api_server.llm_config_real_routes import router as _llm_config_real_router
    app.include_router(_llm_config_real_router)
    log.info("方向5 LLM 配置引导路由已注册")
except Exception as _e:
    log.warning(f"方向5 LLM 配置路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLR_D5
    _PAGES_D5 = [
        ("/tools-installer", "tools_installer_console.html", "工具一键安装"),
        ("/target-lab-real", "target_lab_real_console.html", "真实靶场部署"),
        ("/llm-config-real", "llm_config_real_console.html", "LLM Key 配置引导"),
    ]
    for _route, _fname, _desc in _PAGES_D5:
        def _make_page_d5(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_d5():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_D5(content=_f.read())
                return _HTMLR_D5(content=f"<h1>{desc}页面未找到</h1>")
            return _page_d5
        _make_page_d5()
    log.info("方向5 三个前端控制台已注册：/tools-installer /target-lab-real /llm-config-real")
except Exception as _e:
    log.warning(f"方向5 前端页面注册失败: {_e}")

'''


def inject_routes() -> bool:
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if INJECT_TAG in content:
        print("[INFO] 方向5 路由已存在，跳过注入")
        return True
    if MARK not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(MARK, ROUTES_CODE + "\n" + MARK)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 方向5 路由注册代码已注入 app.py")
    return True


def verify_files() -> bool:
    print("\n" + "=" * 60)
    print("【文件存在验证】")
    print("=" * 60)
    expected = [
        "tools_installer/__init__.py",
        "tools_installer/tool_registry.py",
        "tools_installer/tool_detector.py",
        "tools_installer/tool_installer.py",
        "tools_installer/package_manager.py",
        "tools_installer/tools_dashboard.py",
        "target_lab_real/__init__.py",
        "target_lab_real/lab_registry.py",
        "target_lab_real/docker_manager.py",
        "target_lab_real/lab_deployer.py",
        "target_lab_real/lab_config.py",
        "target_lab_real/lab_template.py",
        "target_lab_real/simulated_lab.py",
        "target_lab_real/labs_dashboard.py",
        "llm_config/__init__.py",
        "llm_config/llm_providers.py",
        "llm_config/llm_config_manager.py",
        "llm_config/llm_tester.py",
        "llm_config/llm_usage.py",
        "llm_config/llm_model_comparison.py",
        "llm_config/llm_dashboard.py",
        "api_server/tools_installer_routes.py",
        "api_server/tools_installer_console.html",
        "api_server/target_lab_real_routes.py",
        "api_server/target_lab_real_console.html",
        "api_server/llm_config_real_routes.py",
        "api_server/llm_config_real_console.html",
    ]
    missing = []
    total = 0
    for fp in expected:
        full = os.path.join(PROJECT_ROOT, fp)
        if os.path.exists(full):
            n = os.path.getsize(full)
            total += n
            print(f"  [OK] {fp} ({n} 字节)")
        else:
            missing.append(fp)
            print(f"  [MISSING] {fp}")
    print(f"\n共 {len(expected)} 文件，缺失 {len(missing)}，合计 {total} 字节")
    return not missing


def verify_imports() -> bool:
    print("\n" + "=" * 60)
    print("【模块导入验证】")
    print("=" * 60)
    mods = [
        "tools_installer", "tools_installer.tool_registry",
        "tools_installer.package_manager", "tools_installer.tool_detector",
        "tools_installer.tool_installer", "tools_installer.tools_dashboard",
        "target_lab_real", "target_lab_real.lab_registry",
        "target_lab_real.docker_manager", "target_lab_real.lab_deployer",
        "target_lab_real.lab_config", "target_lab_real.lab_template",
        "target_lab_real.simulated_lab", "target_lab_real.labs_dashboard",
        "llm_config", "llm_config.llm_providers",
        "llm_config.llm_config_manager", "llm_config.llm_tester",
        "llm_config.llm_usage", "llm_config.llm_model_comparison",
        "llm_config.llm_dashboard",
        "api_server.tools_installer_routes",
        "api_server.target_lab_real_routes",
        "api_server.llm_config_real_routes",
    ]
    passed = failed = 0
    for m in mods:
        try:
            importlib.import_module(m)
            print(f"  [OK] {m}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] {m}: {e}")
            failed += 1
    print(f"\n{len(mods)} 模块，通过 {passed}，失败 {failed}")
    return failed == 0


def verify_endpoints() -> bool:
    print("\n" + "=" * 60)
    print("【API 端点计数】")
    print("=" * 60)
    checks = [
        ("api_server.tools_installer_routes", 40),
        ("api_server.target_lab_real_routes", 40),
        ("api_server.llm_config_real_routes", 40),
    ]
    all_ok = True
    for mod, need in checks:
        try:
            m = importlib.import_module(mod)
            cnt = len(getattr(m.router, "routes", []))
            ok = cnt >= need
            print(f"  [{'OK' if ok else 'WARN'}] {mod}: {cnt} 端点 (>= {need})")
            all_ok &= ok
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] {mod}: {e}")
            all_ok = False
    return all_ok


def verify_smoke() -> bool:
    print("\n" + "=" * 60)
    print("【业务冒烟】")
    print("=" * 60)
    try:
        # 工具安装器
        from tools_installer.tool_registry import get_native_tools, get_python_libs
        from tools_installer.package_manager import detect_all
        from tools_installer.tool_detector import detect_one
        from tools_installer.tool_registry import find_tool
        assert len(get_native_tools()) > 20
        assert len(get_python_libs()) > 15
        print(f"  [OK] 工具注册表: 原生 {len(get_native_tools())} / "
              f"Python库 {len(get_python_libs())}")
        pm = detect_all()
        print(f"  [OK] 包管理器探测: {list(pm.keys())}")
        info = detect_one(find_tool("git"))
        print(f"  [OK] 工具检测 git -> installed={info['installed']} "
              f"version={info.get('version')}")

        # 靶场
        from target_lab_real.lab_registry import list_labs
        from target_lab_real.docker_manager import docker_available
        from target_lab_real.lab_deployer import deploy, stop, list_instances
        assert len(list_labs()) >= 8
        dkr = docker_available()
        print(f"  [OK] 靶场注册表: {len(list_labs())} 个; docker={dkr['available']}")
        r = deploy("dvwa")
        assert r["success"]
        inst_id = r["data"]["instance_id"]
        print(f"  [OK] 靶场部署 dvwa -> mode={r['data']['mode']} "
              f"url={r['data']['url']}")
        stop(inst_id)
        print(f"  [OK] 靶场停止: instances={len(list_instances())}")

        # LLM
        from llm_config.llm_providers import list_providers
        from llm_config.llm_config_manager import get_config_manager
        from llm_config.llm_usage import record_call, stats_range
        assert len(list_providers()) >= 8
        print(f"  [OK] LLM 提供商: {len(list_providers())} 个")
        cm = get_config_manager()
        cm.save_key("deepseek", "sk-test-dummy", model="deepseek-chat")
        st = cm.status()
        assert st["total_configured"] >= 1
        print(f"  [OK] LLM Key 加密存储: configured={st['total_configured']} "
              f"enc={st['encryption']}")
        record_call("deepseek", "deepseek-chat", 100, 50, 1200)
        u = stats_range(86400)
        assert u["total_calls"] >= 1
        print(f"  [OK] 用量统计: calls={u['total_calls']}")
        return True
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"  [FAIL] {e}")
        return False


def main() -> int:
    print("=" * 60)
    print("方向5：工具安装器 + 靶场部署 + LLM 配置引导 集成")
    print("=" * 60)
    f = verify_files()
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
