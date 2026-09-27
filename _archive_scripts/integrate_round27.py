# -*- coding: utf-8 -*-
"""第27轮升级集成与验证脚本"""
import os, sys, importlib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
APP_PY = os.path.join(PROJECT_ROOT, "api_server", "app.py")

ROUTES_CODE = '''

# ============== 第27轮升级方向1：安全知识图谱与智能推理路由（50+端点） ==============
try:
    from api_server.security_kg_routes import router as security_kg_router
    app.include_router(security_kg_router)
    log.info("第27轮安全知识图谱与智能推理路由已注册：知识图谱构建/攻击路径推理/漏洞关联/威胁传播/知识推理/智能问答/知识图谱控制台，共50+个端点")
except Exception as e:
    log.warning(f"第27轮安全知识图谱与智能推理路由注册失败: {e}")


# ============== 第27轮升级方向2：安全Fuzzing与模糊测试平台路由（50+端点） ==============
try:
    from api_server.fuzzing_platform_routes import router as fuzzing_platform_router
    app.include_router(fuzzing_platform_router)
    log.info("第27轮安全Fuzzing与模糊测试平台路由已注册：协议Fuzzing/文件Fuzzing/API Fuzzing/浏览器Fuzzing/内核Fuzzing/Fuzzing管理/Fuzzing控制台，共50+个端点")
except Exception as e:
    log.warning(f"第27轮安全Fuzzing与模糊测试平台路由注册失败: {e}")


# ============== 第27轮升级方向3：二进制逆向与漏洞挖掘路由（50+端点） ==============
try:
    from api_server.binary_reverse_routes import router as binary_reverse_router
    app.include_router(binary_reverse_router)
    log.info("第27轮二进制逆向与漏洞挖掘路由已注册：反汇编引擎/反编译引擎/漏洞挖掘/补丁对比/恶意代码分析/壳检测脱壳/二进制逆向控制台，共50+个端点")
except Exception as e:
    log.warning(f"第27轮二进制逆向与漏洞挖掘路由注册失败: {e}")


# ============== 第27轮升级方向4：区块链与Web3安全路由（50+端点） ==============
try:
    from api_server.web3_security_routes import router as web3_security_router
    app.include_router(web3_security_router)
    log.info("第27轮区块链与Web3安全路由已注册：智能合约安全/DeFi安全/NFT安全/DAO安全/节点安全/加密货币安全/Web3安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第27轮区块链与Web3安全路由注册失败: {e}")


# ============== 第27轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR27
    _PAGES_R27 = [
        ("/security-kg", "security_kg_console.html", "安全知识图谱与智能推理控制台"),
        ("/fuzzing-platform", "fuzzing_platform_console.html", "安全Fuzzing与模糊测试平台控制台"),
        ("/binary-reverse", "binary_reverse_console.html", "二进制逆向与漏洞挖掘控制台"),
        ("/web3-security", "web3_security_console.html", "区块链与Web3安全控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R27:
        def _make_page_handler_r27(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r27():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR27(content=_f.read())
                return _HTMLR27(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r27
        _make_page_handler_r27()
    log.info("第27轮新前端页面已注册：/security-kg /fuzzing-platform /binary-reverse /web3-security")
except Exception as e:
    log.warning(f"第27轮新前端页面注册失败: {e}")

'''


def inject_routes():
    if not os.path.exists(APP_PY):
        print(f"[ERROR] app.py not found: {APP_PY}")
        return False
    with open(APP_PY, "r", encoding="utf-8") as f:
        content = f.read()
    if "第27轮升级方向1：安全知识图谱与智能推理路由" in content:
        print("[INFO] 第27轮路由已存在，跳过注入")
        return True
    marker = "# ============== 全局异常处理器"
    if marker not in content:
        print("[ERROR] 未找到全局异常处理器标记点")
        return False
    content = content.replace(marker, ROUTES_CODE + "\n" + marker)
    with open(APP_PY, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] 第27轮路由注册代码已注入app.py")
    return True


def verify_imports():
    print("\n" + "="*60)
    print("【模块导入验证】")
    print("="*60)
    
    modules = [
        "security_kg.kg_builder", "security_kg.attack_path",
        "security_kg.vuln_correlation", "security_kg.threat_propagation",
        "security_kg.reasoning_engine", "security_kg.kg_qa",
        "security_kg.kg_dashboard",
        "fuzzing_platform.protocol_fuzzer", "fuzzing_platform.file_fuzzer",
        "fuzzing_platform.api_fuzzer", "fuzzing_platform.browser_fuzzer",
        "fuzzing_platform.kernel_fuzzer", "fuzzing_platform.fuzzing_manager",
        "fuzzing_platform.fuzzing_dashboard",
        "binary_reverse.disassembler", "binary_reverse.decompiler",
        "binary_reverse.vuln_miner", "binary_reverse.patch_diff",
        "binary_reverse.malware_analysis", "binary_reverse.pack_unpack",
        "binary_reverse.binary_dashboard",
        "web3_security.smart_contract", "web3_security.defi_security",
        "web3_security.nft_security", "web3_security.dao_security",
        "web3_security.node_security", "web3_security.crypto_security",
        "web3_security.web3_dashboard",
        "api_server.security_kg_routes", "api_server.fuzzing_platform_routes",
        "api_server.binary_reverse_routes", "api_server.web3_security_routes",
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
        "security_kg/__init__.py", "security_kg/kg_builder.py",
        "security_kg/attack_path.py", "security_kg/vuln_correlation.py",
        "security_kg/threat_propagation.py", "security_kg/reasoning_engine.py",
        "security_kg/kg_qa.py", "security_kg/kg_dashboard.py",
        "fuzzing_platform/__init__.py", "fuzzing_platform/protocol_fuzzer.py",
        "fuzzing_platform/file_fuzzer.py", "fuzzing_platform/api_fuzzer.py",
        "fuzzing_platform/browser_fuzzer.py", "fuzzing_platform/kernel_fuzzer.py",
        "fuzzing_platform/fuzzing_manager.py", "fuzzing_platform/fuzzing_dashboard.py",
        "binary_reverse/__init__.py", "binary_reverse/disassembler.py",
        "binary_reverse/decompiler.py", "binary_reverse.vuln_miner.py",
        "binary_reverse.patch_diff.py", "binary_reverse.malware_analysis.py",
        "binary_reverse.pack_unpack.py", "binary_reverse.binary_dashboard.py",
        "web3_security/__init__.py", "web3_security.smart_contract.py",
        "web3_security.defi_security.py", "web3_security.nft_security.py",
        "web3_security.dao_security.py", "web3_security.node_security.py",
        "web3_security.crypto_security.py", "web3_security.web3_dashboard.py",
        "api_server/security_kg_routes.py", "api_server/fuzzing_platform_routes.py",
        "api_server/binary_reverse_routes.py", "api_server/web3_security_routes.py",
        "api_server/security_kg_console.html", "api_server/fuzzing_platform_console.html",
        "api_server/binary_reverse_console.html", "api_server/web3_security_console.html",
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
        ("api_server.security_kg_routes", "security_kg", 50),
        ("api_server.fuzzing_platform_routes", "fuzzing_platform", 50),
        ("api_server.binary_reverse_routes", "binary_reverse", 50),
        ("api_server.web3_security_routes", "web3_security", 50),
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
    print(f"  第27轮API端点总数: {total}")
    return all_ok


def verify_html_pages():
    print("\n" + "="*60)
    print("【前端页面验证】")
    print("="*60)
    
    html_files = [
        "api_server/security_kg_console.html",
        "api_server/fuzzing_platform_console.html",
        "api_server/binary_reverse_console.html",
        "api_server/web3_security_console.html",
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
            if mod.startswith("api_server") or mod.startswith("security_kg") or mod.startswith("fuzzing_platform") or mod.startswith("binary_reverse") or mod.startswith("web3_security"):
                del sys.modules[mod]
        from api_server.app import app
        routes = getattr(app, "routes", [])
        total_routes = len(routes)
        print(f"  [OK] app.py导入成功，总路由数: {total_routes}")
        
        r27_prefixes = ["/api/v1/security-kg", "/api/v1/fuzzing-platform", "/api/v1/binary-reverse", "/api/v1/web3-security"]
        r27_pages = ["/security-kg", "/fuzzing-platform", "/binary-reverse", "/web3-security"]
        
        for prefix in r27_prefixes:
            found = any(prefix in getattr(r, "path", "") for r in routes)
            print(f"  {'[OK]' if found else '[FAIL]'} 路由前缀 {prefix}: {'已注册' if found else '未找到'}")
        for pr in r27_pages:
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
    print("第27轮升级集成与验证脚本")
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
