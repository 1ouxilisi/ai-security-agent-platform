# -*- coding: utf-8 -*-
"""第6轮升级 模块一/模块二 全部验证测试。"""
import os
import sys
import json
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

results = []


def run(name, fn):
    try:
        fn()
        results.append((name, True, ""))
        print(f"[PASS] {name}")
    except Exception as e:
        results.append((name, False, f"{e}\n{traceback.format_exc()}"))
        print(f"[FAIL] {name}: {e}")


# 1. Web 验证器导入
def t1():
    from verification.web_vuln_verifier import WebVulnVerifier
    print("  Web验证器导入OK")
run("1. WebVulnVerifier 导入", t1)


# 2. 服务验证器导入
def t2():
    from verification.service_vuln_verifier import ServiceVulnVerifier
    print("  服务验证器导入OK")
run("2. ServiceVulnVerifier 导入", t2)


# 3. 验证管理器导入
def t3():
    from verification.verification_manager import VerificationManager
    print("  验证管理器导入OK")
run("3. VerificationManager 导入", t3)


# 4. 验证 API 路由导入
def t4():
    from api_server.verification_routes import router
    print(f"  验证API路由注册OK，共{len(router.routes)}个端点")
    assert len(router.routes) >= 7
run("4. verification_routes 路由导入", t4)


# 5. 工具安装器导入
def t5():
    from tools.tool_installer import ToolInstaller
    print("  工具安装器导入OK")
run("5. ToolInstaller 导入", t5)


# 6. WSL 桥接器导入
def t6():
    from tools.wsl_bridge import WSLBridge
    print("  WSL桥接器导入OK")
run("6. WSLBridge 导入", t6)


# 7. WebVulnVerifier 对不存在 URL 应返回 unverifiable
def t7():
    from verification.web_vuln_verifier import WebVulnVerifier
    v = WebVulnVerifier()
    r = v.verify_sql_injection("http://127.0.0.1:9999/test?id=1", "id")
    print("  status=", r.get("status"))
    assert r.get("status") in ("unverifiable", "false_positive"), r
run("7. SQL注入验证不存在URL -> unverifiable", t7)


# 8. match_version_vulnerabilities("Apache", "2.4.49") 应返回 CVE-2021-41773
def t8():
    from verification.service_vuln_verifier import ServiceVulnVerifier
    v = ServiceVulnVerifier()
    r = v.match_version_vulnerabilities("Apache", "2.4.49")
    cves = [m["cve"] for m in r["details"]["matches"]]
    print("  matches=", cves)
    assert "CVE-2021-41773" in cves, r
run("8. match_version_vulnerabilities Apache 2.4.49", t8)


# 9. ToolInstaller.detect_tool("nmap") 返回安装状态
def t9():
    from tools.tool_installer import ToolInstaller
    inst = ToolInstaller()
    r = inst.detect_tool("nmap")
    print("  nmap detect=", r)
    assert "installed" in r
run("9. ToolInstaller.detect_tool(nmap)", t9)


# 10. tools_config.json 是有效 JSON
def t10():
    p = os.path.join(ROOT, "config", "tools_config.json")
    with open(p, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert "tools" in cfg
    sample = cfg["tools"].get("nmap", {})
    for k in ("installed", "version", "last_check", "install_methods"):
        assert k in sample, f"缺少字段 {k}"
    print("  JSON有效，nmap字段:", {k: sample[k] for k in
          ("installed", "version", "install_methods")})
run("10. tools_config.json 有效且含新字段", t10)


print()
print("=" * 60)
passed = sum(1 for _, ok, _ in results if ok)
print(f"通过 {passed}/{len(results)}")
fails = [r for r in results if not r[1]]
if fails:
    print("失败项:")
    for n, _, tb in fails:
        print(f" - {n}\n{tb}")
