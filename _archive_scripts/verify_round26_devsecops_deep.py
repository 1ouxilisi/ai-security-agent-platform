# -*- coding: utf-8 -*-
"""第26轮方向2 DevSecOps Deep 验证脚本。"""
from __future__ import annotations
import os, sys, py_compile, io

ROOT = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent"
os.chdir(ROOT)
sys.path.insert(0, ROOT)

MODULES = [
    "devsecops_deep",
    "devsecops_deep.cicd_security",
    "devsecops_deep.sast_deep",
    "devsecops_deep.dependency_deep",
    "devsecops_deep.container_deep",
    "devsecops_deep.iac_security",
    "devsecops_deep.security_as_code",
    "devsecops_deep.devsecops_dashboard",
]
PYFILES = [
    r"devsecops_deep\__init__.py",
    r"devsecops_deep\cicd_security.py",
    r"devsecops_deep\sast_deep.py",
    r"devsecops_deep\dependency_deep.py",
    r"devsecops_deep\container_deep.py",
    r"devsecops_deep\iac_security.py",
    r"devsecops_deep\security_as_code.py",
    r"devsecops_deep\devsecops_dashboard.py",
    r"api_server\devsecops_deep_routes.py",
]

print("=" * 60)
print("1. py_compile 语法检查")
print("=" * 60)
syntax_ok = True
for f in PYFILES:
    try:
        py_compile.compile(os.path.join(ROOT, f), doraise=True)
        print(f"  [OK] {f}")
    except Exception as e:
        syntax_ok = False
        print(f"  [FAIL] {f}: {e}")
print(f"语法检查结果: {'全部通过' if syntax_ok else '存在错误'}")

print()
print("=" * 60)
print("2. 独立 import 验证")
print("=" * 60)
import_ok = True
for m in MODULES:
    try:
        __import__(m)
        print(f"  [OK] import {m}")
    except Exception as e:
        import_ok = False
        print(f"  [FAIL] import {m}: {e}")

print()
print("=" * 60)
print("3. 路由模块 import + 端点计数")
print("=" * 60)
try:
    from api_server import devsecops_deep_routes as R
    print("  [OK] import api_server.devsecops_deep_routes")
    paths = []
    for r in R.router.routes:
        paths.append((r.path, sorted(r.methods)))
    print(f"  路由前缀: {R.router.prefix}")
    print(f"  API 端点总数: {len(paths)}")
    for p, m in paths:
        print(f"     {','.join(m):20s} {p}")
except Exception as e:
    import_ok = False
    print(f"  [FAIL] routes import: {e}")
    import traceback; traceback.print_exc()

print()
print("=" * 60)
print("4. HTML 文件大小检查")
print("=" * 60)
html_path = os.path.join(ROOT, r"api_server\devsecops_deep_console.html")
sz = os.path.getsize(html_path)
print(f"  文件: {html_path}")
print(f"  大小: {sz} bytes = {sz/1024:.1f} KB")
print(f"  要求 > 15KB (15360 bytes): {'PASS' if sz > 15360 else 'FAIL'}")

print()
print("=" * 60)
print("5. 真实功能冒烟测试")
print("=" * 60)

# 5.1 SAST 真实扫描
from devsecops_deep.sast_deep import get_sast_deep
sast = get_sast_deep()
vuln_code = '''import subprocess
password = "admin12345"
subprocess.call("ls " + user, shell=True)
eval(user_input)
app.run(debug=True)
'''
res = sast.scan_code(vuln_code, "vuln.py")
print(f"  [SAST] 扫描 {res['lines_total']} 行, 命中 {len(res['findings'])} 处: "
      f"C{res['severity_count']['critical']} H{res['severity_count']['high']} M{res['severity_count']['medium']} L{res['severity_count']['low']}")
for f in res["findings"][:4]:
    print(f"         - {f['rule_name']} L{f['line']} [{f['severity']}]")

clean_code = 'import os\nprint("hello")\nx = 1 + 2\n'
res2 = sast.scan_code(clean_code, "clean.py")
print(f"  [SAST] 干净代码命中 {len(res2['findings'])} 处 (应为0): {'PASS' if len(res2['findings'])==0 else 'FAIL'}")

# 5.2 依赖真实解析
from devsecops_deep.dependency_deep import get_dependency_deep
dep = get_dependency_deep()
reqs = "django==3.2.10\nflask==2.0.1\npillow==9.5.0\npyyaml==5.3.1\n# comment\nurllib3==1.26.5\n"
dres = dep.scan_requirements(reqs)
print(f"  [DEP] 解析 {dres['dependency_count']} 个依赖, 匹配 {dres['vuln_count']} 个漏洞:")
for v in dres["vulnerabilities"]:
    print(f"         - {v['package']}@{v['installed']} -> {v['cve']} ({v['severity']} CVSS{v['cvss']}) 升级到 {v['fixed_version']}")

# 5.3 容器真实层分析
from devsecops_deep.container_deep import get_container_deep
cont = get_container_deep()
cres = cont.analyze_layers("img-node-18")
print(f"  [CONT] 镜像 {cres['image']}: {cres['layer_count']}层, {cres['total_size_mb']}MB, root层{cres['root_layer_count']}")
runchk = cont.runtime_check({"name": "web", "privileged": True, "docker_sock_mounted": True, "run_as_root": True})
print(f"  [CONT] 运行时检查: 逃逸风险={runchk['escape_risk']} (应为True), 风险数={len(runchk['risks'])}")

# 5.4 IaC 真实扫描
from devsecops_deep.iac_security import get_iac_security
iac = get_iac_security()
hcl = '''resource "aws_s3_bucket" "data" {
  bucket = "pub"
  acl    = "public-read"
}
resource "aws_security_group" "web" {
  ingress { from_port = 22; cidr_blocks = ["0.0.0.0/0"] }
}
'''
ires = iac.scan_iac(hcl, "main.tf")
print(f"  [IaC] 扫描 {ires['lines_total']} 行, 命中 {len(ires['findings'])} 项配置错误:")
for f in ires["findings"]:
    print(f"         - {f['title']} L{f['line']} [{f['severity']}]")

# 5.5 门禁真实判定
from devsecops_deep.cicd_security import get_cicd_security
ci = get_cicd_security()
gate_fail = ci.evaluate_gate({"critical": 1, "high": 10, "medium": 30, "low": 60, "secret_exposed": 1, "coverage_pct": 50})
gate_pass = ci.evaluate_gate({"critical": 0, "high": 2, "medium": 5, "low": 10, "secret_exposed": 0, "coverage_pct": 85})
print(f"  [GATE] 恶意输入判定 passed={gate_fail['passed']} (应为False), blockers={len(gate_fail['blockers'])}")
print(f"  [GATE] 干净输入判定 passed={gate_pass['passed']} (应为True)")

# 5.6 管道真实执行
run = ci.run_pipeline("pipeline-web-frontend", injected_findings={"critical": 0, "high": 1, "medium": 5, "low": 10})
print(f"  [CICD] 管道运行 status={run['status']}, jobs={len(run['jobs'])}, gate.passed={run['gate']['passed']}")

# 5.7 SaC 策略校验 + 测试执行
from devsecops_deep.security_as_code import get_security_as_code
sac = get_security_as_code()
val = sac.validate_policy("severity: high\nrules:\n- 禁止硬编码密钥")
print(f"  [SAC] 策略校验 valid={val['valid']}")
tst = sac.evaluate_test("assert tls_version == 1.2", {"tls_version": "1.2"})
print(f"  [SAC] 测试执行 passed={tst['passed']}")

# 5.8 仪表盘聚合
from devsecops_deep.devsecops_dashboard import get_devsecops_dashboard
dash = get_devsecops_dashboard()
ov = dash.overview()
print(f"  [DASH] 健康分={ov['platform_health_score']}, 模块数={len(ov['active_modules'])}")

print()
print("=" * 60)
print(f"验证总结: 语法={'PASS' if syntax_ok else 'FAIL'}, import={'PASS' if import_ok else 'FAIL'}, "
      f"端点={len(paths) if 'paths' in dir() else 0}, HTML={sz/1024:.1f}KB")
print("=" * 60)
