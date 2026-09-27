# -*- coding: utf-8 -*-
"""第27轮方向2 安全Fuzzing平台 冒烟测试。"""
from __future__ import annotations
import os, sys, py_compile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "api_server"))

FILES = [
    "fuzzing_platform/__init__.py",
    "fuzzing_platform/protocol_fuzzer.py",
    "fuzzing_platform/file_fuzzer.py",
    "fuzzing_platform/api_fuzzer.py",
    "fuzzing_platform/browser_fuzzer.py",
    "fuzzing_platform/kernel_fuzzer.py",
    "fuzzing_platform/fuzzing_manager.py",
    "fuzzing_platform/fuzzing_dashboard.py",
    "api_server/fuzzing_platform_routes.py",
]

print("=" * 60)
print("1. py_compile 全部 .py 文件")
ok = True
for f in FILES:
    p = os.path.join(ROOT, f.replace("/", os.sep))
    try:
        py_compile.compile(p, doraise=True)
        print(f"  [OK] {f}")
    except Exception as e:
        ok = False
        print(f"  [FAIL] {f}: {e}")
print("COMPILE:", "PASS" if ok else "FAIL")

print("=" * 60)
print("2. 7个核心模块独立 import")
from fuzzing_platform.protocol_fuzzer import get_protocol_fuzzer, PROTOCOLS
from fuzzing_platform.file_fuzzer import get_file_fuzzer, FILE_FORMATS
from fuzzing_platform.api_fuzzer import get_api_fuzzer, parse_openapi
from fuzzing_platform.browser_fuzzer import get_browser_fuzzer, BROWSERS
from fuzzing_platform.kernel_fuzzer import get_kernel_fuzzer
from fuzzing_platform.fuzzing_manager import get_fuzzing_manager
from fuzzing_platform.fuzzing_dashboard import get_fuzzing_dashboard
print("  [OK] 全部模块独立导入成功")

print("=" * 60)
print("3. 真实功能演示")
pf = get_protocol_fuzzer()
c = pf.generate_case("dns", "random")
print(f"  协议用例(DNS): {c['protocol']} 长度={c['mutated_len']} hex={c['payload_hex'][:32]}")
c2 = pf.run("http", 30, "random")
print(f"  协议执行: 用例={c2['cases']} 崩溃={c2['crashes']} 速度={c2['speed_cps']}cps")

ff = get_file_fuzzer()
fc = ff.generate_case("png", "bitflip")
print(f"  文件用例(PNG): 大小={fc['size']}B 头={fc['head_hex']}")
fc2 = ff.run("pdf", 30, "bitflip")
print(f"  文件执行: 用例={fc2['cases']} 崩溃={fc2['crashes']} ASAN={fc2['asan_findings']}")

af = get_api_fuzzer()
eps = af.discover("https://api.demo.com")
print(f"  API发现: {len(eps)} 个端点")
openapi_spec = '{"openapi":"3.0","paths":{"/users":{"get":{"operationId":"listUsers","parameters":[{"name":"page","in":"query","schema":{"type":"integer"}}]}}}}'
oe = af.import_openapi(openapi_spec)
print(f"  OpenAPI解析: {len(oe)} 个端点, 参数={oe[0]['params']}")
mp = af.mutate_param("id", "int", "boundary")
print(f"  参数变异: id={mp['value']} 类型={mp['mutation']}")

bf = get_browser_fuzzer()
bc = bf.generate_case("chrome", "js_engine", "js")
print(f"  浏览器用例: 大小={bc['size']}B 优先级={bc['priority']}")
bc2 = bf.run("firefox", "js_engine", 20, "js")
print(f"  浏览器执行: 用例={bc2['cases']} 崩溃={bc2['crashes']}")

kf = get_kernel_fuzzer()
ks = kf.generate_sequence(8)
print(f"  内核序列: 长度={ks['length']} 预览={ks['sequence_preview'][:50]}")
ktt = kf.syscall_table()
print(f"  系统调用表: {len(ktt)} 个调用号, 例: {ktt[0]}")
kc2 = kf.run("syscall", 20, 8)
print(f"  内核执行: 序列={kc2['sequences']} 崩溃={kc2['crashes']}")

mgr = get_fuzzing_manager()
proj = mgr.create_project("演示项目", "demo:80", "protocol")
task = mgr.create_task(proj["project_id"], "演示任务", "protocol", "high")
cov = mgr.coverage_report(proj["project_id"])
print(f"  管理: 项目={len(mgr.projects)} 任务={len(mgr.tasks)} 行覆盖率={cov['line_pct']}%")
rep = mgr.generate_report("fuzzing", proj["project_id"])
print(f"  报告: {rep['report_id']} 类型={rep['type']}")

dash = get_fuzzing_dashboard()
ov = dash.overview()
print(f"  控制台聚合: 模块加载={dash._ok} 协议用例={ov.get('protocol',{}).get('total_cases')}")

print("=" * 60)
print("4. API 端点数统计")
import fuzzing_platform_routes as R
n = len(R.router.routes)
print(f"  路由总数: {n}")
assert n >= 50, "端点数不足50"
print("  [OK] 端点数 >= 50")

print("=" * 60)
print("5. HTML 文件大小检查")
html_path = os.path.join(ROOT, "api_server", "fuzzing_platform_console.html")
sz = os.path.getsize(html_path)
print(f"  HTML 大小: {sz} 字节 ({sz/1024:.1f} KB)")
assert sz > 15360, "HTML 不足15KB"
print("  [OK] HTML > 15KB")

print("=" * 60)
print("全部冒烟测试通过 ✓")
print(f"端点数: {n} | 协议: {len(PROTOCOLS)} | 文件格式: {len(FILE_FORMATS)} | 浏览器: {len(BROWSERS)}")
