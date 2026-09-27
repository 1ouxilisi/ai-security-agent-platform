#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R28 S3 完整验证：编译/import/端点数/HTML大小/冒烟。"""
import sys, os, py_compile, traceback, re

ROOT = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent"
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "api_server"))
os.chdir(ROOT)

print("=" * 60)
print("R28-S3 性能优化与压力测试 完整验证")
print("=" * 60)

# 1. py_compile
print("\n[1] py_compile 全部 .py")
py_files = [
    "performance_deep/__init__.py",
    "performance_deep/benchmark.py",
    "performance_deep/high_concurrency.py",
    "performance_deep/big_data.py",
    "performance_deep/distributed_scan_perf.py",
    "performance_deep/stress_test.py",
    "performance_deep/performance_monitor.py",
    "performance_deep/performance_dashboard.py",
    "api_server/performance_deep_routes.py",
]
all_ok = True
for f in py_files:
    try:
        py_compile.compile(os.path.join(ROOT, f), doraise=True)
        print("  OK ", f)
    except Exception as e:
        all_ok = False
        print("  FAIL", f, e)

# 2. import 全部模块
print("\n[2] 独立 import")
mods = [
    "performance_deep",
    "performance_deep.benchmark",
    "performance_deep.high_concurrency",
    "performance_deep.big_data",
    "performance_deep.distributed_scan_perf",
    "performance_deep.stress_test",
    "performance_deep.performance_monitor",
    "performance_deep.performance_dashboard",
]
for m in mods:
    try:
        __import__(m)
        print("  OK ", m)
    except Exception as e:
        all_ok = False
        print("  FAIL", m, repr(e))

# 3. 路由 import + 端点数
print("\n[3] 路由 import + 端点计数")
try:
    import importlib
    mod = importlib.import_module("performance_deep_routes")
    print("  OK  performance_deep_routes imported")
    routes = [r for r in mod.router.routes]
    print(f"  端点数: {len(routes)}")
    for r in routes[:5]:
        print(f"    {list(r.methods)[0]:6s} {r.path}")
    print(f"    ... 共 {len(routes)} 个")
    if len(routes) < 50:
        all_ok = False
        print("  FAIL 端点数<50")
except Exception as e:
    all_ok = False
    print("  FAIL", repr(e))
    traceback.print_exc()

# 4. HTML 大小
print("\n[4] HTML 文件大小")
html_path = os.path.join(ROOT, "api_server", "performance_deep_console.html")
size = os.path.getsize(html_path)
print(f"  路径: {html_path}")
print(f"  大小: {size} bytes ({size/1024:.1f} KB)")
if size < 15 * 1024:
    all_ok = False
    print("  FAIL HTML<15KB")
else:
    print("  OK HTML>15KB")

# 5. 文件清单
print("\n[5] 交付文件清单")
files = py_files + ["api_server/performance_deep_console.html", "verify_r28_s3_perf.py"]
for f in files:
    p = os.path.join(ROOT, f)
    if os.path.exists(p):
        sz = os.path.getsize(p)
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            lines = sum(1 for _ in fh)
        print(f"  {sz:>8d} bytes  {lines:>5d} 行  {f}")

# 6. 功能冒烟
print("\n[6] 功能冒烟")
try:
    from performance_deep.benchmark import get_benchmark_runner
    r = get_benchmark_runner()
    res = r.run_benchmark("http://127.0.0.1:9/health", "single_user", requests=15)
    print(f"  benchmark: p50={res['latency']['p50']}ms p95={res['latency']['p95']}ms rps={res['throughput_rps']}")

    from performance_deep.high_concurrency import get_concurrency_manager
    hc = get_concurrency_manager()
    hc.execute_request("smoke-key", cost_ms=1)
    hc.execute_request("smoke-key")
    print(f"  cache: {hc.local_cache.stats()}")

    from performance_deep.big_data import get_big_data_manager
    bd = get_big_data_manager()
    cmp = bd.batch.compare_batch_vs_single(3000)
    print(f"  batch speedup: {cmp['speedup_x']}x")

    from performance_deep.distributed_scan_perf import get_distributed_scan_manager
    ds = get_distributed_scan_manager()
    t = ds.mw.submit_scan("smoke.com", "1-50")
    print(f"  scan task: {t['task_id']}")
    print(f"  proxy: {ds.proxy_pool.pick()['addr']}")

    from performance_deep.stress_test import get_stress_runner
    st = get_stress_runner()
    lr = st.load_test(10, 2)
    print(f"  stress: rps={lr['throughput_rps']} p95={lr['p95']}")

    from performance_deep.performance_monitor import get_monitor_manager
    pm = get_monitor_manager()
    snap = pm.collector.snapshot()
    print(f"  monitor: cpu={snap['cpu_percent']}% mem={snap['memory_percent']}%")

    from performance_deep.performance_dashboard import get_performance_dashboard
    dash = get_performance_dashboard()
    ov = dash.overview()
    print(f"  dashboard health: {ov['health_score']}")
except Exception as e:
    all_ok = False
    traceback.print_exc()

print("\n" + "=" * 60)
print("最终结果:", "全部通过 ✅" if all_ok else "存在失败项 ❌")
print("=" * 60)
