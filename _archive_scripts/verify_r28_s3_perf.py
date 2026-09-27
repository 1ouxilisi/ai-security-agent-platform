#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一次性验证脚本：编译 + import + 冒烟。"""
import sys, os, py_compile, traceback

ROOT = r"E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent"
sys.path.insert(0, ROOT)
os.chdir(ROOT)

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

print("=== 1. py_compile ===")
files = [
    "performance_deep/__init__.py",
    "performance_deep/benchmark.py",
    "performance_deep/high_concurrency.py",
    "performance_deep/big_data.py",
    "performance_deep/distributed_scan_perf.py",
    "performance_deep/stress_test.py",
    "performance_deep/performance_monitor.py",
    "performance_deep/performance_dashboard.py",
]
for f in files:
    try:
        py_compile.compile(os.path.join(ROOT, f), doraise=True)
        print("OK ", f)
    except Exception as e:
        print("FAIL", f, e)

print("\n=== 2. import ===")
for m in mods:
    try:
        __import__(m)
        print("OK ", m)
    except Exception as e:
        print("FAIL", m, repr(e))
        traceback.print_exc()

print("\n=== 3. smoke ===")
from performance_deep.benchmark import get_benchmark_runner
r = get_benchmark_runner()
res = r.run_benchmark("http://127.0.0.1:9/health", "single_user", requests=20)
print("bench p95=", res["latency"]["p95"], "rps=", res["throughput_rps"])

from performance_deep.high_concurrency import get_concurrency_manager
hc = get_concurrency_manager()
hc.execute_request("k1", cost_ms=1)
hc.execute_request("k1")  # cache hit
print("cache stats=", hc.local_cache.stats())

from performance_deep.big_data import get_big_data_manager
bd = get_big_data_manager()
print("shard route=", bd.shards.route_key("example.com"))
print("batch speedup=", bd.batch.compare_batch_vs_single(5000)["speedup_x"])

from performance_deep.distributed_scan_perf import get_distributed_scan_manager
ds = get_distributed_scan_manager()
print("mw submit=", ds.mw.submit_scan("test.com", "1-100")["task_id"])
print("proxy pick=", ds.proxy_pool.pick()["addr"])

from performance_deep.stress_test import get_stress_runner
st = get_stress_runner()
lr = st.load_test(20, 3)
print("stress rps=", lr["throughput_rps"], "p95=", lr["p95"])

from performance_deep.performance_monitor import get_monitor_manager
pm = get_monitor_manager()
print("monitor snap=", pm.collector.snapshot())

from performance_deep.performance_dashboard import get_performance_dashboard
dash = get_performance_dashboard()
ov = dash.overview()
print("overview health=", ov["health_score"])
print("\nALL SMOKE DONE")
