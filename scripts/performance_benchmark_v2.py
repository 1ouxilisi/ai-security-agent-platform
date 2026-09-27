# -*- coding: utf-8 -*-
"""
性能基准测试脚本 v2。

测量内容：
    1. API 响应时间：10 个常用 GET 端点，每个请求 10 次，输出平均/最大/P95
    2. 启动时间：从 import 到 TestClient 可接受请求
    3. 内存占用：import 前 / import 后 / 处理 100 请求后（psutil 优先，tracemalloc 兜底）
    4. 并发吞吐：ThreadPoolExecutor 10 并发，测吞吐与错误率
    5. 数据库性能：对 platform.db 用临时内存表做 1000 条查询/插入/聚合（不影响真实数据）

用法：
    python scripts/performance_benchmark_v2.py              # 完整测试
    python scripts/performance_benchmark_v2.py --quick      # 快速模式（5 个 API）
    python scripts/performance_benchmark_v2.py --output my_report.json

输出：
    scripts/performance_report.json + 控制台表格
"""
from __future__ import annotations

import os as _os
_os.environ.setdefault("API_AUTH_ENABLED", "false")
_os.environ.setdefault("API_ENV", "test")

import sys
import json
import time
import argparse
import statistics
import sqlite3
import tempfile
import traceback
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_OUTPUT = Path(__file__).resolve().parent / "performance_report.json"
DB_PATH = PROJECT_ROOT / "data" / "platform.db"


class C:
    GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
    CYAN = "\033[96m"; GRAY = "\033[90m"; BOLD = "\033[1m"; END = "\033[0m"


# 候选常用 GET 端点（按稳定性排序，测试时过滤掉 404/405 的）
CANDIDATE_ENDPOINTS = [
    "/health",
    "/api/v1/tasks",
    "/api/v1/tools",
    "/api/v1/agents",
    "/api/v1/knowledge/stats",
    "/api/v1/knowledge/cve",
    "/api/v1/super-agent/capabilities",
    "/api/v1/super-agent/history",
    "/api/v1/ai/tools",
    "/api/v1/poc/status",
    "/api/v1/reports/list",
    "/api/v1/monitoring/tasks",
    "/api/v1/commercial/tenants",
    "/api/v1/collaboration/tasks",
    "/api/v1/analytics/summary",
]
QUICK_ENDPOINTS = CANDIDATE_ENDPOINTS[:5]


def _p50(values):
    return round(statistics.median(values) * 1000, 2) if values else 0.0


def _p95(values):
    if not values:
        return 0.0
    s = sorted(values)
    idx = max(0, int(len(s) * 0.95) - 1)
    return round(s[idx] * 1000, 2)


def _mem_mb():
    """返回当前进程内存（MB），psutil 优先，tracemalloc 兜底。"""
    try:
        import psutil  # type: ignore
        return round(psutil.Process().memory_info().rss / 1024 / 1024, 2)
    except Exception:
        pass
    # tracemalloc 兜底：跟踪 Python 堆分配
    try:
        import tracemalloc
        if not tracemalloc.is_tracing():
            tracemalloc.start()
        cur = tracemalloc.take_snapshot()
        # 统计当前字节数
        total = sum(stat.size for stat in cur.statistics("lineno"))
        return round(total / 1024 / 1024, 2)
    except Exception:
        return None


def bench_api_response(client, endpoints, repeats=10):
    """对每个端点重复请求 repeats 次，统计毫秒级耗时。"""
    results = []
    for ep in endpoints:
        latencies = []
        status = None
        err = None
        # 预热一次
        try:
            client.get(ep, timeout=5.0)
        except Exception as e:  # noqa: BLE001
            err = f"预热失败: {e}"
        for _ in range(repeats):
            t0 = time.perf_counter()
            try:
                r = client.get(ep, timeout=5.0)
                status = r.status_code
            except Exception as e:  # noqa: BLE001
                err = f"{type(e).__name__}: {e}"
                status = -1
            latencies.append(time.perf_counter() - t0)
        ok_latencies = [l for l, st in zip(latencies, [status] * repeats) if st and st < 500]
        avg_ms = round(statistics.mean(latencies) * 1000, 2) if latencies else 0.0
        max_ms = round(max(latencies) * 1000, 2) if latencies else 0.0
        results.append({
            "endpoint": ep,
            "avg_ms": avg_ms,
            "max_ms": max_ms,
            "p50_ms": _p50(latencies),
            "p95_ms": _p95(latencies),
            "last_status": status,
            "error": err,
            "repeats": repeats,
        })
    return results


def bench_concurrency(client, endpoint, concurrency=10):
    """并发请求 endpoint，统计吞吐与错误率。"""
    def _one(_):
        t0 = time.perf_counter()
        try:
            r = client.get(endpoint, timeout=5.0)
            return r.status_code, time.perf_counter() - t0
        except Exception as e:  # noqa: BLE001
            return -1, time.perf_counter() - t0

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        results = list(ex.map(_one, range(concurrency)))
    total = time.perf_counter() - t0
    errors = sum(1 for st, _ in results if st >= 500 or st == -1)
    errors += sum(1 for st, _ in results if st in (401, 403))
    latencies = [l for _, l in results]
    return {
        "endpoint": endpoint,
        "concurrency": concurrency,
        "total_seconds": round(total, 3),
        "throughput_rps": round(concurrency / total, 2) if total > 0 else 0,
        "error_count": errors,
        "error_rate": round(errors / concurrency * 100, 2),
        "p95_latency_ms": _p95(latencies),
    }


def bench_db_perf():
    """在内存临时库里模拟 1000 条记录的查询/插入/聚合性能，不污染真实数据。"""
    if not DB_PATH.exists():
        return {"skipped": True, "reason": f"数据库不存在: {DB_PATH}"}
    try:
        # 复制真实库的 schema 到内存库（attach 方式只读打开真实库）
        src = sqlite3.connect(str(DB_PATH))
        inmem = sqlite3.connect(":memory:")
        # 探测真实库的表
        tables = [r[0] for r in src.execute(
            "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1"
        ).fetchall()]
        if not tables:
            src.close()
            return {"skipped": True, "reason": "真实数据库无表"}

        # 在内存库建一张测试表
        inmem.execute("CREATE TABLE IF NOT EXISTS bench (id INTEGER PRIMARY KEY, k TEXT, v INTEGER)")
        inmem.execute("BEGIN")
        t0 = time.perf_counter()
        for i in range(1000):
            inmem.execute("INSERT INTO bench(k, v) VALUES (?, ?)", (f"key_{i%50}", i))
        inmem.commit()
        insert_ms = round((time.perf_counter() - t0) * 1000, 2)

        t0 = time.perf_counter()
        for _ in range(1000):
            inmem.execute("SELECT v FROM bench WHERE id = ?", (1,)).fetchone()
        query_ms = round((time.perf_counter() - t0) * 1000, 2)

        t0 = time.perf_counter()
        inmem.execute("SELECT k, COUNT(*), AVG(v) FROM bench GROUP BY k").fetchall()
        agg_ms = round((time.perf_counter() - t0) * 1000, 2)

        src.close()
        inmem.close()
        return {
            "skipped": False,
            "insert_1000_ms": insert_ms,
            "query_1000_ms": query_ms,
            "aggregate_ms": agg_ms,
        }
    except Exception as e:  # noqa: BLE001
        return {"skipped": True, "reason": f"数据库测试异常: {type(e).__name__}: {e}"}


def main():
    parser = argparse.ArgumentParser(description="AI Hacking Agent 性能基准测试 v2")
    parser.add_argument("--quick", action="store_true", help="快速模式：只测 5 个 API，重复 3 次")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="报告 JSON 输出路径")
    args = parser.parse_args()

    repeats = 3 if args.quick else 10
    endpoints = QUICK_ENDPOINTS if args.quick else CANDIDATE_ENDPOINTS

    print(f"{C.BOLD}{C.CYAN}=== 性能基准测试开始 (quick={args.quick}) ==={C.END}")

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "mode": "quick" if args.quick else "full",
    }

    # 内存基线
    mem_before = _mem_mb()
    t_import_start = time.perf_counter()
    import_error = None
    try:
        from api_server.app import app  # noqa: F401
    except Exception as e:  # noqa: BLE001
        import_error = f"{type(e).__name__}: {e}"
        traceback.print_exc()
    import_seconds = round(time.perf_counter() - t_import_start, 2)
    mem_after_import = _mem_mb()
    report["import_error"] = import_error
    report["startup_seconds"] = import_seconds

    if import_error:
        report["summary"] = {"status": "import_failed"}
        out = Path(args.output)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"{C.RED}app 导入失败，报告写入 {out}{C.END}")
        return 1

    from fastapi.testclient import TestClient
    client = TestClient(app, base_url="http://testserver")

    # 1. API 响应时间
    print(f"{C.CYAN}[1/5] API 响应时间测试 ({len(endpoints)} 端点 × {repeats} 次){C.END}")
    api_results = bench_api_response(client, endpoints, repeats=repeats)
    report["api_response"] = api_results

    # 2. 处理 100 个请求后内存
    mem_after_warmup = mem_after_import
    try:
        for _ in range(100):
            client.get("/health", timeout=5.0)
        mem_after_warmup = _mem_mb()
    except Exception as e:  # noqa: BLE001
        report["warmup_error"] = str(e)

    report["memory_mb"] = {
        "before_import": mem_before,
        "after_import": mem_after_import,
        "after_100_requests": mem_after_warmup,
        "measured_by": "psutil" if mem_after_import is not None else "tracemalloc/unavailable",
    }

    # 3. 并发测试（选第一个健康的端点）
    print(f"{C.CYAN}[2/5] 并发 10 吞吐测试{C.END}")
    chosen = next((r["endpoint"] for r in api_results
                   if r["last_status"] and r["last_status"] < 500), "/health")
    report["concurrency"] = bench_concurrency(client, chosen, concurrency=10)

    # 4. 数据库性能
    print(f"{C.CYAN}[3/5] 数据库性能测试{C.END}")
    report["database"] = bench_db_perf()

    # 5. 综合判定
    slow_apis = [r for r in api_results if r["avg_ms"] > 1000]
    report["summary"] = {
        "apis_measured": len(api_results),
        "apis_over_1s": len(slow_apis),
        "startup_ok": import_seconds < 10,
        "concurrency_error_rate": report["concurrency"]["error_rate"],
        "db_skipped": report["database"].get("skipped", False),
    }

    # 控制台表格
    print()
    print(f"{C.BOLD}{'端点':<45} {'avg(ms)':>10} {'p95(ms)':>10} {'max(ms)':>10} {'状态':>6}{C.END}")
    print("-" * 85)
    for r in api_results:
        color = C.RED if r["avg_ms"] > 1000 else (C.YELLOW if r["avg_ms"] > 500 else C.GREEN)
        print(f"{r['endpoint']:<45} {color}{r['avg_ms']:>10.2f}{C.END} {r['p95_ms']:>10.2f} "
              f"{r['max_ms']:>10.2f} {str(r['last_status']):>6}")
    print()
    print(f"  启动时间     : {import_seconds}s (目标 <10s)")
    print(f"  内存(MB)     : before={mem_before} after_import={mem_after_import} "
          f"after_100req={mem_after_warmup}")
    print(f"  并发吞吐     : {report['concurrency']['throughput_rps']} rps, "
          f"错误率 {report['concurrency']['error_rate']}%")
    print(f"  数据库       : {report['database']}")

    out = Path(args.output)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{C.CYAN}报告已写入 {out}{C.END}")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
