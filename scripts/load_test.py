# -*- coding: utf-8 -*-
"""
scripts/load_test.py — 压力测试脚本（独立可运行）

用法：
    python scripts/load_test.py [--url http://127.0.0.1:8000] [--duration 10]

模拟 10 / 50 / 100 / 200 并发请求，测试：
    GET  /health
    GET  /api/v1/knowledge/cve
    GET  /api/v1/system/stats
    POST /api/v1/tasks        （只创建任务，不实际执行）

输出：控制台表格 + data/load_test_report.json
仅依赖 requests 与标准库，不 import 项目内部模块。
"""
import argparse
import json
import os
import random
import statistics
import sys
import threading
import time
from collections import deque

try:
    import requests
except ImportError:
    print("[错误] 缺少 requests 库，请先执行: pip install requests")
    sys.exit(1)


ENDPOINTS = [
    {"name": "health", "method": "GET", "path": "/health"},
    {"name": "cve_query", "method": "GET", "path": "/api/v1/knowledge/cve"},
    {"name": "system_stats", "method": "GET", "path": "/api/v1/system/stats"},
    {"name": "create_task", "method": "POST", "path": "/api/v1/tasks",
     "json": {"task_type": "ping", "target": "127.0.0.1"}},
]

CONCURRENCY_LEVELS = [10, 50, 100, 200]


class HitRecorder:
    """线程安全的结果记录器。"""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.latencies: deque = deque()
        self.success = 0
        self.failure = 0
        self.started = 0
        self.finished = 0

    def record(self, latency_ms: float, ok: bool) -> None:
        with self.lock:
            self.finished += 1
            if ok:
                self.success += 1
            else:
                self.failure += 1
            self.latencies.append(latency_ms)


def worker(base_url: str, duration: float, recorder: HitRecorder,
           stop_flag: threading.Event) -> None:
    """单个并发工作线程：在 duration 秒内循环发请求。"""
    endpoint = random.choice(ENDPOINTS)
    deadline = time.time() + duration
    while time.time() < deadline and not stop_flag.is_set():
        recorder.started += 1
        url = base_url.rstrip("/") + endpoint["path"]
        t0 = time.time()
        ok = False
        try:
            if endpoint["method"] == "GET":
                resp = requests.get(url, timeout=5)
            else:
                resp = requests.post(url, json=endpoint.get("json"), timeout=5)
            ok = resp.status_code < 500
        except Exception:
            ok = False
        latency = (time.time() - t0) * 1000.0
        recorder.record(latency, ok)
        # 0-0.1s 随机延迟模拟真实场景
        time.sleep(random.uniform(0, 0.1))


def run_level(base_url: str, concurrency: int, duration: float) -> dict:
    """跑一个并发级别。"""
    recorder = HitRecorder()
    stop_flag = threading.Event()
    threads = [threading.Thread(target=worker,
                                args=(base_url, duration, recorder, stop_flag),
                                daemon=True)
               for _ in range(concurrency)]
    t0 = time.time()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    elapsed = time.time() - t0

    lat = sorted(recorder.latencies)
    total = recorder.success + recorder.failure
    avg = statistics.mean(lat) if lat else 0.0
    p95 = lat[int(len(lat) * 0.95) - 1] if lat else 0.0
    return {
        "concurrency": concurrency,
        "duration_sec": round(elapsed, 2),
        "total_requests": total,
        "success": recorder.success,
        "failure": recorder.failure,
        "rps": round(total / elapsed, 1) if elapsed > 0 else 0.0,
        "avg_latency_ms": round(avg, 2),
        "p95_latency_ms": round(p95, 2),
        "error_rate": round(recorder.failure / total * 100, 2) if total else 0.0,
    }


def check_server(base_url: str) -> bool:
    """探测服务器是否可用。"""
    try:
        resp = requests.get(base_url.rstrip("/") + "/health", timeout=3)
        return resp.status_code < 500
    except Exception:
        return False


def print_table(rows: list) -> None:
    """控制台表格输出。"""
    header = f"{'并发':>6} {'耗时s':>7} {'总数':>7} {'成功':>7} {'失败':>7} {'RPS':>8} {'平均ms':>9} {'P95ms':>9} {'错误率%':>8}"
    print("\n" + header)
    print("-" * len(header))
    for r in rows:
        print(f"{r['concurrency']:>6} {r['duration_sec']:>7} {r['total_requests']:>7} "
              f"{r['success']:>7} {r['failure']:>7} {r['rps']:>8} "
              f"{r['avg_latency_ms']:>9} {r['p95_latency_ms']:>9} {r['error_rate']:>8}")


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Hacking Agent 压力测试")
    parser.add_argument("--url", default="http://127.0.0.1:8000",
                        help="目标地址，默认 http://127.0.0.1:8000")
    parser.add_argument("--duration", type=float, default=10.0,
                        help="每个并发级别运行秒数，默认 10")
    parser.add_argument("--levels", type=str, default="10,50,100,200",
                        help="并发级别，逗号分隔")
    args = parser.parse_args()

    base_url = args.url
    print(f"[压力测试] 目标: {base_url}")
    if not check_server(base_url):
        print(f"[提示] 服务器 {base_url} 未响应（GET /health 失败）。")
        print("       请先启动服务（如: python main.py 或 uvicorn ...）后再运行本脚本。")
        sys.exit(0)

    levels = [int(x) for x in args.levels.split(",") if x.strip()]
    results = []
    for lvl in levels:
        print(f"[运行] 并发 {lvl} ...")
        results.append(run_level(base_url, lvl, args.duration))

    print_table(results)

    report = {
        "base_url": base_url,
        "duration_per_level_sec": args.duration,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "results": results,
    }
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "data")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "load_test_report.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n[完成] 报告已保存: {out_path}")


if __name__ == "__main__":
    main()
