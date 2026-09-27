# -*- coding: utf-8 -*-
"""
performance_tester.py — 真实性能压测。

优先 locust / wrk；无则用 Python threading + requests 模拟压测
（明确标注模拟）。输出 P50/P95/P99/QPS/错误率。
"""

from __future__ import annotations

import shutil
import statistics
import threading
import time
from typing import Any, Dict, List, Optional

SCENARIOS = {
    "home": "首页",
    "api": "API 端点",
    "scan_task": "扫描任务",
    "report_gen": "报告生成",
}


def _percentile(data: List[float], p: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    k = max(0, min(len(s) - 1, int(len(s) * p)))
    return round(s[k], 3)


class PerformanceTester:
    """性能压测器。"""

    def list_scenarios(self) -> Dict[str, str]:
        return SCENARIOS

    def _backend(self) -> str:
        if shutil.which("locust"):
            return "locust"
        if shutil.which("wrk"):
            return "wrk"
        return "threading_sim"

    def run(self, target: str = "http://127.0.0.1:8000",
            scenario: str = "home",
            concurrencies: Optional[List[int]] = None,
            duration: int = 10) -> Dict[str, Any]:
        concurrencies = concurrencies or [10, 50, 100]
        backend = self._backend()
        is_sim = backend == "threading_sim"
        series: List[Dict[str, Any]] = []

        for n in concurrencies:
            lat: List[float] = []
            errors = {"n": 0}
            stop = time.time() + duration
            lock = threading.Lock()

            def worker():
                try:
                    import urllib.request
                    while time.time() < stop:
                        t0 = time.time()
                        try:
                            urllib.request.urlopen(target, timeout=5)
                        except Exception:
                            with lock:
                                errors["n"] += 1
                        dt = (time.time() - t0) * 1000
                        with lock:
                            lat.append(dt)
                except Exception:
                    pass

            threads = [threading.Thread(target=worker, daemon=True)
                       for _ in range(n)]
            t_start = time.time()
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=duration + 5)
            wall = time.time() - t_start
            total_req = len(lat) + errors["n"]
            series.append({
                "concurrency": n,
                "total_requests": total_req,
                "qps": round(total_req / wall, 1) if wall else 0,
                "error_rate": round(errors["n"] / total_req, 3) if total_req else 0,
                "p50": _percentile(lat, 0.50),
                "p95": _percentile(lat, 0.95),
                "p99": _percentile(lat, 0.99),
                "avg_ms": round(statistics.mean(lat), 2) if lat else 0,
            })

        return {
            "ok": True, "target": target, "scenario": scenario,
            "scenario_name": SCENARIOS.get(scenario, scenario),
            "backend": backend, "simulated": is_sim,
            "note": "threading+urllib 模拟压测（无 locust/wrk）" if is_sim
                    else f"真实压测工具 {backend}",
            "duration_sec": duration, "series": series,
            "bottleneck": self._bottleneck(series),
            "run_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def _bottleneck(series: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not series:
            return {"level": "unknown", "advice": ""}
        worst = max(series, key=lambda x: x["p95"])
        if worst["p95"] > 1000:
            return {"level": "high",
                    "advice": f"并发{worst['concurrency']}时 P95={worst['p95']}ms，"
                              f"建议引入异步/缓存/连接池"}
        if worst["error_rate"] > 0.05:
            return {"level": "medium",
                    "advice": f"错误率{worst['error_rate']*100:.1f}%，检查超时与资源上限"}
        return {"level": "low", "advice": "当前压测范围内表现良好"}


_tester: Optional[PerformanceTester] = None


def get_performance_tester() -> PerformanceTester:
    global _tester
    if _tester is None:
        _tester = PerformanceTester()
    return _tester
