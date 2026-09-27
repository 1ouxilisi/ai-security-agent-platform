# -*- coding: utf-8 -*-
"""
performance_monitor.py — API/资源性能监控与优化建议引擎。

- 记录每个 API 端点响应时间，计算 P50/P95/P99
- 慢查询（>1s）记录与优化建议
- 缓存命中/未命中统计
- 内存/CPU 监控（优先 psutil，回退 os/resource）
- 自动性能报告与优化建议生成
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)

# 可选依赖
try:
    import psutil  # type: ignore
    _PSUTIL_AVAILABLE = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    _PSUTIL_AVAILABLE = False

SLOW_THRESHOLD_MS = 1000.0
MAX_SAMPLES = 2000


def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * pct
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return round(sorted_vals[f], 2)
    return round(sorted_vals[f] + (k - f) * (sorted_vals[c] - sorted_vals[f]), 2)


class PerformanceMonitor:
    """线程安全的内存性能采样器。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._endpoint_samples: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=MAX_SAMPLES)
        )
        self._endpoint_counts: Dict[str, int] = defaultdict(int)
        self._endpoint_errors: Dict[str, int] = defaultdict(int)
        self._slow_calls: Deque[Dict[str, Any]] = deque(maxlen=500)
        self._cache_hits = 0
        self._cache_misses = 0
        self._status_codes: Dict[int, int] = defaultdict(int)
        self._total_requests = 0
        self._total_errors = 0
        self._proc = None
        if _PSUTIL_AVAILABLE:
            try:
                self._proc = psutil.Process(os.getpid())
            except Exception:
                self._proc = None

    # ---- API 调用采样 ----
    def record_request(self, endpoint: str, duration_ms: float,
                       status_code: int = 200) -> None:
        with self._lock:
            self._endpoint_samples[endpoint].append(duration_ms)
            self._endpoint_counts[endpoint] += 1
            self._status_codes[status_code] += 1
            self._total_requests += 1
            if status_code >= 500:
                self._endpoint_errors[endpoint] += 1
                self._total_errors += 1
            if duration_ms > SLOW_THRESHOLD_MS:
                self._slow_calls.appendleft({
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "endpoint": endpoint,
                    "duration_ms": round(duration_ms, 1),
                    "status_code": status_code,
                })

    def record_cache(self, hit: bool) -> None:
        with self._lock:
            if hit:
                self._cache_hits += 1
            else:
                self._cache_misses += 1

    # ---- 查询 ----
    def endpoint_stats(self) -> List[Dict[str, Any]]:
        with self._lock:
            out = []
            for ep, samples in self._endpoint_samples.items():
                vals = sorted(samples)
                cnt = self._endpoint_counts[ep]
                err = self._endpoint_errors[ep]
                out.append({
                    "endpoint": ep,
                    "calls": cnt,
                    "errors": err,
                    "error_rate": round(err / cnt * 100, 2) if cnt else 0.0,
                    "p50_ms": _percentile(vals, 0.50),
                    "p95_ms": _percentile(vals, 0.95),
                    "p99_ms": _percentile(vals, 0.99),
                    "avg_ms": round(sum(vals) / len(vals), 2) if vals else 0.0,
                    "max_ms": round(vals[-1], 2) if vals else 0.0,
                })
            out.sort(key=lambda x: x["p95_ms"], reverse=True)
            return out

    def slow_calls_list(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._slow_calls)[:limit]

    def cache_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._cache_hits + self._cache_misses
            return {
                "hits": self._cache_hits,
                "misses": self._cache_misses,
                "total": total,
                "hit_ratio": round(self._cache_hits / total * 100, 2) if total else 0.0,
            }

    def overview(self) -> Dict[str, Any]:
        eps = self.endpoint_stats()
        all_vals: List[float] = []
        with self._lock:
            for dq in self._endpoint_samples.values():
                all_vals.extend(dq)
        all_vals.sort()
        return {
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "error_rate": round(self._total_errors / self._total_requests * 100, 2)
            if self._total_requests else 0.0,
            "global_p50_ms": _percentile(all_vals, 0.50),
            "global_p95_ms": _percentile(all_vals, 0.95),
            "global_p99_ms": _percentile(all_vals, 0.99),
            "endpoints_tracked": len(eps),
            "slow_threshold_ms": SLOW_THRESHOLD_MS,
            "slow_count": sum(1 for e in eps if e["p95_ms"] > SLOW_THRESHOLD_MS),
            "status_codes": dict(self._status_codes),
        }

    # ---- 资源监控 ----
    def resources(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "psutil_available": _PSUTIL_AVAILABLE,
            "pid": os.getpid(),
            "threads": threading.active_count(),
        }
        if not _PSUTIL_AVAILABLE or self._proc is None:
            info.update({
                "cpu_percent": None,
                "memory_rss_mb": None,
                "memory_peak_mb": None,
                "note": "psutil 未安装，资源数据不可用；pip install psutil",
            })
            return info
        try:
            mem = self._proc.memory_info()
            info["memory_rss_mb"] = round(mem.rss / 1024 / 1024, 1)
            info["memory_peak_mb"] = round(
                getattr(mem, "vms", 0) / 1024 / 1024, 1
            )
            info["cpu_percent"] = self._proc.cpu_percent(interval=0.1)
            info["cpu_count"] = os.cpu_count()
            try:
                vm = psutil.virtual_memory()
                info["system_memory_percent"] = vm.percent
                info["system_memory_available_mb"] = round(vm.available / 1024 / 1024, 1)
            except Exception:
                pass
            try:
                dt = psutil.disk_usage(os.getcwd())
                info["disk_percent"] = dt.percent
                info["disk_free_gb"] = round(dt.free / 1024 / 1024 / 1024, 1)
            except Exception:
                pass
        except Exception as e:  # pragma: no cover
            info["error"] = str(e)
        return info

    # ---- 报告与建议 ----
    def report(self) -> Dict[str, Any]:
        eps = self.endpoint_stats()
        slow = [e for e in eps if e["p95_ms"] > SLOW_THRESHOLD_MS]
        return {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "overview": self.overview(),
            "top_slow_endpoints": slow[:10],
            "cache": self.cache_stats(),
            "resources": self.resources(),
            "recent_slow_calls": list(self._slow_calls)[:20],
        }

    def suggestions(self) -> List[Dict[str, Any]]:
        eps = self.endpoint_stats()
        out: List[Dict[str, Any]] = []
        rank = 1
        for e in eps:
            if e["p95_ms"] > 1000:
                out.append({
                    "rank": rank, "type": "async_or_index",
                    "endpoint": e["endpoint"],
                    "current_p95_ms": e["p95_ms"],
                    "suggestion": (
                        f"端点 {e['endpoint']} P95={e['p95_ms']}ms 超过阈值，"
                        "建议：① 检查是否缺少数据库索引；② 将阻塞逻辑改为异步；"
                        "③ 增加结果缓存；④ 对列表接口加分页。"
                    ),
                })
                rank += 1
        cache = self.cache_stats()
        if cache["total"] >= 50 and cache["hit_ratio"] < 60:
            out.append({
                "rank": rank, "type": "cache",
                "endpoint": "global",
                "current_p95_ms": 0,
                "suggestion": (
                    f"缓存命中率仅 {cache['hit_ratio']}%，建议增加缓存层"
                    "（如 Redis / 内存 LRU），热点数据预热。"
                ),
            })
            rank += 1
        res = self.resources()
        if res.get("system_memory_percent") and res["system_memory_percent"] > 85:
            out.append({
                "rank": rank, "type": "resource",
                "endpoint": "global",
                "current_p95_ms": 0,
                "suggestion": (
                    f"系统内存使用率 {res['system_memory_percent']}%，"
                    "建议排查内存泄漏或扩容。"
                ),
            })
            rank += 1
        if res.get("disk_percent") and res["disk_percent"] > 90:
            out.append({
                "rank": rank, "type": "resource",
                "endpoint": "global",
                "current_p95_ms": 0,
                "suggestion": f"磁盘使用率 {res['disk_percent']}%，建议清理日志/临时文件。",
            })
            rank += 1
        if not out:
            out.append({
                "rank": 1, "type": "ok",
                "endpoint": "global",
                "current_p95_ms": 0,
                "suggestion": "当前未发现明显性能瓶颈，继续保持监控。",
            })
        return out


_monitor: Optional[PerformanceMonitor] = None


def get_monitor() -> PerformanceMonitor:
    global _monitor
    if _monitor is None:
        _monitor = PerformanceMonitor()
    return _monitor
