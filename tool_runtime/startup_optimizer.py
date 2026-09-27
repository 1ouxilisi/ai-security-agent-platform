# -*- coding: utf-8 -*-
"""
startup_optimizer.py — 启动优化与预热。

- 并行初始化各模块（ThreadPoolExecutor）
- 延迟加载非核心模块
- 启动进度/耗时统计
- 失败自动诊断（不影响其他模块）
- 启动后健康检查
- 手动预热接口
"""

from __future__ import annotations

import logging
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class StartupOptimizer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stages: List[Dict[str, Any]] = []
        self._started_at: float = 0.0
        self._finished_at: float = 0.0
        self._health_report: Dict[str, Any] = {}
        self._warmup_done = False
        self._lazy_registry: Dict[str, Callable[[], Any]] = {}
        self._lazy_cache: Dict[str, Any] = {}

    # ---- 阶段记录 ----
    def record_stage(self, name: str, duration_ms: float,
                     status: str = "ok", error: str = "",
                     fix_hint: str = "") -> None:
        with self._lock:
            self._stages.append({
                "name": name,
                "duration_ms": round(duration_ms, 1),
                "status": status,
                "error": error,
                "fix_hint": fix_hint,
                "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            })

    # ---- 并行初始化 ----
    def run_parallel(self,
                     stages: Dict[str, Callable[[], Any]],
                     max_workers: int = 4) -> Dict[str, Any]:
        """并发执行初始化阶段，失败不影响其他阶段。"""
        self._started_at = time.perf_counter()
        results: Dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=max_workers,
                                thread_name_prefix="startup") as pool:
            future_map = {pool.submit(fn): name for name, fn in stages.items()}
            for fut in as_completed(future_map):
                name = future_map[fut]
                t0 = time.perf_counter()
                try:
                    res = fut.result()
                    results[name] = res
                    self.record_stage(name, (time.perf_counter() - t0) * 1000, "ok")
                    logger.info("startup stage OK: %s", name)
                except Exception as e:  # pragma: no cover
                    tb = traceback.format_exc(limit=3)
                    self.record_stage(
                        name, (time.perf_counter() - t0) * 1000,
                        status="failed",
                        error=f"{type(e).__name__}: {e}",
                        fix_hint=(
                            f"查看堆栈前3行定位；常见原因：依赖缺失/端口占用/配置错误。"
                            f"堆栈摘要: {tb.splitlines()[-1] if tb else ''}"
                        ),
                    )
                    results[name] = None
                    logger.exception("startup stage FAILED: %s", name)
        self._finished_at = time.perf_counter()
        return results

    # ---- 延迟加载 ----
    def register_lazy(self, name: str, loader: Callable[[], Any]) -> None:
        self._lazy_registry[name] = loader

    def get_lazy(self, name: str) -> Any:
        if name in self._lazy_cache:
            return self._lazy_cache[name]
        loader = self._lazy_registry.get(name)
        if loader is None:
            return None
        t0 = time.perf_counter()
        try:
            obj = loader()
            self._lazy_cache[name] = obj
            self.record_stage(f"lazy:{name}", (time.perf_counter() - t0) * 1000, "ok")
            return obj
        except Exception as e:  # pragma: no cover
            self.record_stage(f"lazy:{name}", (time.perf_counter() - t0) * 1000,
                              "failed", str(e), "检查该模块依赖")
            return None

    # ---- 预热 ----
    def warmup(self) -> Dict[str, Any]:
        """预热核心数据：触发工具检测 + 性能监控初始化 + 模块导入。"""
        t0 = time.perf_counter()
        report: Dict[str, Any] = {"steps": []}
        try:
            from .tool_detector import get_detector
            get_detector().detect_all()
            report["steps"].append({"name": "tool_detector", "ok": True})
        except Exception as e:
            report["steps"].append({"name": "tool_detector", "ok": False, "error": str(e)})
        try:
            from .performance_monitor import get_monitor
            get_monitor().resources()
            report["steps"].append({"name": "performance_monitor", "ok": True})
        except Exception as e:
            report["steps"].append({"name": "performance_monitor", "ok": False, "error": str(e)})
        try:
            from .smart_fallback import get_all_mappings
            get_all_mappings()
            report["steps"].append({"name": "fallback_map", "ok": True})
        except Exception as e:
            report["steps"].append({"name": "fallback_map", "ok": False, "error": str(e)})
        report["duration_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        self._warmup_done = True
        return report

    # ---- 健康检查 ----
    def post_health_check(self) -> Dict[str, Any]:
        from .performance_monitor import get_monitor as _get_mon
        from .tool_detector import get_detector as _get_detector
        checks: Dict[str, Any] = {}
        # 1. 核心模块 import
        try:
            from . import tool_detector, smart_fallback, install_guide  # noqa: F401
            checks["core_modules"] = "ok"
        except Exception as e:
            checks["core_modules"] = f"fail: {e}"
        # 2. 工具检测
        try:
            summary = _get_detector().summary()
            checks["tool_detection"] = (
                f"ok ({summary['available']}/{summary['total']} available)"
            )
        except Exception as e:
            checks["tool_detection"] = f"fail: {e}"
        # 3. 性能监控
        try:
            _get_mon().overview()
            checks["performance_monitor"] = "ok"
        except Exception as e:
            checks["performance_monitor"] = f"fail: {e}"
        self._health_report = {
            "checks": checks,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return self._health_report

    # ---- 查询 ----
    def report(self) -> Dict[str, Any]:
        with self._lock:
            stages = list(self._stages)
        total_ms = 0.0
        if self._started_at and self._finished_at:
            total_ms = round((self._finished_at - self._started_at) * 1000, 1)
        sorted_by_time = sorted(stages, key=lambda s: s["duration_ms"], reverse=True)
        return {
            "total_duration_ms": total_ms,
            "stages": stages,
            "slowest_3": sorted_by_time[:3],
            "failed_stages": [s for s in stages if s["status"] != "ok"],
            "warmup_done": self._warmup_done,
            "health_report": self._health_report,
            "lazy_modules": list(self._lazy_registry.keys()),
        }

    def progress(self) -> Dict[str, Any]:
        with self._lock:
            done = len(self._stages)
            failed = sum(1 for s in self._stages if s["status"] != "ok")
        return {
            "stages_done": done,
            "failed": failed,
            "warmup_done": self._warmup_done,
        }


_optimizer: Optional[StartupOptimizer] = None


def get_optimizer() -> StartupOptimizer:
    global _optimizer
    if _optimizer is None:
        _optimizer = StartupOptimizer()
    return _optimizer
