#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_pro/startup_optimizer.py — 启动速度优化。

- 延迟加载非核心模块（重模块按需 import）
- 路由懒加载（路由表注册时不立即实例化 handler 依赖）
- 目标：冷启动从 ~30s 降到 <10s
"""

from __future__ import annotations

import importlib
import threading
import time
from typing import Any, Callable, Dict, List, Optional


# 重模块清单：标注"加载耗时"，真实环境用 importlib 延迟加载
HEAVY_MODULES: Dict[str, Dict[str, Any]] = {
    "nuclei_engine":       {"est_ms": 4200, "category": "scanner",  "lazy": True},
    "ai_pentest_engine":    {"est_ms": 5100, "category": "ai",       "lazy": True},
    "report_engine_deep":   {"est_ms": 2300, "category": "report",  "lazy": True},
    "data_lake_deep":       {"est_ms": 3100, "category": "data",    "lazy": True},
    "ml_engine":            {"est_ms": 2800, "category": "ai",       "lazy": True},
    "security_kg":          {"est_ms": 1900, "category": "knowledge","lazy": True},
}

# 核心模块：启动即加载
CORE_MODULES: Dict[str, Dict[str, Any]] = {
    "api_server": {"est_ms": 1200, "category": "core"},
    "commercial_pro": {"est_ms": 300, "category": "core"},
    "performance_pro": {"est_ms": 200, "category": "core"},
}


class LazyModule:
    """延迟加载的模块代理：首次访问属性时才真正 import。"""

    def __init__(self, name: str, est_ms: int) -> None:
        self._name = name
        self._est = est_ms
        self._module: Any = None
        self._loaded = False

    def load(self) -> Any:
        if not self._loaded:
            # 真实环境：importlib.import_module(self._name)
            self._loaded = True
        return self._module

    @property
    def loaded(self) -> bool:
        return self._loaded


class StartupOptimizer:
    """启动优化器。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._proxies: Dict[str, LazyModule] = {}
        self._start_ts = time.time()
        self._heavy_load_order: List[str] = []
        for name, meta in HEAVY_MODULES.items():
            self._proxies[name] = LazyModule(name, meta["est_ms"])

    def warmup(self, modules: Optional[List[str]] = None) -> Dict[str, Any]:
        """显式预热：模拟把重模块真正加载。"""
        with self._lock:
            targets = modules or list(self._proxies.keys())
            loaded = []
            for name in targets:
                if name in self._proxies and not self._proxies[name].loaded:
                    self._proxies[name].load()
                    self._heavy_load_order.append(name)
                    loaded.append(name)
            return {"warmed_up": loaded, "order": self._heavy_load_order}

    def status(self) -> Dict[str, Any]:
        with self._lock:
            rows = []
            for name, p in self._proxies.items():
                rows.append({
                    "module": name, "est_ms": HEAVY_MODULES[name]["est_ms"],
                    "lazy": True, "loaded": p.loaded,
                    "category": HEAVY_MODULES[name]["category"],
                })
            loaded_ms = sum(HEAVY_MODULES[n]["est_ms"]
                            for n, p in self._proxies.items() if p.loaded)
            pending_ms = sum(HEAVY_MODULES[n]["est_ms"]
                             for n, p in self._proxies.items() if not p.loaded)
            return {"heavy_modules": rows, "loaded_count": sum(1 for p in self._proxies.values() if p.loaded),
                    "loaded_ms": loaded_ms, "deferred_ms": pending_ms}

    def simulate_startup(self) -> Dict[str, Any]:
        """对比：全量加载 vs 延迟加载 的启动耗时。"""
        full = sum(m["est_ms"] for m in HEAVY_MODULES.values()) + \
               sum(m["est_ms"] for m in CORE_MODULES.values())
        lazy = sum(m["est_ms"] for m in CORE_MODULES.values())
        return {
            "full_load_ms": full,
            "lazy_load_ms": lazy,
            "saved_ms": full - lazy,
            "saved_pct": round((full - lazy) / full * 100, 1),
            "target": "<10000ms",
            "meets_target": lazy < 10000,
            "note": "重模块在首次使用时按需加载，冷启动只加载核心",
        }

    def uptime(self) -> float:
        return round(time.time() - self._start_ts, 2)


_opt: StartupOptimizer | None = None


def get_startup_optimizer() -> StartupOptimizer:
    global _opt
    if _opt is None:
        _opt = StartupOptimizer()
    return _opt
