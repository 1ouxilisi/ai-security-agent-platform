#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_ultra/lazy_loader.py — 延迟加载器 / 路由懒加载。

把非核心模块从启动路径剥离，首次真正用到时才 import，
目标：冷启动从 ~30s 降到 10s 以内。
"""

from __future__ import annotations

import importlib
import threading
import time
from typing import Any, Callable, Dict, List, Optional


class LazyModule:
    """惰性模块代理：访问属性时才真正 import。"""

    def __init__(self, name: str, importer: Optional[Callable[[], Any]] = None,
                 group: str = "misc") -> None:
        self._name = name
        self._importer = importer
        self._group = group
        self._module: Any = None
        self._load_ms: Optional[float] = None
        self._loaded_at: Optional[str] = None

    def _load(self) -> Any:
        if self._module is None:
            t0 = time.perf_counter()
            if self._importer is not None:
                self._module = self._importer()
            else:
                self._module = importlib.import_module(self._name)
            self._load_ms = round((time.perf_counter() - t0) * 1000, 2)
            self._loaded_at = time.strftime("%H:%M:%S")
        return self._module

    def __getattr__(self, item: str) -> Any:
        return getattr(self._load(), item)

    def is_loaded(self) -> bool:
        return self._module is not None

    def info(self) -> Dict[str, Any]:
        return {
            "name": self._name,
            "group": self._group,
            "loaded": self.is_loaded(),
            "load_ms": self._load_ms,
            "loaded_at": self._loaded_at,
        }


class LazyLoader:
    """集中管理懒加载模块注册表。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._registry: Dict[str, LazyModule] = {}
        self._core_modules: List[str] = []
        self._register_default()

    def _register_default(self) -> None:
        # 非核心 / 重模块：默认延迟
        heavy = [
            ("ml_engine", "AI 推理引擎", "ai"),
            ("binary_reverse", "二进制逆向分析", "analysis"),
            ("mobile_deep", "移动端深度分析", "analysis"),
            ("web3_security", "Web3 安全审计", "analysis"),
            ("darkweb_monitor", "暗网监控", "intel"),
            ("blockchain_security", "区块链安全", "analysis"),
            ("forensics", "数字取证", "analysis"),
        ]
        for name, desc, group in heavy:
            self.register(name, importer=lambda n=name: importlib.import_module(n),
                          group=group)

    def register(self, name: str, importer: Optional[Callable[[], Any]] = None,
                 group: str = "misc") -> LazyModule:
        with self._lock:
            lm = LazyModule(name, importer, group)
            self._registry[name] = lm
            return lm

    def get(self, name: str) -> Optional[LazyModule]:
        return self._registry.get(name)

    def warmup(self, names: Optional[List[str]] = None) -> Dict[str, Any]:
        """预热：显式加载指定（或全部已注册）模块。"""
        targets = names or list(self._registry.keys())
        results = {}
        for n in targets:
            lm = self._registry.get(n)
            if lm is None:
                results[n] = "not_registered"
                continue
            try:
                lm._load()
                results[n] = {"ok": True, "ms": lm._load_ms}
            except Exception as e:  # pragma: no cover
                results[n] = {"ok": False, "error": str(e)}
        return results

    def status(self) -> Dict[str, Any]:
        loaded = [m.info() for m in self._registry.values() if m.is_loaded()]
        pending = [m.info() for m in self._registry.values() if not m.is_loaded()]
        return {
            "registered": len(self._registry),
            "loaded": len(loaded),
            "pending": len(pending),
            "loaded_modules": loaded,
            "pending_modules": pending,
            "estimated_saved_startup_ms": len(pending) * 180,
        }

    def simulate_startup(self) -> Dict[str, Any]:
        """模拟启动耗时对比：全量 vs 懒加载。"""
        total = len(self._registry)
        return {
            "full_load_estimate_ms": total * 220,
            "lazy_load_estimate_ms": 600,
            "savings_ms": total * 220 - 600,
            "target": "冷启动 < 10s",
            "heavy_modules": total,
        }


_loader: LazyLoader | None = None


def get_lazy_loader() -> LazyLoader:
    global _loader
    if _loader is None:
        _loader = LazyLoader()
    return _loader
