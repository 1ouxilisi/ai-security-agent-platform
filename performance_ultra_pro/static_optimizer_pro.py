# -*- coding: utf-8 -*-
"""
performance_ultra_pro/static_optimizer_pro.py — 静态资源优化 Pro。

- 全部压缩
- CDN 化
- 长缓存
- 预加载
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List


class StaticOptimizerPro:
    """静态资源优化 Pro（全内存模拟）。"""

    ASSETS = [
        {"path": "/static/js/app.js", "raw_kb": 412, "hashed": True, "preload": True},
        {"path": "/static/css/main.css", "raw_kb": 88, "hashed": True, "preload": True},
        {"path": "/static/fonts/icon.woff2", "raw_kb": 42, "hashed": True, "preload": False},
        {"path": "/static/img/logo.svg", "raw_kb": 12, "hashed": False, "preload": False},
    ]

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._gzip = True
        self._brotli = True
        self._cdn = "https://cdn.assets.hacking.ai"
        self._cache_control = "public, max-age=31536000, immutable"

    def report(self) -> Dict[str, Any]:
        rows = []
        total_raw = total_after = 0.0
        for a in self.ASSETS:
            after = round(a["raw_kb"] * 0.25, 1)
            total_raw += a["raw_kb"]
            total_after += after
            rows.append({**a, "gzip_kb": after,
                         "cache": self._cache_control if a["hashed"] else "no-cache"})
        saved = round(100 * (1 - total_after / total_raw), 1) if total_raw else 0
        return {
            "gzip_enabled": self._gzip, "brotli_enabled": self._brotli,
            "cdn": self._cdn, "cache_control": self._cache_control,
            "preload_hints": [a["path"] for a in self.ASSETS if a["preload"]],
            "assets": rows,
            "before_compress_kb": round(total_raw, 1),
            "after_compress_kb": round(total_after, 1),
            "saved_pct": saved,
        }

    def preload(self) -> List[str]:
        return [a["path"] for a in self.ASSETS if a["preload"]]

    def policy(self) -> Dict[str, Any]:
        with self._lock:
            return {"gzip": self._gzip, "brotli": self._brotli, "cdn": self._cdn,
                    "cache_control": self._cache_control,
                    "hash_naming": "[name].[contenthash].ext"}


_opt: StaticOptimizerPro | None = None


def get_static_optimizer_pro() -> StaticOptimizerPro:
    global _opt
    if _opt is None:
        _opt = StaticOptimizerPro()
    return _opt
