#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_pro/static_optimizer.py — 静态资源优化。

- 压缩（gzip / brotli）
- 缓存头（Cache-Control / ETag / immutable）
- CDN 友好（指纹化文件名 / 边缘缓存）
"""

from __future__ import annotations

from typing import Any, Dict, List


class StaticOptimizer:
    """静态资源优化器（元数据 + 建议）。"""

    def __init__(self) -> None:
        # 模拟资源清单：压缩前后体积
        self._assets: List[Dict[str, Any]] = [
            {"name": "app.js", "before_kb": 210, "after_kb": 46, "gzip_ratio": 0.78},
            {"name": "vendor.js", "before_kb": 540, "after_kb": 118, "gzip_ratio": 0.78},
            {"name": "style.css", "before_kb": 96, "after_kb": 22, "gzip_ratio": 0.77},
            {"name": "logo.png", "before_kb": 88, "after_kb": 84, "gzip_ratio": 0.05},
            {"name": "console.html", "before_kb": 62, "after_kb": 14, "gzip_ratio": 0.77},
        ]

    def headers(self) -> Dict[str, str]:
        """推荐响应头。"""
        return {
            "Cache-Control": "public, max-age=31536000, immutable",
            "ETag": 'W/"v{hash}"',
            "Content-Encoding": "br",
            "Vary": "Accept-Encoding",
            "CDN-Cache": "edge=86400",
        }

    def assets(self) -> List[Dict[str, Any]]:
        return self._assets

    def summary(self) -> Dict[str, Any]:
        before = sum(a["before_kb"] for a in self._assets)
        after = sum(a["after_kb"] for a in self._assets)
        return {
            "gzip_enabled": True,
            "brotli_enabled": True,
            "total_before_kb": before,
            "total_after_kb": after,
            "saved_pct": round((before - after) / before * 100, 1),
            "cdn": ["jsDelivr", "Cloudflare", "自建边缘节点"],
            "fingerprinting": "文件名 contenthash 指纹，长缓存 + 内容更新即换名",
            "headers": self.headers(),
        }


_static: StaticOptimizer | None = None


def get_static_optimizer() -> StaticOptimizer:
    global _static
    if _static is None:
        _static = StaticOptimizer()
    return _static
