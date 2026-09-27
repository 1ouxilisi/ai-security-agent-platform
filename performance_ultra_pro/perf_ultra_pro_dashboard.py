# -*- coding: utf-8 -*-
"""
performance_ultra_pro/perf_ultra_pro_dashboard.py — 性能极致仪表盘聚合。

聚合：启动优化 / 响应优化 / 并发控制 / DB 优化 / 静态资源 / 内存优化。
"""

from __future__ import annotations

from typing import Any, Dict

from performance_ultra_pro.startup_optimizer_pro import get_startup_optimizer_pro
from performance_ultra_pro.response_optimizer_pro import get_response_optimizer_pro
from performance_ultra_pro.concurrency_controller_pro import get_concurrency_controller_pro
from performance_ultra_pro.db_optimizer_pro import get_db_optimizer_pro
from performance_ultra_pro.static_optimizer_pro import get_static_optimizer_pro
from performance_ultra_pro.memory_optimizer import get_memory_optimizer


class PerfUltraProDashboard:
    """性能极致优化 · 聚合仪表盘。"""

    def overview(self) -> Dict[str, Any]:
        return {
            "startup": get_startup_optimizer_pro().startup_compare(),
            "latency": get_response_optimizer_pro().percentiles(),
            "concurrency": get_concurrency_controller_pro().health(),
            "db": get_db_optimizer_pro().stats(),
            "static": get_static_optimizer_pro().report(),
            "memory": get_memory_optimizer().summary(),
        }

    def scorecard(self) -> Dict[str, Dict[str, Any]]:
        su = get_startup_optimizer_pro().startup_compare()
        lat = get_response_optimizer_pro().percentiles()
        cc = get_concurrency_controller_pro().health()
        st = get_static_optimizer_pro().report()
        mem = get_memory_optimizer().summary()
        return {
            "startup": {"label": "启动速度", "ok": su["meets_target"],
                         "detail": f"{su['before_ms']}ms → {su['after_ms']}ms（<5000）"},
            "p95": {"label": "API P95", "ok": lat["meets_target"],
                     "detail": f"P95 {lat['p95']}ms（<30ms）"},
            "concurrency": {"label": "200 并发", "ok": cc["peak_concurrent"] <= 200,
                             "detail": f"峰值并发 {cc['peak_concurrent']}，连接池 {cc['pool_size']}"},
            "db": {"label": "DB 优化", "ok": True,
                    "detail": f"{len(get_db_optimizer_pro().TABLES)} 表 / "
                              f"{get_db_optimizer_pro().schema()['total_indexes']} 索引"},
            "static": {"label": "静态资源", "ok": st["saved_pct"] > 50,
                        "detail": f"压缩节省 {st['saved_pct']}%，CDN + 长缓存"},
            "memory": {"label": "内存优化", "ok": mem["long_run_ready"],
                        "detail": f"RSS {mem['rss_mb']}MB，长稳 {mem['long_run_ready']}"},
        }

    def all_in_one(self) -> Dict[str, Any]:
        return {
            "overview": self.overview(),
            "scorecard": self.scorecard(),
            "cache_stats": get_response_optimizer_pro().cache_stats(),
            "concurrency_health": get_concurrency_controller_pro().health(),
            "static_policy": get_static_optimizer_pro().policy(),
            "memory_trend": get_memory_optimizer().trend()[-10:],
        }


_dash: PerfUltraProDashboard | None = None


def get_perf_ultra_pro_dashboard() -> PerfUltraProDashboard:
    global _dash
    if _dash is None:
        _dash = PerfUltraProDashboard()
    return _dash
