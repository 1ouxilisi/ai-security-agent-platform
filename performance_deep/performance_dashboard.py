#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_deep/performance_dashboard.py — 性能优化控制台数据聚合层。

聚合 8 个 Tab 视图：
    1. 性能总览：健康度/吞吐/延迟/资源/告警/趋势/瓶颈
    2. 基准测试：报告/场景/指标/对比
    3. 高并发优化：连接池/缓存/限流/熔断/异步
    4. 大数据优化：分片/分区/批量/压缩/查询
    5. 分布式优化：Master-Worker/代理池/断点
    6. 压力测试：负载/浸泡/故障注入/混沌/容量
    7. 性能监控：实时指标/告警/慢接口/调用链
    8. 系统设置：模块配置/阈值/通知/保留
"""

from __future__ import annotations

from typing import Any, Dict

from .benchmark import get_benchmark_runner, TEST_SCENARIOS, METRIC_DEFS, TOOL_CONFIG
from .high_concurrency import get_concurrency_manager
from .big_data import get_big_data_manager
from .distributed_scan_perf import get_distributed_scan_manager
from .stress_test import get_stress_runner
from .performance_monitor import get_monitor_manager


SYSTEM_SETTINGS: Dict[str, Dict[str, Any]] = {
    "benchmark_config": {"default_url": "http://127.0.0.1:8000/api/v1/health",
                         "warmup": 5, "timeout_sec": 10, "auto_ramp": True},
    "concurrency_config": {"http_pool": 30, "db_pool": 50, "worker_threads": 16,
                            "rate_limit_rps": 500, "circuit_fail_threshold": 5},
    "cache_config": {"local_ttl_sec": 30, "dist_ttl_sec": 120,
                      "local_capacity": 2000, "dist_capacity": 5000,
                      "protection": True},
    "shard_config": {"shard_count": 16, "auto_rebalance": True,
                      "rebalance_threshold_pct": 20},
    "monitor_config": {"collect_interval_sec": 5, "retention_points": 288,
                        "alert_channels": ["im", "email", "webhook"],
                        "escalation_after_min": 30},
    "stress_config": {"max_vusers": 500, "soak_default_hours": 2,
                       "fault_injection_allowed": True, "chaos_window": "工作日白天"},
}


class PerformanceDashboard:
    """聚合 7 大子系统，为前端 8 个 Tab 提供数据。"""

    def __init__(self) -> None:
        self.bench = get_benchmark_runner()
        self.hc = get_concurrency_manager()
        self.bd = get_big_data_manager()
        self.ds = get_distributed_scan_manager()
        self.stress = get_stress_runner()
        self.mon = get_monitor_manager()

    # -- Tab1 性能总览 -- #
    def overview(self) -> Dict[str, Any]:
        snap = self.mon.collector.snapshot()
        return {
            "health_score": 88,
            "health_level": "良好",
            "snapshot": snap,
            "active_alerts": len(self.mon.alerts.fired[-10:]),
            "benchmarks": len(self.bench.reports),
            "connections": self.hc.pool_status(),
            "shards": self.bd.overview(),
            "cluster": self.ds.mw.cluster_status(),
            "trend": self.mon.collector.trend(12),
            "top_bottlenecks": self.mon.analyzer.slow_endpoints()[:3],
        }

    # -- Tab2 基准测试 -- #
    def benchmark_view(self) -> Dict[str, Any]:
        return {"reports": self.bench.list_reports(),
                "scenarios": TEST_SCENARIOS,
                "metrics": METRIC_DEFS,
                "tool_config": TOOL_CONFIG,
                "env": self.bench.env}

    # -- Tab3 高并发 -- #
    def concurrency_view(self) -> Dict[str, Any]:
        return {"pools": self.hc.pool_status(),
                "cache": self.hc.cache_overview(),
                "resilience": self.hc.resilience_status(),
                "queues": self.hc.queue_status(),
                "tuning": self.hc.resource_tuning()}

    # -- Tab4 大数据 -- #
    def bigdata_view(self) -> Dict[str, Any]:
        return {"overview": self.bd.overview(),
                "shards": self.bd.shards.list_shards(),
                "partitions": self.bd.partitions.list_partitions(),
                "indexes": self.bd.optimizer.list_indexes(),
                "compression": self.bd.compression.formats()}

    # -- Tab5 分布式 -- #
    def distributed_view(self) -> Dict[str, Any]:
        return {"cluster": self.ds.mw.cluster_status(),
                "workers": self.ds.mw.list_workers(),
                "tasks": self.ds.mw.list_tasks(),
                "proxies": self.ds.proxy_pool.list_proxies(),
                "checkpoints": self.ds.resume.list_checkpoints(),
                "speed": self.ds.scan_speed_report(),
                "bottlenecks": self.ds.bottleneck()}

    # -- Tab6 压力测试 -- #
    def stress_view(self) -> Dict[str, Any]:
        return {"runs": list(self.stress.runs.values())[-10:],
                "active_faults": self.stress.injector.list_active(),
                "experiments": self.stress.chaos.list(),
                "capacity_curve": self.stress.capacity_curve(),
                "chaos_practices": self.stress.chaos.best_practices(),
                "capacity": self.stress.capacity_planning()}

    # -- Tab7 性能监控 -- #
    def monitor_view(self) -> Dict[str, Any]:
        return {"dashboard": self.mon.dashboard(),
                "slow_endpoints": self.mon.analyzer.slow_endpoints(),
                "slow_queries": self.mon.analyzer.slow_queries(),
                "call_chain": self.mon.analyzer.call_chain(),
                "alerts": self.mon.alerts.list_alerts()[-20:],
                "rules": self.mon.alerts.list_rules()}

    # -- Tab8 系统设置 -- #
    def settings_view(self) -> Dict[str, Any]:
        return {"settings": SYSTEM_SETTINGS,
                "modules": {
                    "benchmark": "loaded", "high_concurrency": "loaded",
                    "big_data": "loaded", "distributed_scan_perf": "loaded",
                    "stress_test": "loaded", "performance_monitor": "loaded",
                    "dashboard": "loaded"},
                "psutil_available": bool(self.mon.collector.history)
                or __import__("performance_deep.performance_monitor",
                              fromlist=["_PSUTIL_OK"])._PSUTIL_OK}


_DASH: Any = None


def get_performance_dashboard() -> PerformanceDashboard:
    global _DASH
    if _DASH is None:
        _DASH = PerformanceDashboard()
    return _DASH
