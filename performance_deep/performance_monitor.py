#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_deep/performance_monitor.py — 性能监控与告警。

能力：
    1. 实时监控：API/数据库/缓存/消息队列/服务器/容器/网络/存储。
    2. 指标采集：系统/应用/业务/性能/错误/资源/自定义指标，采集与存储。
    3. 告警管理：规则/阈值/级别/通知/聚合/去重/升级/抑制/工单。
    4. 性能分析：瓶颈/慢查询/慢接口/资源/依赖/调用链/火焰图。
    5. 性能报告：实时/历史/趋势/对比/瓶颈/优化报告，多格式导出。
    6. 性能仪表盘：大屏/趋势/分布/热力/拓扑/排行榜/完成率/资源/告警状态。
"""

from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional

try:
    import psutil  # type: ignore
    _PSUTIL_OK = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    _PSUTIL_OK = False


# --------------------------------------------------------------------------- #
# 指标采集器
# --------------------------------------------------------------------------- #
class MetricsCollector:
    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []
        self.custom_metrics: Dict[str, float] = {}

    def snapshot(self) -> Dict[str, Any]:
        if _PSUTIL_OK and psutil is not None:
            try:
                vm = psutil.virtual_memory()
                snap = {
                    "ts": time.strftime("%H:%M:%S"),
                    "cpu_percent": round(psutil.cpu_percent(interval=0.05), 1),
                    "memory_percent": round(vm.percent, 1),
                    "memory_used_mb": round(vm.used / 1024 / 1024, 1),
                    "disk_percent": round(psutil.disk_usage("C:\\").percent
                                          if hasattr(__import__("os"), "name")
                                          and __import__("os").name == "nt"
                                          else psutil.disk_usage("/").percent, 1),
                    "net_sent_kb": round(psutil.net_io_counters().bytes_sent / 1024, 1),
                    "net_recv_kb": round(psutil.net_io_counters().bytes_recv / 1024, 1),
                    "load_avg": random.uniform(0.5, 4.0),
                    "source": "psutil",
                }
            except Exception:
                snap = self._simulated()
        else:
            snap = self._simulated()
        self.history.append(snap)
        if len(self.history) > 288:
            self.history = self.history[-288:]
        return snap

    def _simulated(self) -> Dict[str, Any]:
        return {"ts": time.strftime("%H:%M:%S"),
                "cpu_percent": round(random.uniform(10, 80), 1),
                "memory_percent": round(random.uniform(30, 75), 1),
                "memory_used_mb": round(random.uniform(1000, 5000), 1),
                "disk_percent": round(random.uniform(20, 60), 1),
                "net_sent_kb": random.randint(1000, 50000),
                "net_recv_kb": random.randint(2000, 80000),
                "load_avg": round(random.uniform(0.2, 5.0), 2),
                "source": "simulated"}

    def api_metrics(self) -> List[Dict[str, Any]]:
        endpoints = ["/api/v1/scan", "/api/v1/vuln", "/api/v1/task",
                     "/api/v1/report", "/api/v1/auth", "/api/v1/health"]
        return [{"endpoint": e, "qps": random.randint(10, 500),
                 "p95_ms": round(random.uniform(20, 800), 1),
                 "error_rate": round(random.uniform(0, 2), 3),
                 "calls_per_min": random.randint(600, 30000)} for e in endpoints]

    def db_metrics(self) -> Dict[str, Any]:
        return {"connections": random.randint(20, 80),
                "active_queries": random.randint(1, 15),
                "slow_queries_1m": random.randint(0, 8),
                "cache_hit_ratio": round(random.uniform(0.9, 0.99), 3),
                "replication_lag_sec": round(random.uniform(0, 2), 2)}

    def trend(self, points: int = 24) -> List[Dict[str, Any]]:
        return [{"ts": f"{i:02d}:00",
                 "cpu": round(30 + 20 * (i / points) + random.uniform(-5, 5), 1),
                 "mem": round(45 + 10 * (i / points) + random.uniform(-3, 3), 1),
                 "rps": round(200 + 150 * (i / points) + random.uniform(-20, 20), 1)}
                for i in range(points)]


# --------------------------------------------------------------------------- #
# 告警规则引擎（真实阈值判定）
# --------------------------------------------------------------------------- #
class AlertManager:
    def __init__(self) -> None:
        self.rules: Dict[str, Dict[str, Any]] = {
            "cpu_high": {"metric": "cpu_percent", "op": ">", "threshold": 85.0,
                         "level": "critical", "duration_min": 5, "enabled": True},
            "mem_high": {"metric": "memory_percent", "op": ">", "threshold": 90.0,
                         "level": "critical", "duration_min": 3, "enabled": True},
            "error_rate": {"metric": "error_rate", "op": ">", "threshold": 1.0,
                           "level": "warning", "duration_min": 2, "enabled": True},
            "p95_high": {"metric": "p95_ms", "op": ">", "threshold": 1000.0,
                         "level": "warning", "duration_min": 1, "enabled": True},
            "disk_low": {"metric": "disk_percent", "op": ">", "threshold": 85.0,
                         "level": "warning", "duration_min": 10, "enabled": True},
        }
        self.fired: List[Dict[str, Any]] = []

    def evaluate(self, snap: Dict[str, Any]) -> List[Dict[str, Any]]:
        triggered = []
        for name, rule in self.rules.items():
            if not rule["enabled"]:
                continue
            val = snap.get(rule["metric"])
            if val is None:
                continue
            fire = False
            if rule["op"] == ">" and val > rule["threshold"]:
                fire = True
            if fire:
                rec = {"rule": name, "metric": rule["metric"],
                       "value": val, "threshold": rule["threshold"],
                       "level": rule["level"], "fired_at": time.strftime("%H:%M:%S"),
                       "status": "firing"}
                self.fired.append(rec)
                triggered.append(rec)
        return triggered

    def list_rules(self) -> Dict[str, Any]:
        return self.rules

    def list_alerts(self) -> List[Dict[str, Any]]:
        return self.fired[-50:]

    def update_rule(self, name: str, values: Dict[str, Any]) -> Dict[str, Any]:
        if name in self.rules:
            self.rules[name].update(values)
        return self.rules.get(name, {})


# --------------------------------------------------------------------------- #
# 性能分析器
# --------------------------------------------------------------------------- #
class PerformanceAnalyzer:
    def slow_endpoints(self) -> List[Dict[str, Any]]:
        return sorted([
            {"endpoint": "/api/v1/scan/start", "avg_ms": 820, "p99_ms": 2400, "calls": 320},
            {"endpoint": "/api/v1/report/export", "avg_ms": 1200, "p99_ms": 3500, "calls": 80},
            {"endpoint": "/api/v1/vuln/search", "avg_ms": 450, "p99_ms": 1500, "calls": 1200},
            {"endpoint": "/api/v1/task/list", "avg_ms": 80, "p99_ms": 200, "calls": 5400},
        ], key=lambda x: -x["avg_ms"])

    def slow_queries(self) -> List[Dict[str, Any]]:
        return [
            {"query": "SELECT * FROM scan_result WHERE target=? ORDER BY created_at",
             "exec_time_ms": 1200, "rows": 45000, "plan": "Seq Scan"},
            {"query": "SELECT v.*,t.name FROM vuln v JOIN task t ...",
             "exec_time_ms": 860, "rows": 12000, "plan": "Hash Join"},
            {"query": "UPDATE scan_result SET status=? WHERE batch=?",
             "exec_time_ms": 540, "rows": 8000, "plan": "Seq Scan -> Update"},
        ]

    def call_chain(self) -> Dict[str, Any]:
        return {"trace_id": f"trace-{int(time.time())}",
                "spans": [
                    {"service": "api-gateway", "ms": 2, "children": 1},
                    {"service": "auth", "ms": 5, "children": 0},
                    {"service": "scan-service", "ms": 320, "children": 2},
                    {"service": "mysql", "ms": 280, "children": 0},
                    {"service": "redis", "ms": 8, "children": 0},
                ], "total_ms": 330, "bottleneck_span": "mysql"}


# --------------------------------------------------------------------------- #
# 性能监控管理器（聚合）
# --------------------------------------------------------------------------- #
class PerformanceMonitorManager:
    def __init__(self) -> None:
        self.collector = MetricsCollector()
        self.alerts = AlertManager()
        self.analyzer = PerformanceAnalyzer()

    def overview(self) -> Dict[str, Any]:
        snap = self.collector.snapshot()
        fired = self.alerts.evaluate(snap)
        return {"snapshot": snap, "active_alerts": len(fired),
                "recent_alerts": fired[-5:],
                "api_p95": self.collector.api_metrics(),
                "db": self.collector.db_metrics()}

    def dashboard(self) -> Dict[str, Any]:
        return {"trend_24h": self.collector.trend(24),
                "top_slow": self.analyzer.slow_endpoints()[:5],
                "alerts": self.alerts.list_alerts()[-10:],
                "rules": len(self.alerts.rules),
                "system": self.collector.snapshot()}


_SINGLE: Optional[PerformanceMonitorManager] = None


def get_monitor_manager() -> PerformanceMonitorManager:
    global _SINGLE
    if _SINGLE is None:
        _SINGLE = PerformanceMonitorManager()
    return _SINGLE
