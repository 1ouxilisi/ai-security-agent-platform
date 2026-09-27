# -*- coding: utf-8 -*-
"""
api_monitor.py - API 监控器。

性能监控（响应时间百分位/吞吐量/并发）、错误监控（错误率/类型分布）、
可用性监控、基线与性能退化检测、告警、监控报告。纯 Python 实现。
"""

from __future__ import annotations

import os
import json
import time
import threading
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional


_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "api_gateway",
)


def _percentile(sorted_vals: List[float], p: float) -> float:
    """计算百分位（p: 0~100）。"""
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return round(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac, 3)


class APIMonitor:
    """API 监控器（线程安全，单例）。"""

    def __init__(self, data_dir: Optional[str] = None,
                 retention: int = 10_000) -> None:
        """初始化监控器。

        Args:
            data_dir: 持久化目录。
            retention: 每个端点保留的指标样本数。
        """
        self._lock = threading.RLock()
        self._data_dir = data_dir or _DATA_DIR
        os.makedirs(self._data_dir, exist_ok=True)
        self._retention = retention

        # 端点指标：endpoint -> {method -> [(ts, rt, status)]}
        self._metrics: Dict[str, Dict[str, Deque]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=retention)))

        # 当前并发数
        self._concurrent: int = 0

        # 告警阈值：endpoint -> {rt_p95, error_rate, availability}
        self._thresholds: Dict[str, Dict[str, float]] = {
            "*": {"rt_p95": 1000.0, "error_rate": 0.05,
                  "degradation_ratio": 0.20, "min_requests": 20},
        }

        # 基线：endpoint -> {p50, p95, error_rate, updated}
        self._baselines: Dict[str, Dict[str, float]] = {}

        # 告警事件
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=500)

    # ------------------------------------------------------------------ #
    # 指标记录
    # ------------------------------------------------------------------ #
    def record_metric(self, endpoint: str, method: str,
                       response_time: float, status_code: int) -> None:
        """记录一次请求指标。

        Args:
            endpoint: API 端点。
            method: HTTP 方法。
            response_time: 响应时间（毫秒）。
            status_code: 状态码。
        """
        now = time.time()
        with self._lock:
            self._metrics[endpoint][method].append((now, response_time, status_code))
            # 记录后检测退化
            self._detect_and_alert(endpoint)

    # ------------------------------------------------------------------ #
    # 端点统计
    # ------------------------------------------------------------------ #
    def _samples(self, endpoint: str,
                 window: Optional[float] = None) -> List[List[float]]:
        """汇总某端点所有方法的样本 [[ts, rt, status], ...]。"""
        out: List[List[float]] = []
        cutoff = None if window is None else time.time() - window
        for method in self._metrics.get(endpoint, {}).values():
            for ts, rt, st in method:
                if cutoff is not None and ts < cutoff:
                    continue
                out.append([ts, rt, st])
        return out

    def get_endpoint_stats(self, endpoint: str) -> Dict[str, Any]:
        """获取端点性能/错误/可用性统计。"""
        with self._lock:
            samples = self._samples(endpoint)
        if not samples:
            return {"endpoint": endpoint, "requests": 0, "available": True}

        rts = sorted(s[1] for s in samples)
        n = len(samples)
        errors_4xx = sum(1 for s in samples if 400 <= s[2] < 500)
        errors_5xx = sum(1 for s in samples if s[2] >= 500)
        errors = errors_4xx + errors_5xx
        success = n - errors
        return {
            "endpoint": endpoint,
            "requests": n,
            "rt_avg": round(sum(rts) / n, 3),
            "rt_p50": _percentile(rts, 50),
            "rt_p95": _percentile(rts, 95),
            "rt_p99": _percentile(rts, 99),
            "rt_max": round(max(rts), 3),
            "rt_min": round(min(rts), 3),
            "error_4xx": errors_4xx,
            "error_5xx": errors_5xx,
            "error_rate": round(errors / n, 4),
            "availability": round(success / n, 4),
        }

    def get_all_endpoints(self) -> List[str]:
        """获取所有被监控的端点。"""
        with self._lock:
            return sorted(self._metrics.keys())

    # ------------------------------------------------------------------ #
    # 吞吐量 / 并发
    # ------------------------------------------------------------------ #
    def get_throughput(self, window: int = 60) -> Dict[str, Any]:
        """计算窗口内吞吐量。"""
        cutoff = time.time() - window
        count = 0
        with self._lock:
            for ep in self._metrics.values():
                for method in ep.values():
                    for ts, _, _ in method:
                        if ts >= cutoff:
                            count += 1
        return {
            "window_seconds": window,
            "requests": count,
            "per_second": round(count / window, 3),
            "per_minute": round(count / window * 60, 1),
            "current_concurrent": self._concurrent,
        }

    # ------------------------------------------------------------------ #
    # 趋势
    # ------------------------------------------------------------------ #
    def get_trends(self, time_range: str = "1h") -> Dict[str, Any]:
        """获取性能趋势（按端点聚合）。"""
        # 将时间范围转成秒
        sec_map = {"1m": 60, "5m": 300, "1h": 3600,
                   "24h": 86400, "7d": 604800}
        window = sec_map.get(time_range, 3600)
        with self._lock:
            eps = list(self._metrics.keys())
        trends = []
        for ep in eps:
            st = self.get_endpoint_stats(ep)
            st["window"] = time_range
            trends.append(st)
        # 按请求数排序
        trends.sort(key=lambda x: x.get("requests", 0), reverse=True)
        return {"time_range": time_range, "endpoints": trends[:50],
                "throughput": self.get_throughput(window)}

    # ------------------------------------------------------------------ #
    # 可用性
    # ------------------------------------------------------------------ #
    def get_availability(self, endpoint: Optional[str] = None) -> Dict[str, Any]:
        """获取可用性。"""
        if endpoint:
            st = self.get_endpoint_stats(endpoint)
            return {"endpoint": endpoint,
                    "availability": st.get("availability", 1.0),
                    "requests": st.get("requests", 0)}
        total_req = 0
        total_ok = 0
        with self._lock:
            eps = list(self._metrics.keys())
        for ep in eps:
            st = self.get_endpoint_stats(ep)
            n = st.get("requests", 0)
            total_req += n
            total_ok += int(n * st.get("availability", 1.0))
        return {
            "availability": round(total_ok / total_req, 4) if total_req else 1.0,
            "total_requests": total_req,
            "total_success": total_ok,
            "endpoint_count": len(eps),
        }

    # ------------------------------------------------------------------ #
    # 退化检测 / 告警
    # ------------------------------------------------------------------ #
    def set_alert_threshold(self, endpoint: Optional[str] = None,
                            **thresholds: float) -> Dict[str, float]:
        """设置告警阈值。"""
        with self._lock:
            key = endpoint or "*"
            t = self._thresholds.setdefault(key, {})
            for k, v in thresholds.items():
                t[k] = float(v)
            return dict(t)

    def get_alert_threshold(self, endpoint: Optional[str] = None) -> Dict[str, float]:
        """获取告警阈值。"""
        with self._lock:
            base = dict(self._thresholds.get("*", {}))
            if endpoint and endpoint in self._thresholds:
                base.update(self._thresholds[endpoint])
            return base

    def _detect_and_alert(self, endpoint: str) -> None:
        """检测性能退化并生成告警（在持锁状态下调用）。"""
        samples = self._samples(endpoint)
        if len(samples) < 5:
            return
        rts = sorted(s[1] for s in samples)
        p95 = _percentile(rts, 95)
        n = len(samples)
        err_rate = sum(1 for s in samples if s[2] >= 400) / n

        th = self.get_alert_threshold(endpoint)
        # 错误率告警
        if err_rate >= th.get("error_rate", 0.05):
            self._alerts.appendleft({
                "time": time.time(), "endpoint": endpoint,
                "type": "high_error_rate",
                "value": round(err_rate, 4),
                "threshold": th.get("error_rate"), "active": True,
            })
        # 响应时间告警
        if p95 >= th.get("rt_p95", 1000.0):
            self._alerts.appendleft({
                "time": time.time(), "endpoint": endpoint,
                "type": "high_response_time",
                "value": p95,
                "threshold": th.get("rt_p95"), "active": True,
            })
        # 基线退化检测
        baseline = self._baselines.get(endpoint)
        if baseline:
            deg_ratio = th.get("degradation_ratio", 0.20)
            base_p95 = baseline.get("p95", p95)
            if base_p95 > 0 and (p95 - base_p95) / base_p95 >= deg_ratio:
                self._alerts.appendleft({
                    "time": time.time(), "endpoint": endpoint,
                    "type": "performance_degradation",
                    "value": p95, "baseline_p95": base_p95,
                    "degradation_ratio": round((p95 - base_p95) / base_p95, 4),
                    "active": True,
                })
        else:
            # 样本足够时建立基线
            if n >= th.get("min_requests", 20):
                self._baselines[endpoint] = {
                    "p50": _percentile(rts, 50),
                    "p95": p95,
                    "error_rate": round(err_rate, 4),
                    "updated": time.time(),
                }

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """对所有端点执行一次异常检测，返回当前活跃告警。"""
        with self._lock:
            eps = list(self._metrics.keys())
            for ep in eps:
                self._detect_and_alert(ep)
            return self.get_alerts(active_only=True)

    def get_alerts(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """获取告警列表。"""
        with self._lock:
            items = list(self._alerts)
        if active_only:
            items = [a for a in items if a.get("active", True)]
        return items[:100]

    # ------------------------------------------------------------------ #
    # 报告
    # ------------------------------------------------------------------ #
    def generate_report(self, time_range: str = "24h") -> Dict[str, Any]:
        """生成 API 监控报告。"""
        eps = self.get_all_endpoints()
        endpoint_reports = [self.get_endpoint_stats(ep) for ep in eps]
        # 错误端点排名
        err_rank = sorted(endpoint_reports,
                          key=lambda x: x.get("error_rate", 0), reverse=True)
        slow_rank = sorted(endpoint_reports,
                           key=lambda x: x.get("rt_p95", 0), reverse=True)
        avail = self.get_availability()
        anomalies = self.detect_anomalies()

        suggestions: List[str] = []
        for ep in err_rank[:3]:
            if ep.get("error_rate", 0) > 0.05:
                suggestions.append(
                    f"端点 {ep['endpoint']} 错误率 {ep['error_rate']:.1%}，"
                    f"建议检查后端依赖与熔断配置")
        for ep in slow_rank[:3]:
            if ep.get("rt_p95", 0) > 1000:
                suggestions.append(
                    f"端点 {ep['endpoint']} P95 延迟 {ep['rt_p95']:.0f}ms，"
                    f"建议加缓存或优化数据库查询")

        return {
            "time_range": time_range,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_endpoints": len(eps),
                "availability": avail["availability"],
                "total_requests": avail["total_requests"],
                "active_alerts": len(anomalies),
            },
            "endpoint_stats": endpoint_reports,
            "top_errors": [
                {"endpoint": e["endpoint"], "error_rate": e["error_rate"],
                 "requests": e["requests"]}
                for e in err_rank[:5]
            ],
            "top_slow": [
                {"endpoint": e["endpoint"], "rt_p95": e["rt_p95"],
                 "rt_avg": e["rt_avg"]}
                for e in slow_rank[:5]
            ],
            "alerts": anomalies[:20],
            "optimization_suggestions": suggestions,
        }


# 模块级单例
api_monitor = APIMonitor()
