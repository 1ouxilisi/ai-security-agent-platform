#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
performance_deep — 第28轮升级方向3：性能优化与压力测试平台。

包含 7 大核心模块：
    - benchmark.py              性能基准测试（真实API压测/P50~P99.9/吞吐量/并发/资源/报告）
    - high_concurrency.py       高并发优化（连接池/线程池/协程/限流熔断/缓存/异步任务）
    - big_data.py               大数据量处理优化（分片/分区/批量/流式/压缩/物化视图）
    - distributed_scan_perf.py  分布式扫描性能（Master-Worker/任务分发/代理池/断点续扫）
    - stress_test.py            压力测试与稳定性（负载/峰值/浸泡/故障注入/混沌/恢复/容量）
    - performance_monitor.py   性能监控与告警（实时指标/告警规则/瓶颈分析/仪表盘）
    - performance_dashboard.py  性能优化控制台数据聚合层（8视图总览）

设计定位：全部内存字典模拟，不建数据库表；
    基准测试/压测真实执行计时与百分位统计；连接池/线程池/缓存/代理池真实管理；
    psutil 可用时采集真实系统指标，缺失自动回退模拟。
"""

from __future__ import annotations

__version__ = "28.3.0"
__all__ = [
    "benchmark",
    "high_concurrency",
    "big_data",
    "distributed_scan_perf",
    "stress_test",
    "performance_monitor",
    "performance_dashboard",
]
