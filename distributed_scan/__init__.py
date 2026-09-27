# -*- coding: utf-8 -*-
"""
distributed_scan — 分布式扫描与任务调度模块（第23轮升级 · 方向2）。

提供：
- cluster_arch：Master/Worker 架构、节点注册、任务队列、调度、结果聚合
- task_manager：扫描任务 CRUD/控制/监控/历史/模板
- proxy_pool：代理管理/检测/池/IP 轮换/限流/反检测
- resume_scan：断点续扫/增量扫描/快照/分片/缓存
- resource_manager：配额/监控/资源调度/隔离/预警/报表
- cluster_dashboard：分布式管理控制台聚合视图

全部内存模拟，不建数据库表；第三方依赖 try-import 回退。
"""

from __future__ import annotations

__version__ = "23.2.0"
__all__ = [
    "cluster_arch", "task_manager", "proxy_pool",
    "resume_scan", "resource_manager", "cluster_dashboard",
]
