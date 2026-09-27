#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
__init__分布式扫描功能模块，提供相关分布式任务管理功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
from distributed.scheduler import DistributedScheduler, DistributedTask, TaskStatus, WorkerNode, WorkerStatus
from distributed.worker_node import WorkerManager, WorkerHeartbeat
from distributed.result_aggregator import ResultAggregator, AggregatedResult
from distributed.proxy_pool import ProxyPool, ProxyServer, ProxyType

__all__ = [
    'DistributedScheduler', 'DistributedTask', 'TaskStatus', 'WorkerNode', 'WorkerStatus',
    'WorkerManager', 'WorkerHeartbeat',
    'ResultAggregator', 'AggregatedResult',
    'ProxyPool', 'ProxyServer', 'ProxyType',
    'distributed_scheduler', 'worker_manager', 'result_aggregator', 'proxy_pool',
]

# 全局实例
distributed_scheduler = DistributedScheduler()
worker_manager = WorkerManager()
result_aggregator = ResultAggregator()
proxy_pool = ProxyPool()
