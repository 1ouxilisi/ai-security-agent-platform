# -*- coding: utf-8 -*-
"""
api_gateway 模块（第 10 轮深化 - 第五优先级）。

提供 API 网关治理的六大核心能力：
    - RateLimiter      API 限流器（令牌桶/漏桶/固定窗口/滑动窗口）
    - CircuitBreaker   API 熔断器（三态状态机）
    - DegradationManager API 降级器
    - APICache         API 缓存器（TTL/LRU/LFU）
    - APILogger        API 日志器（脱敏 + 持久化）
    - APIMonitor       API 监控器（性能/错误/可用性/告警）

每个类均为线程安全单例，模块级实例直接可用。
"""

from __future__ import annotations

# 限流器
from .rate_limiter import RateLimiter, rate_limiter
# 熔断器
from .circuit_breaker import CircuitBreaker, CircuitBreakerError, circuit_breaker
# 降级器
from .degradation import DegradationManager, degradation_manager
# 缓存器
from .api_cache import APICache, api_cache
# 日志器
from .api_logger import APILogger, api_logger
# 监控器
from .api_monitor import APIMonitor, api_monitor

__all__ = [
    # 类
    "RateLimiter",
    "CircuitBreaker",
    "CircuitBreakerError",
    "DegradationManager",
    "APICache",
    "APILogger",
    "APIMonitor",
    # 单例
    "rate_limiter",
    "circuit_breaker",
    "degradation_manager",
    "api_cache",
    "api_logger",
    "api_monitor",
]

__version__ = "1.0.0"
__round__ = "v10-priority-5"
