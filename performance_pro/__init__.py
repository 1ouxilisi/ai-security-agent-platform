# -*- coding: utf-8 -*-
"""performance_pro — 性能大升级包。

模块：
- startup_optimizer   启动速度优化（延迟加载 / 路由懒加载，30s → <10s）
- response_optimizer  API 响应优化（P95<50ms / LRU+TTL / 批量合并）
- concurrency_controller  并发控制（100并发不崩 / 异步 / 请求队列）
- db_optimizer_v2     数据库优化V2（索引 / 查询 / 缓存层）
- static_optimizer    静态资源优化（压缩 / 缓存头 / CDN）
- perf_pro_dashboard   性能聚合
"""

from __future__ import annotations

__version__ = "6.0.0"
__target_score__ = "9.0"

__all__ = [
    "startup_optimizer",
    "response_optimizer",
    "concurrency_controller",
    "db_optimizer_v2",
    "static_optimizer",
    "perf_pro_dashboard",
]
