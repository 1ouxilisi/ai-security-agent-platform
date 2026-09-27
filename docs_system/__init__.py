# -*- coding: utf-8 -*-
"""
docs_system — 文档体系大提升模块包。

包含 6 大核心模块：
    1. architecture_docs   — 架构文档体系
    2. api_docs_center     — API 文档中心
    3. user_guides         — 用户手册与指南
    4. deployment_ops_docs — 部署与运维文档
    5. knowledge_base      — 知识库与最佳实践
    6. docs_management     — 文档管理与运营

所有模块均为纯数据生成器，通过内存字典模拟异步任务，
不依赖数据库，第三方库 try-import 后回退模拟数据。
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "ai-hacking-agent docs_system"

MODULES = [
    "architecture_docs",
    "api_docs_center",
    "user_guides",
    "deployment_ops_docs",
    "knowledge_base",
    "docs_management",
]
