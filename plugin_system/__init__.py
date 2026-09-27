# -*- coding: utf-8 -*-
"""
plugin_system - 插件扩展系统（第11轮升级）

提供插件管理、插件市场、SDK 开发框架、安全审核、运行时五大能力。
所有功能以防御/评估/检测视角实现，数据存储于内存字典，不依赖数据库。
"""

from __future__ import annotations

__version__ = "11.0.0"
__all__ = [
    "plugin_manager",
    "plugin_marketplace",
    "plugin_sdk",
    "plugin_security",
    "plugin_runtime",
]
