# -*- coding: utf-8 -*-
"""
tools_installer 包 —— 真实安全工具一键安装

模块：
  - tool_registry: 工具元数据注册表
  - package_manager: 包管理器探测与执行
  - tool_detector: 工具安装/版本/健康检测
  - tool_installer: 一键安装/批量安装/升级/卸载/修复
  - tools_dashboard: 仪表盘聚合
"""
from __future__ import annotations

from . import tool_registry
from . import package_manager
from . import tool_detector
from . import tool_installer
from . import tools_dashboard

__all__ = [
    "tool_registry",
    "package_manager",
    "tool_detector",
    "tool_installer",
    "tools_dashboard",
]
