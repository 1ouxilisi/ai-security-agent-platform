# -*- coding: utf-8 -*-
"""
developer_ecosystem — 跨平台客户端与开发者生态包（第24轮升级方向4）。

六大核心模块：
  - cli_tool       : CLI 命令行工具框架与全部子命令
  - desktop_client : 跨平台桌面客户端框架
  - ide_plugin     : VS Code / IDE 插件
  - python_sdk     : Python SDK 与 API 文档
  - developer_portal: 开发者门户与插件市场
  - open_api       : 开放 API 网关与 Webhook

全部内存字典模拟，不依赖数据库。所有模块 try-import 第三方库，缺失时回退模拟。
本包仅用于授权安全评估与开发者运营场景。
"""

from __future__ import annotations

__version__ = "24.4.0"
__author__ = "AI Hacking Agent Team"

# 子模块（try-import，缺失不崩溃）
try:
    from . import cli_tool as _cli_tool
    CLI_TOOL = _cli_tool
except Exception:
    CLI_TOOL = None

try:
    from . import desktop_client as _desktop_client
    DESKTOP_CLIENT = _desktop_client
except Exception:
    DESKTOP_CLIENT = None

try:
    from . import ide_plugin as _ide_plugin
    IDE_PLUGIN = _ide_plugin
except Exception:
    IDE_PLUGIN = None

try:
    from . import python_sdk as _python_sdk
    PYTHON_SDK = _python_sdk
except Exception:
    PYTHON_SDK = None

try:
    from . import developer_portal as _developer_portal
    DEVELOPER_PORTAL = _developer_portal
except Exception:
    DEVELOPER_PORTAL = None

try:
    from . import open_api as _open_api
    OPEN_API = _open_api
except Exception:
    OPEN_API = None

__all__ = [
    "CLI_TOOL", "DESKTOP_CLIENT", "IDE_PLUGIN",
    "PYTHON_SDK", "DEVELOPER_PORTAL", "OPEN_API",
    "__version__",
]
