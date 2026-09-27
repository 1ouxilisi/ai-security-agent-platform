# -*- coding: utf-8 -*-
"""developer_portal — 开放 API 平台与开发者中心。

模块组成：
- api_docs:           API 文档中心（OpenAPI 3.0 / 交互式调试 / 版本管理 / 变更日志）
- sdk_tools:          多语言 SDK / Postman / cURL / CLI
- sandbox_manager:    开发者沙箱 / 模拟数据 / 请求回放
- app_key_manager:   应用注册 / API Key / 权限范围 / IP 白名单
- usage_billing:      用量统计 / 配额 / 套餐 / 计费
- community_support:  论坛 / 教程 / 状态页 / 贡献者
- portal_workflow:    开发者中心综合工作流（注册->应用->密钥->沙箱->调用->计费->社区）

所有模块均为纯内存字典模拟，不依赖数据库。
"""

from __future__ import annotations

__all__ = [
    "api_docs",
    "sdk_tools",
    "sandbox_manager",
    "app_key_manager",
    "usage_billing",
    "community_support",
    "portal_workflow",
]

__version__ = "15.0.0"
