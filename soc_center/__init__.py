# -*- coding: utf-8 -*-
"""
soc_center 包 — 统一安全运营中心（SOC Center）。

整合十六大核心领域 Pro 版本：
    - 统一入口 /soc-center（顶部导航 + 左任务 + 中仪表盘 + 右告警 + 底日志）
    - 统一数据聚合层（任务/告警/漏洞/资产/事件/日志 统一模型 + 适配器）
    - 统一 WebSocket 推送 /api/v1/soc-center/ws
    - 全局搜索 / 统一通知中心 / 统一配置中心

模块:
    data_aggregator         统一数据聚合层（统一模型 + 适配器 + 查询 + 缓存）
    unified_dashboard       统一仪表盘（安全态势总览）
    unified_task_list       统一任务列表
    unified_alert_center    统一告警中心
    unified_operation_log   统一操作日志
    global_search           全局搜索
    notification_center     统一通知中心（WebSocket）
    configuration_center    统一配置中心
    soc_center_dashboard    SOC Center 顶层聚合门面
"""

from __future__ import annotations

from .configuration_center import ConfigurationCenter, get_configuration_center
from .data_aggregator import (
    DOMAINS, DOMAIN_KEYS, DOMAIN_NAME_MAP, UnifiedDataAggregator,
    get_aggregator,
)
from .global_search import GlobalSearch, get_global_search
from .notification_center import NotificationCenter, get_notification_center
from .soc_center_dashboard import SOCCenterDashboard, get_soc_center
from .unified_alert_center import UnifiedAlertCenter, get_alert_center
from .unified_dashboard import UnifiedDashboard, get_dashboard
from .unified_operation_log import UnifiedOperationLog, get_operation_log
from .unified_task_list import UnifiedTaskList, get_task_list

__all__ = [
    "DOMAINS", "DOMAIN_KEYS", "DOMAIN_NAME_MAP",
    "UnifiedDataAggregator", "get_aggregator",
    "UnifiedDashboard", "get_dashboard",
    "UnifiedTaskList", "get_task_list",
    "UnifiedAlertCenter", "get_alert_center",
    "UnifiedOperationLog", "get_operation_log",
    "GlobalSearch", "get_global_search",
    "NotificationCenter", "get_notification_center",
    "ConfigurationCenter", "get_configuration_center",
    "SOCCenterDashboard", "get_soc_center",
]
