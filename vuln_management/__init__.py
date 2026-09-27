# -*- coding: utf-8 -*-
"""
vuln_management 模块 —— 漏洞管理深化模块。

模块组成：
    - lifecycle        漏洞生命周期管理器（状态流转 / 分配 / 优先级 / 评论 / 标签 / 历史）
    - sla              漏洞 SLA 管理器（策略 / 截止时间 / 合规统计 / 例外审批）
    - analytics        漏洞分析引擎（趋势 / 修复率 / 老化分布 / 资产风险排名 / 扫描对比）
    - remediation_tracker 修复跟踪器（修复任务 / 修复方案 / 验证 / 回滚）

设计说明：
    - 统一复用 utils.database.db 全局实例（WAL 模式）
    - 所有表使用 CREATE TABLE IF NOT EXISTS 幂等创建，扩展列使用 ALTER + try/except 兼容已有表
    - 本模块仅用于授权的安全评估与漏洞治理场景
"""

from vuln_management.lifecycle import lifecycle_manager, LifecycleManager
from vuln_management.sla import sla_manager, SLAManager
from vuln_management.analytics import analytics_engine, VulnerabilityAnalytics
from vuln_management.remediation_tracker import remediation_tracker, RemediationTracker

__all__ = [
    "lifecycle_manager",
    "LifecycleManager",
    "sla_manager",
    "SLAManager",
    "analytics_engine",
    "VulnerabilityAnalytics",
    "remediation_tracker",
    "RemediationTracker",
]
