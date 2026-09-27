#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar_deep — 第24轮升级方向2：SOAR 深度平台。

包含 6 大核心模块：
    - playbook_engine          可视化剧本编排引擎（节点/连线/条件/循环/并行/变量/版本/调试）
    - response_actions         响应动作库（网络/终端/账户/云/应用/通知 6 类动作）
    - alert_triage             告警分诊与聚合（接入/标准化/去重/聚合/分诊/丰富化）
    - case_management          案例管理与协作（创建/协作/时间线/知识库/分析）
    - threat_intel_integration 威胁情报联动（IOC匹配/情报查询/驱动响应/共享/质量评估）
    - soar_dashboard           SOAR 管理控制台数据层（总览/剧本/动作/告警/案例/系统设置）

设计定位：全部内存字典模拟，不建数据库表，不实际下发任何生产操作。
"""

from __future__ import annotations

__version__ = "24.2.0"
__all__ = [
    "playbook_engine",
    "response_actions",
    "alert_triage",
    "case_management",
    "threat_intel_integration",
    "soar_dashboard",
]
