#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_metrics_deep — 第25轮升级方向3：安全度量与成熟度平台。

包含 6 大核心模块：
    - maturity_assessment 安全成熟度评估（5级模型/控制域评估/差距分析/路线图/趋势/报告/基准）
    - kpi_kri             安全 KPI/KRI 管理（100+ KPI / 50+ KRI / 采集 / 分析 / 报告）
    - security_roi        安全投资回报率 ROI（投资管理/收益计算/ROI公式/成本管理/价值证明）
    - security_efficiency 安全效能度量（团队/流程/技术/质量/效率/效能改进）
    - security_culture    安全文化评估（意识/行为/沟通/培训/文化指标/文化改进）
    - metrics_dashboard   安全度量控制台数据层（总览/成熟度/KPI/ROI/效能/文化/系统设置）

设计定位：全部内存字典模拟，不建数据库表；真实评估/计算/度量逻辑，dry-run 输出。
"""

from __future__ import annotations

__version__ = "25.3.0"
__all__ = [
    "maturity_assessment",
    "kpi_kri",
    "security_roi",
    "security_efficiency",
    "security_culture",
    "metrics_dashboard",
]
