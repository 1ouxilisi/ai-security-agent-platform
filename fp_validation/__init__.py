# -*- coding: utf-8 -*-
"""fp_validation — 误报率验证做实包（方向1）。

提供 10 个真实靶场知识库、一键靶场验证执行器、误报/漏报/准确率/召回率/F1
指标计算、检测规则优化器、误报率报告生成与仪表盘聚合。
"""
from __future__ import annotations

from .range_repository import RangeRepository, get_repository
from .metrics_calculator import MetricsCalculator, get_calculator
from .rule_optimizer import RuleOptimizer, get_optimizer
from .fp_report import FPReportGenerator, get_report_generator
from .fp_dashboard import FPDashboard, get_dashboard
from .fp_runner import FPRunner, get_runner

__all__ = [
    "RangeRepository",
    "get_repository",
    "MetricsCalculator",
    "get_calculator",
    "RuleOptimizer",
    "get_optimizer",
    "FPReportGenerator",
    "get_report_generator",
    "FPDashboard",
    "get_dashboard",
    "FPRunner",
    "get_runner",
]
