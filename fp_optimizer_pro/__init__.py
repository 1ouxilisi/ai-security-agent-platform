# -*- coding: utf-8 -*-
"""fp_optimizer_pro — 误报率优化Pro包（方向1核心）。

目标：将误报率从 18.75% 降到 5% 以下。

模块：
- rule_optimizer_pro:  规则优化器Pro — 排除常见误报、nuclei规则调优
- secondary_verifier:   二次验证机制 — SQLi/XSS/目录遍历真实payload验证
- confidence_scorer:    置信度评分 — 高/中/低三级，工具检测+二次验证
- fp_filter_engine:     误报过滤引擎 — 已知误报特征库 + 白名单机制
- fp_pro_dashboard:     仪表盘聚合 — 误报率指标、优化前后对比、报告
"""
from __future__ import annotations

from .rule_optimizer_pro import RuleOptimizerPro, get_rule_optimizer_pro
from .secondary_verifier import SecondaryVerifier, get_secondary_verifier
from .confidence_scorer import ConfidenceScorer, get_confidence_scorer
from .fp_filter_engine import FPFilterEngine, get_fp_filter_engine
from .fp_pro_dashboard import FPProDashboard, get_fp_pro_dashboard

__all__ = [
    "RuleOptimizerPro",
    "get_rule_optimizer_pro",
    "SecondaryVerifier",
    "get_secondary_verifier",
    "ConfidenceScorer",
    "get_confidence_scorer",
    "FPFilterEngine",
    "get_fp_filter_engine",
    "FPProDashboard",
    "get_fp_pro_dashboard",
]
