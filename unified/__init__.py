#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全域安全评估统一框架 (Unified Security Assessment Framework)

融合渗透测试、移动安全、区块链安全、AI智能体安全四大领域，
提供统一的数据模型、风险评级、评估引擎、知识库和报告生成。

仅用于授权的安全测试与防御评估。
"""

from unified.models import (
    DomainType,
    Severity,
    Finding,
    DomainAssessment,
    UnifiedAssessmentResult,
    ReportConfig,
)
from unified.risk_scoring import RiskScorer, calculate_risk_score, risk_level_from_score
from unified.knowledge_base import KnowledgeBase, get_knowledge_base
from unified.engine import UnifiedAssessmentEngine, get_engine
from unified.registry import register_all_domains, get_domain_status

__version__ = "1.0.0"
__all__ = [
    "DomainType", "Severity", "Finding", "DomainAssessment",
    "UnifiedAssessmentResult", "ReportConfig",
    "RiskScorer", "calculate_risk_score", "risk_level_from_score",
    "KnowledgeBase", "get_knowledge_base",
    "UnifiedAssessmentEngine", "get_engine",
    "register_all_domains", "get_domain_status",
]
