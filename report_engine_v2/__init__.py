#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
专业报告引擎 v2
CVSS v3.1评分 + 修复建议库 + 多格式报告生成
"""

from .cvss_scorer import (
    CVSSScorer,
    CVSSMetrics,
)
from .remediation_library import (
    RemediationLibrary,
    Remediation,
)
from .report_generator import (
    ReportGenerator,
    PentestReport,
    VulnerabilityFinding,
    ReportSection,
)

__all__ = [
    # CVSS评分
    "CVSSScorer",
    "CVSSMetrics",
    # 修复建议库
    "RemediationLibrary",
    "Remediation",
    # 报告生成
    "ReportGenerator",
    "PentestReport",
    "VulnerabilityFinding",
    "ReportSection",
]

__version__ = "2.0.0"
