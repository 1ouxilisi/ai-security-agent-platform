# -*- coding: utf-8 -*-
"""real_usability — 真实可用性大升级包（方向3）。

提供：
    - fp_optimizer:        误报率优化（10 靶场验证 / 规则调优 / 误报率报告）
    - e2e_runner:          端到端真实跑通（testphp.vulnweb.com 全流程）
    - range_manager:       真实靶场集成（DVWA/JuiceShop/WebGoat/...）
    - quality_check:       输出质量检查（POC/复现/修复建议）
    - usability_dashboard: 可用性聚合

目标：真实可用性 7.5 → 9.5，误报率 < 5%。
"""
from __future__ import annotations

import logging

from .fp_optimizer import (
    FPRealTester,
    FalsePositiveOptimizer,
    FP_RULES,
    TARGET_RANGES,
)
from .e2e_runner import (
    E2ERunner,
    E2E_STAGES,
)
from .range_manager import (
    RangeManager,
    KNOWN_RANGES,
)
from .quality_check import (
    QualityChecker,
    QUALITY_RUBRIC,
)
from .usability_dashboard import (
    UsabilityDashboard,
    USABILITY_SCORE_BASELINE,
)

__all__ = [
    "FPRealTester", "FalsePositiveOptimizer", "FP_RULES", "TARGET_RANGES",
    "E2ERunner", "E2E_STAGES",
    "RangeManager", "KNOWN_RANGES",
    "QualityChecker", "QUALITY_RUBRIC",
    "UsabilityDashboard", "USABILITY_SCORE_BASELINE",
]

logger = logging.getLogger(__name__)
logger.info("real_usability package loaded (方向3: 真实可用性大升级)")
