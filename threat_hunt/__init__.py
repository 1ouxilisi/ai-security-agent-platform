#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
threat_hunt — 威胁狩猎专业级模块（第 17 轮升级方向 1）。

提供威胁狩猎全流程能力：
    - hunt_query_engine         类SQL狩猎查询引擎（解析/验证/执行/模板库/版本管理）
    - hypothesis_driven_hunt    假设驱动狩猎（假设管理/项目/剧本/发现）
    - behavior_analysis         行为分析引擎（基线/画像/异常检测/行为链/评分）
    - ioc_enrichment            IOC关联与富化（IOC管理/富化/关联/导入导出/评分）
    - hunt_data_manager         狩猎数据管理（数据源/跨源搜索/管道/质量/导出）
    - hunt_report_metrics       狩猎报告与度量（报告/度量/知识库/成熟度/仪表盘）

设计定位：
    - 仅做检测、监控、分析、管理视角的威胁狩猎，不提供攻击/入侵工具。
    - 所有功能仅用于经过授权的防御性威胁狩猎活动，输出检测报告与建议。
    - 第三方库一律 try-import，不可用时自动回退到内嵌模拟/离线数据。
    - Python 3.14 兼容。
"""

from __future__ import annotations

__version__ = "17.1.0"
__round__ = 17
__direction__ = "threat_hunting_pro"

# 核心类与工厂函数（try-import，避免单个模块缺失导致整个包不可用）
try:
    from threat_hunt.hunt_query_engine import (
        HuntQueryEngine, HUNT_QUERY_TEMPLATES, QueryTemplate,
    )
except Exception:  # pragma: no cover
    HuntQueryEngine = None  # type: ignore
    HUNT_QUERY_TEMPLATES = []
    QueryTemplate = None  # type: ignore

try:
    from threat_hunt.hypothesis_driven_hunt import (
        HypothesisManager, HuntProjectManager, HuntPlaybookManager, HuntFindingManager,
    )
except Exception:  # pragma: no cover
    HypothesisManager = None  # type: ignore
    HuntProjectManager = None  # type: ignore
    HuntPlaybookManager = None  # type: ignore
    HuntFindingManager = None  # type: ignore

try:
    from threat_hunt.behavior_analysis import (
        BehaviorBaselineBuilder, EntityProfiler, AnomalyDetector,
        BehaviorChainAnalyzer, BehaviorScorer,
    )
except Exception:  # pragma: no cover
    BehaviorBaselineBuilder = None  # type: ignore
    EntityProfiler = None  # type: ignore
    AnomalyDetector = None  # type: ignore
    BehaviorChainAnalyzer = None  # type: ignore
    BehaviorScorer = None  # type: ignore

try:
    from threat_hunt.ioc_enrichment import (
        IOCManager, IOCEnricher, IOCRelationAnalyzer, IOCImportExport, IOCScorer,
    )
except Exception:  # pragma: no cover
    IOCManager = None  # type: ignore
    IOCEnricher = None  # type: ignore
    IOCRelationAnalyzer = None  # type: ignore
    IOCImportExport = None  # type: ignore
    IOCScorer = None  # type: ignore

try:
    from threat_hunt.hunt_data_manager import (
        DataSourceManager, CrossSourceSearcher, DataPipeline,
        DataQualityMonitor, HuntDataExporter,
    )
except Exception:  # pragma: no cover
    DataSourceManager = None  # type: ignore
    CrossSourceSearcher = None  # type: ignore
    DataPipeline = None  # type: ignore
    DataQualityMonitor = None  # type: ignore
    HuntDataExporter = None  # type: ignore

try:
    from threat_hunt.hunt_report_metrics import (
        HuntReportGenerator, HuntMetricsCalculator, HuntKnowledgeBase,
        HuntMaturityAssessor, HuntDashboardData,
    )
except Exception:  # pragma: no cover
    HuntReportGenerator = None  # type: ignore
    HuntMetricsCalculator = None  # type: ignore
    HuntKnowledgeBase = None  # type: ignore
    HuntMaturityAssessor = None  # type: ignore
    HuntDashboardData = None  # type: ignore

__all__ = [
    "__version__",
    "__round__",
    "__direction__",
    "HuntQueryEngine",
    "HUNT_QUERY_TEMPLATES",
    "QueryTemplate",
    "HypothesisManager",
    "HuntProjectManager",
    "HuntPlaybookManager",
    "HuntFindingManager",
    "BehaviorBaselineBuilder",
    "EntityProfiler",
    "AnomalyDetector",
    "BehaviorChainAnalyzer",
    "BehaviorScorer",
    "IOCManager",
    "IOCEnricher",
    "IOCRelationAnalyzer",
    "IOCImportExport",
    "IOCScorer",
    "DataSourceManager",
    "CrossSourceSearcher",
    "DataPipeline",
    "DataQualityMonitor",
    "HuntDataExporter",
    "HuntReportGenerator",
    "HuntMetricsCalculator",
    "HuntKnowledgeBase",
    "HuntMaturityAssessor",
    "HuntDashboardData",
]
