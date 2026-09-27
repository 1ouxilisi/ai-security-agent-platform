#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data_lake_deep — 安全数据湖与大数据分析深度平台（第 29 轮升级方向 1）。

在既有数据安全/SIEM 基础上深度扩展：
    - lake_architecture        安全数据湖架构（分层/分区/生命周期/多源接入/数据治理）
    - log_aggregation          日志聚合与标准化（多源解析/标准化/富化/检索）
    - behavior_analysis        行为分析与 UEBA 深化（基线/偏离检测/风险评分）
    - ai_threat_detection      AI 驱动威胁检测深化（ML模型/特征工程/推理/监控）
    - data_mining              安全数据挖掘（关联/序列/聚类/预测/根因分析）
    - data_lake_dashboard      安全数据湖控制台数据聚合层

设计定位：
    - 安全运营视角的数据湖分析与模拟，不提供任何攻击工具。
    - 第三方库一律 try-import，不可用时自动回退到内嵌模拟/离线数据。
    - 全部内存字典模拟，不建数据库表。
"""

from __future__ import annotations

__version__ = "29.1.0"
__round__ = 29
__direction__ = 1

# 核心类与工厂函数（try-import，避免单个模块缺失导致整个包不可用）
try:
    from data_lake_deep.lake_architecture import (
        LakeArchitecture,
        LAKE_LAYERS,
        PARTITION_STRATEGIES,
        DATA_SOURCES,
        STORAGE_TYPES,
        LIFECYCLE_POLICIES,
    )
except Exception:  # pragma: no cover
    LakeArchitecture = None  # type: ignore
    LAKE_LAYERS = {}
    PARTITION_STRATEGIES = {}
    DATA_SOURCES = {}
    STORAGE_TYPES = {}
    LIFECYCLE_POLICIES = {}

try:
    from data_lake_deep.log_aggregation import (
        LogAggregationEngine,
        LOG_SOURCES,
        PARSER_TEMPLATES,
        STANDARD_FIELDS,
        RETENTION_POLICIES,
    )
except Exception:  # pragma: no cover
    LogAggregationEngine = None  # type: ignore
    LOG_SOURCES = {}
    PARSER_TEMPLATES = {}
    STANDARD_FIELDS = {}
    RETENTION_POLICIES = {}

try:
    from data_lake_deep.behavior_analysis import (
        BehaviorUEBAEngine,
        USER_BEHAVIOR_DIMS,
        ENTITY_TYPES,
        ANOMALY_TYPES,
        RISK_LEVELS,
    )
except Exception:  # pragma: no cover
    BehaviorUEBAEngine = None  # type: ignore
    USER_BEHAVIOR_DIMS = {}
    ENTITY_TYPES = {}
    ANOMALY_TYPES = {}
    RISK_LEVELS = {}

try:
    from data_lake_deep.ai_threat_detection import (
        AIThreatDetectionEngine,
        ML_MODELS,
        FEATURE_CATEGORIES,
        THREAT_TYPES,
        MODEL_STATUSES,
    )
except Exception:  # pragma: no cover
    AIThreatDetectionEngine = None  # type: ignore
    ML_MODELS = {}
    FEATURE_CATEGORIES = {}
    THREAT_TYPES = {}
    MODEL_STATUSES = {}

try:
    from data_lake_deep.data_mining import (
        DataMiningEngine,
        MINING_TASKS,
        ALGORITHMS,
        REPORT_TYPES,
    )
except Exception:  # pragma: no cover
    DataMiningEngine = None  # type: ignore
    MINING_TASKS = {}
    ALGORITHMS = {}
    REPORT_TYPES = {}

try:
    from data_lake_deep.data_lake_dashboard import (
        DataLakeDashboard,
        DASHBOARD_TABS,
    )
except Exception:  # pragma: no cover
    DataLakeDashboard = None  # type: ignore
    DASHBOARD_TABS = {}

__all__ = [
    "__version__", "__round__", "__direction__",
    "LakeArchitecture", "LAKE_LAYERS", "PARTITION_STRATEGIES",
    "DATA_SOURCES", "STORAGE_TYPES", "LIFECYCLE_POLICIES",
    "LogAggregationEngine", "LOG_SOURCES", "PARSER_TEMPLATES",
    "STANDARD_FIELDS", "RETENTION_POLICIES",
    "BehaviorUEBAEngine", "USER_BEHAVIOR_DIMS", "ENTITY_TYPES",
    "ANOMALY_TYPES", "RISK_LEVELS",
    "AIThreatDetectionEngine", "ML_MODELS", "FEATURE_CATEGORIES",
    "THREAT_TYPES", "MODEL_STATUSES",
    "DataMiningEngine", "MINING_TASKS", "ALGORITHMS", "REPORT_TYPES",
    "DataLakeDashboard", "DASHBOARD_TABS",
]
