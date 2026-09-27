#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_metrics_deep/metrics_dashboard.py — 安全度量控制台数据层。

聚合 7 大视图：
    1. 度量总览：成熟度/KPI达标/KRI预警/ROI/效能/文化/安全趋势/风险趋势
    2. 成熟度管理：模型/评估/路线图/趋势/报告/基准
    3. KPI/KRI 管理：指标库/定义/采集/分析/报告/仪表盘
    4. ROI 管理：投资/收益/ROI/分析/成本/价值证明
    5. 效能管理：团队/流程/技术/质量/效率/改进
    6. 文化管理：意识/行为/沟通/培训/指标/改进
    7. 系统设置：模型/指标/采集/报告/通知/权限/审计配置
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .maturity_assessment import (
    get_maturity_assessor, MATURITY_LEVELS, MATURITY_MODELS,
    INDUSTRY_BENCHMARKS, SCALE_BENCHMARKS, REGION_BENCHMARKS,
)
from .kpi_kri import get_metrics_manager
from .security_roi import get_roi_manager, INVESTMENT_CATEGORIES
from .security_efficiency import get_efficiency_manager
from .security_culture import get_culture_manager


SYSTEM_SETTINGS: Dict[str, Dict[str, Any]] = {
    "model_config": {
        "default_model": "nist_csf",
        "target_level": 4,
        "assessment_cycle_months": 6,
        "auto_reassess": True,
    },
    "metric_config": {
        "kpi_target_default": 85.0,
        "kri_threshold_default": 60.0,
        "weighting_enabled": True,
        "custom_kpi_allowed": True,
    },
    "collection_config": {
        "auto_collect": True,
        "collect_interval_minutes": 60,
        "sources": ["siem", "scanner", "ticketing", "finance", "hr"],
        "batch_size": 50,
    },
    "report_config": {
        "weekly_report": True,
        "monthly_report": True,
        "executive_report": True,
        "format": ["pdf", "html"],
        "distribution": ["cio", "ciso", "it-director"],
    },
    "notification_config": {
        "kri_alert_enabled": True,
        "kpi_miss_alert_enabled": True,
        "channel": "im",
        "escalation_after_minutes": 30,
    },
    "permission_config": {
        "roles": ["admin", "analyst", "manager", "viewer"],
        "report_export_roles": ["admin", "manager"],
    },
    "audit_config": {
        "audit_metric_changes": True,
        "audit_assessments": True,
        "retention_days": 365,
    },
}


class MetricsDashboard:
    def __init__(self) -> None:
        self.assessor = get_maturity_assessor()
        self.metrics = get_metrics_manager()
        self.roi = get_roi_manager()
        self.eff = get_efficiency_manager()
        self.culture = get_culture_manager()

    # -- 度量总览 -- #
    def overview(self) -> Dict[str, Any]:
        # 首次自动跑一次评估，保证总览有数据
        if not self.assessor.assessments:
            self.assessor.create_assessment("nist_csf", "示例企业")
        ma = next(iter(self.assessor.assessments.values()))
        kpi = self.metrics.kpi_dashboard()
        kri = self.metrics.kri_dashboard()
        eff = self.eff.overview()
        cul = self.culture.culture_indicators()
        return {
            "maturity": {"level": ma["overall_level_name"], "score": ma["overall_score"]},
            "kpi_attainment": kpi["attainment"],
            "kri_active_alerts": kri["levels"]["严重"] + kri["levels"]["预警"],
            "roi": self.roi.roi_comparison()["by_category"],
            "efficiency_score": eff["team"]["team_efficiency_score"],
            "culture_score": cul["composite_score"],
            "security_trend": [{"period": f"Q{i+1}", "value": 60 + i * 4} for i in range(4)],
            "risk_trend": [{"period": f"Q{i+1}", "value": 80 - i * 3} for i in range(4)],
        }

    # -- 系统设置读写 -- #
    def get_settings(self) -> Dict[str, Any]:
        return SYSTEM_SETTINGS

    def update_settings(self, section: str, values: Dict[str, Any]) -> Dict[str, Any]:
        if section in SYSTEM_SETTINGS and isinstance(SYSTEM_SETTINGS[section], dict):
            SYSTEM_SETTINGS[section].update(values)
            return {"section": section, "updated": True, "settings": SYSTEM_SETTINGS[section]}
        return {"section": section, "updated": False}

    # -- 可用元数据 -- #
    def meta(self) -> Dict[str, Any]:
        return {
            "maturity_levels": MATURITY_LEVELS,
            "maturity_models": MATURITY_MODELS,
            "kpi_groups": self.metrics.kpi_groups(),
            "kri_groups": self.metrics.kri_groups(),
            "roi_categories": INVESTMENT_CATEGORIES,
            "industry_benchmarks": INDUSTRY_BENCHMARKS,
            "scale_benchmarks": SCALE_BENCHMARKS,
            "region_benchmarks": REGION_BENCHMARKS,
        }


_dash: Optional[MetricsDashboard] = None


def get_metrics_dashboard() -> MetricsDashboard:
    global _dash
    if _dash is None:
        _dash = MetricsDashboard()
    return _dash
