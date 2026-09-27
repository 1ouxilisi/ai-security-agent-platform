#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
metrics_workflow.py — 安全度量综合工作流。

数据采集 → 指标计算 → 成熟度评估 → 风险评分 → 合规度量 → 高管报告 → 持续改进
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


METRICS_WORKFLOW_STEPS: List[Dict[str, Any]] = [
    {"step": 1, "name": "数据采集", "output": "原始度量数据(模拟)"},
    {"step": 2, "name": "指标计算", "output": "KPI 达成情况"},
    {"step": 3, "name": "成熟度评估", "output": "成熟度等级与维度分"},
    {"step": 4, "name": "风险评分", "output": "综合风险分与等级分布"},
    {"step": 5, "name": "合规度量", "output": "框架通过率与整改率"},
    {"step": 6, "name": "高管报告", "output": "CISO 仪表盘与一页纸"},
    {"step": 7, "name": "持续改进", "output": "改进项与路线图"},
]


class MetricsWorkflow:
    """安全度量端到端工作流编排器（全内存模拟）。"""

    def __init__(self) -> None:
        from security_metrics.maturity_model import SecurityMaturityModel
        from security_metrics.kpi_library import KPILibrary
        from security_metrics.risk_scoring import RiskScoringEngine
        from security_metrics.operational_efficiency import OperationalEfficiencyMetrics
        from security_metrics.compliance_audit import ComplianceAuditMetrics
        from security_metrics.executive_dashboard import ExecutiveDashboard
        self.mm = SecurityMaturityModel()
        self.kpi = KPILibrary()
        self.risk = RiskScoringEngine()
        self.ops = OperationalEfficiencyMetrics()
        self.comp = ComplianceAuditMetrics()
        self.dash = ExecutiveDashboard()

    def run(self, industry: str = "金融",
            include_report: bool = True) -> Dict[str, Any]:
        """执行完整度量工作流，返回全链路结果。"""
        started = time.strftime("%Y-%m-%d %H:%M:%S")
        log: List[Dict[str, Any]] = []

        # 1 数据采集（模拟）
        log.append({"step": 1, "name": "数据采集", "status": "done",
                    "note": "从 SIEM/工单/GRC/资产系统拉取模拟数据"})

        # 2 指标计算
        readings = {
            "KPI-RISK-VULN-03": 88.0, "KPI-OPS-TTR-01": 3.2,
            "KPI-TECH-COVERAGE-01": 96.0, "KPI-COMPLIANCE-REMEDIATION-01": 85.0,
        }
        kpi_eval = self.kpi.evaluate(readings)
        log.append({"step": 2, "name": "指标计算", "status": "done",
                    "note": f"评估 {kpi_eval['total_metrics']} 项 KPI，命中率 {kpi_eval['hit_rate']}%"})

        # 3 成熟度评估
        mat = self.mm.assess(industry=industry)
        log.append({"step": 3, "name": "成熟度评估", "status": "done",
                    "note": f"{mat['overall_score']}/5.0，{mat['level_name']}"})

        # 4 风险评分
        sc = self.risk.overall_scorecard()
        log.append({"step": 4, "name": "风险评分", "status": "done",
                    "note": f"综合风险 {sc['overall_risk_score']}，严重 {sc['level_distribution'].get('critical', 0)}"})

        # 5 合规度量
        comp_cov = self.comp.coverage()
        comp_rem = self.comp.remediation()
        log.append({"step": 5, "name": "合规度量", "status": "done",
                    "note": f"框架通过率 {comp_cov['framework_avg_pass_rate']}%，整改率 {comp_rem['remediation_rate_pct']}%"})

        # 6 高管报告
        report = None
        if include_report:
            report = self.dash.generate_report("weekly")
        log.append({"step": 6, "name": "高管报告", "status": "done" if include_report else "skipped",
                    "note": "生成 CISO 仪表盘与周报" if include_report else ""})

        # 7 持续改进
        improvements = [r["actions"] for r in mat["roadmap"]]
        log.append({"step": 7, "name": "持续改进", "status": "done",
                    "note": f"生成 {len(mat['roadmap'])} 阶段改进路线图"})

        return {
            "workflow_id": f"MWF-{int(time.time())}",
            "started_at": started,
            "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "industry": industry,
            "steps": log,
            "kpi_eval": {"total": kpi_eval["total_metrics"],
                         "hit_rate": kpi_eval["hit_rate"]},
            "maturity": {"score": mat["overall_score"], "level": mat["maturity_level"],
                         "level_name": mat["level_name"]},
            "risk": {"score": sc["overall_risk_score"],
                     "distribution": sc["level_distribution"]},
            "compliance": {"pass_rate": comp_cov["framework_avg_pass_rate"],
                           "remediation_rate": comp_rem["remediation_rate_pct"]},
            "executive_report": report,
            "roadmap_phases": mat["roadmap"],
        }

    def list_steps(self) -> List[Dict[str, Any]]:
        return METRICS_WORKFLOW_STEPS


_singleton: Optional[MetricsWorkflow] = None


def get_metrics_workflow() -> MetricsWorkflow:
    global _singleton
    if _singleton is None:
        _singleton = MetricsWorkflow()
    return _singleton
