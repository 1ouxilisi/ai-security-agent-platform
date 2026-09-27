#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
executive_dashboard.py — 高管报告与仪表盘。

覆盖：
    - CISO 仪表盘核心指标
    - 高管摘要 / 安全态势一页纸
    - 安全投资回报率(ROI)、风险地图数据
    - 自动生成周报/月报、多格式导出（Markdown/JSON）
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional


class ExecutiveDashboard:
    """面向 CISO / 管理层的高管仪表盘与报告。"""

    def __init__(self) -> None:
        # 延迟导入，避免循环依赖
        from security_metrics.maturity_model import SecurityMaturityModel
        from security_metrics.risk_scoring import RiskScoringEngine
        from security_metrics.operational_efficiency import OperationalEfficiencyMetrics
        from security_metrics.compliance_audit import ComplianceAuditMetrics
        self.mm = SecurityMaturityModel()
        self.risk = RiskScoringEngine()
        self.ops = OperationalEfficiencyMetrics()
        self.comp = ComplianceAuditMetrics()

    # ------------------------------------------------------------------ #
    # CISO 仪表盘
    # ------------------------------------------------------------------ #
    def ciso_dashboard(self) -> Dict[str, Any]:
        sc = self.risk.overall_scorecard()
        ops = self.ops.summary()
        comp = self.comp.coverage()
        return {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "top_kpi": {
                "综合风险评分": sc["overall_risk_score"],
                "加权风险评分": sc["weighted_risk_score"],
                "MTTD(小时)": ops["MTTD_latest_h"],
                "MTTR(小时)": ops["MTTR_latest_h"],
                "SLA达成率(%)": ops["sla_achievement_pct"],
                "自动化率(%)": ops["automation_rate_pct"],
                "误报率(%)": ops["false_positive_rate_pct"],
                "合规平均通过率(%)": comp["framework_avg_pass_rate"],
                "整改完成率(%)": self.comp.remediation()["remediation_rate_pct"],
                "运营健康分": ops["health_score"],
            },
            "level_distribution": sc["level_distribution"],
            "alerts": self._executive_alerts(sc, ops, comp),
        }

    def _executive_alerts(self, sc: Dict[str, Any], ops: Dict[str, Any],
                          comp: Dict[str, Any]) -> list:
        alerts = []
        if sc["level_distribution"].get("critical", 0) > 0:
            alerts.append({"level": "critical",
                           "text": f"存在 {sc['level_distribution']['critical']} 个严重风险，需管理层关注"})
        if ops["false_positive_rate_pct"] > 25:
            alerts.append({"level": "high",
                           "text": f"告警误报率 {ops['false_positive_rate_pct']}%，超过 20% 阈值"})
        if comp["framework_avg_pass_rate"] < 90:
            alerts.append({"level": "medium",
                           "text": f"合规平均通过率 {comp['framework_avg_pass_rate']}%，低于 90% 目标"})
        if ops["overloaded_analysts"] > 0:
            alerts.append({"level": "medium",
                           "text": f"{ops['overloaded_analysts']} 名分析师过载，建议扩编"})
        if not alerts:
            alerts.append({"level": "low", "text": "各项指标处于健康区间"})
        return alerts

    # ------------------------------------------------------------------ #
    # ROI
    # ------------------------------------------------------------------ #
    def security_roi(self) -> Dict[str, Any]:
        invest = 1250.0  # 万元/年
        avoided_loss = 4200.0  # 模拟规避损失
        incident_loss = 860.0
        roi = round((avoided_loss - invest) / invest * 100, 1)
        return {
            "annual_investment_wan": invest,
            "avoided_loss_wan": avoided_loss,
            "residual_loss_wan": incident_loss,
            "ROI_pct": roi,
            "payback_months": round(invest / (avoided_loss / 12), 1),
            "assumptions": ["规避损失基于历史事件频率与平均损失模型估算",
                            "投资含人力/工具/服务/认证"],
        }

    # ------------------------------------------------------------------ #
    # 一页纸 / 摘要
    # ------------------------------------------------------------------ #
    def one_pager(self) -> Dict[str, Any]:
        dash = self.ciso_dashboard()
        roi = self.security_roi()
        return {
            "title": "企业安全态势一页纸",
            "date": time.strftime("%Y-%m-%d"),
            "executive_summary": (
                f"当前综合风险 {dash['top_kpi']['综合风险评分']}/100，"
                f"严重风险 {dash['level_distribution'].get('critical', 0)} 项；"
                f"MTTR {dash['top_kpi']['MTTR(小时)']}h，SLA 达成 "
                f"{dash['top_kpi']['SLA达成率(%)']}%；"
                f"安全 ROI {roi['ROI_pct']}%。"),
            "kpi_cards": dash["top_kpi"],
            "top_risks": [r for r in self.risk.list_register()["items"]
                          if r["level"] in ("critical", "high")][:5],
            "alerts": dash["alerts"],
            "next_steps": ["6 个月内将自动化率提升至 70%+",
                           "关闭全部严重风险项",
                           "推动合规通过率至 95%"],
        }

    # ------------------------------------------------------------------ #
    # 风险地图
    # ------------------------------------------------------------------ #
    def risk_map(self) -> Dict[str, Any]:
        return self.risk.heatmap()

    # ------------------------------------------------------------------ #
    # 周报/月报
    # ------------------------------------------------------------------ #
    def generate_report(self, period: str = "weekly") -> Dict[str, Any]:
        """period: weekly / monthly"""
        dash = self.ciso_dashboard()
        roi = self.security_roi()
        trend = self.risk.risk_trend(12)
        title = "安全周报" if period == "weekly" else "安全月报"
        md = [
            f"# {title}（{time.strftime('%Y-%m-%d')}）",
            "",
            "## 一、关键指标",
        ]
        for k, v in dash["top_kpi"].items():
            md.append(f"- {k}：{v}")
        md += [
            "", "## 二、风险趋势",
            f"- 近一期综合风险：{trend['scores'][-1]}（{trend['direction']}，"
            f"变化 {trend['change']}）",
            "", "## 三、安全投资回报",
            f"- ROI：{roi['ROI_pct']}%，年投入 {roi['annual_investment_wan']} 万元",
            "", "## 四、管理层行动项",
        ]
        for a in dash["alerts"]:
            md.append(f"- [{a['level']}] {a['text']}")
        return {
            "period": period, "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "title": title,
            "markdown": "\n".join(md),
            "json_payload": {
                "kpi": dash["top_kpi"], "roi": roi,
                "risk_trend_last": trend["scores"][-1],
                "alerts": dash["alerts"],
            },
            "export_formats": ["markdown", "json", "pdf(占位)"],
        }
