# -*- coding: utf-8 -*-
"""
risk_rating_phase.py — 方向2 供应链安全 Pro：阶段5 风险评级。

功能:
    - 根据漏洞严重程度 + 许可证风险 + 依赖深度打分（0-100）
    - critical / high / medium / low 四级
    - Top 风险组件排序
    - 风险趋势分析
    - 组件风险矩阵
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


SEV_SCORE = {"critical": 40, "high": 25, "medium": 12, "low": 4,
             "info": 1}
LIC_RISK_SCORE = {"critical": 30, "high": 18, "medium": 8, "low": 2,
                  "permissive": 0}


def _band(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


@dataclass
class ComponentRisk:
    name: str = ""
    version: str = ""
    vuln_score: float = 0.0
    license_score: float = 0.0
    depth_score: float = 0.0
    total: float = 0.0
    band: str = "low"
    reasons: List[str] = field(default_factory=list)
    vuln_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "version": self.version,
            "vuln_score": round(self.vuln_score, 1),
            "license_score": round(self.license_score, 1),
            "depth_score": round(self.depth_score, 1),
            "total": round(self.total, 1),
            "band": self.band,
            "reasons": self.reasons,
            "vuln_count": self.vuln_count,
        }


@dataclass
class RiskReport:
    overall_score: float = 0.0
    overall_band: str = "low"
    by_severity: Dict[str, int] = field(default_factory=dict)
    top_components: List[ComponentRisk] = field(default_factory=list)
    matrix: List[Dict[str, Any]] = field(default_factory=list)
    trend: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 1),
            "overall_band": self.overall_band,
            "by_severity": self.by_severity,
            "top_components": [c.to_dict() for c in self.top_components],
            "matrix": self.matrix,
            "trend": self.trend,
            "top_count": len(self.top_components),
        }


class RiskRatingPhase:
    """阶段5：风险评级。"""

    # ------------------------------------------------------------------ #
    def score_component(self, name: str, version: str,
                        vulns: List[Dict[str, Any]],
                        license_risk: str = "low",
                        depth: int = 0) -> ComponentRisk:
        cr = ComponentRisk(name=name, version=version)
        cr.vuln_count = len(vulns)
        for v in vulns:
            cr.vuln_score += SEV_SCORE.get(v.get("severity", "low"), 4)
            cr.reasons.append(
                f"{v.get('cve_id', 'CVE')} ({v.get('severity','?')}) "
                f"{v.get('title', '')[:60]}")
        cr.license_score = LIC_RISK_SCORE.get(license_risk, 0)
        if license_risk in ("high", "critical"):
            cr.reasons.append(f"许可证风险: {license_risk}")
        cr.depth_score = min(10, depth * 2)
        cr.total = min(100.0, cr.vuln_score + cr.license_score
                      + cr.depth_score)
        cr.band = _band(cr.total)
        return cr

    # ------------------------------------------------------------------ #
    def rate(self,
             sbom_components: List[Dict[str, Any]],
             vulns: List[Dict[str, Any]],
             license_report: Optional[Dict[str, Any]] = None,
             dep_report: Optional[Dict[str, Any]] = None
             ) -> RiskReport:
        rep = RiskReport()
        license_report = license_report or {}
        dep_report = dep_report or {}

        # 按组件聚合漏洞
        vuln_by_comp: Dict[str, List[Dict[str, Any]]] = {}
        for v in vulns:
            key = (v.get("component", "") or "").lower()
            vuln_by_comp.setdefault(key, []).append(v)
            rep.by_severity[v.get("severity", "low")] = \
                rep.by_severity.get(v.get("severity", "low"), 0) + 1

        # 许可证风险映射
        lic_risk_by_comp: Dict[str, str] = {}
        for issue in license_report.get("issues", []):
            lic_risk_by_comp[issue.get("component", "").lower()] = \
                issue.get("risk", "low")

        # 依赖深度
        depth_dist = dep_report.get("depth_distribution", {}) or {}

        component_scores: List[ComponentRisk] = []
        for c in sbom_components:
            name = c.get("name", "")
            key = name.lower()
            cv = vuln_by_comp.get(key, [])
            lr = lic_risk_by_comp.get(key, "low")
            cr = self.score_component(
                name, c.get("version", ""), cv,
                license_risk=lr,
                depth=0 if c.get("direct", True) else 2)
            component_scores.append(cr)

        component_scores.sort(key=lambda x: x.total, reverse=True)
        rep.top_components = component_scores[:20]

        # 整体分：取 Top5 平均 + 漏洞总数加成
        if component_scores:
            top5 = component_scores[:5]
            rep.overall_score = sum(c.total for c in top5) / len(top5)
        rep.overall_band = _band(rep.overall_score)

        # 风险矩阵: 横轴=组件数量分桶, 纵轴=漏洞严重度
        matrix_rows = []
        for sev in ("critical", "high", "medium", "low"):
            cnt = rep.by_severity.get(sev, 0)
            matrix_rows.append({
                "severity": sev, "count": cnt,
                "score_per": SEV_SCORE.get(sev, 0),
                "weighted": cnt * SEV_SCORE.get(sev, 0),
            })
        rep.matrix = matrix_rows

        # 趋势（启发式：按严重度分布推断环比）
        total_v = sum(rep.by_severity.values()) or 1
        crit_ratio = rep.by_severity.get("critical", 0) / total_v
        if crit_ratio > 0.2:
            trend_state = "恶化"
        elif crit_ratio > 0.05:
            trend_state = "稳定"
        else:
            trend_state = "改善"
        rep.trend = {
            "state": trend_state,
            "critical_ratio": round(crit_ratio, 3),
            "note": ("基于当前 SBOM 快照，无历史基线；"
                     "持续扫描后可给出真实环比。"),
            "depth_distribution": depth_dist,
        }
        return rep

    # ------------------------------------------------------------------ #
    def tools_status(self) -> Dict[str, Any]:
        return {
            "score_formula": (
                "score = ΣSEV_SCORE + LIC_RISK_SCORE + min(10, depth*2)"),
            "bands": {"critical": "≥75", "high": "50-74",
                      "medium": "25-49", "low": "<25"},
        }


_default_rr: Optional[RiskRatingPhase] = None


def get_risk_phase() -> RiskRatingPhase:
    global _default_rr
    if _default_rr is None:
        _default_rr = RiskRatingPhase()
    return _default_rr
