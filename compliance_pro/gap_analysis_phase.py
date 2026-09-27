# -*- coding: utf-8 -*-
"""
gap_analysis_phase.py — 阶段4：差距分析。

- 自动对比合规要求与实际状态
- 按严重程度分级（critical/high/medium/low）
- 差距项详情（要求/实际/差距/影响/风险）
- 差距项关联（资产/基线规则/合规项）
- 差距趋势 / 报告生成
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Gap:
    gap_id: str = ""
    title: str = ""
    severity: str = "medium"
    framework: str = ""
    domain: str = ""
    requirement: str = ""
    actual: str = ""
    gap_desc: str = ""
    impact: str = ""
    risk_score: int = 50
    related_assets: List[str] = field(default_factory=list)
    related_rules: List[str] = field(default_factory=list)
    related_items: List[str] = field(default_factory=list)
    status: str = "open"   # open/in_remediation/verified/accepted
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GapAnalysisPhase:
    """阶段4：差距分析。"""

    def __init__(self) -> None:
        self._gaps: Dict[str, Gap] = {}
        self._lock = threading.Lock()
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    def analyze(self) -> Dict[str, Any]:
        """自动从合规评估 + 基线检查生成差距项。"""
        from .compliance_assessment_phase import (
            get_compliance_assessment_phase, FRAMEWORKS)
        from .baseline_check_phase import get_baseline_check_phase
        ca = get_compliance_assessment_phase()
        base = get_baseline_check_phase()

        # 基于未通过的合规项生成差距
        self._gaps.clear()
        for it in ca.list_items():
            if it["status"] in ("fail", "partial"):
                gid = "gap_" + uuid.uuid4().hex[:8]
                g = Gap(
                    gap_id=gid,
                    title=f"[{it['framework'].upper()}] {it['title']}",
                    severity=it["severity"],
                    framework=it["framework"], domain=it["domain"],
                    requirement=it["requirement"],
                    actual="当前未完全满足要求" +
                           ("（部分符合）" if it["status"] == "partial"
                            else "（不符合）"),
                    gap_desc=f"合规项 {it['item_id']} 状态={it['status']}",
                    impact=self._impact_text(it["severity"]),
                    risk_score={"critical": 90, "high": 70,
                                "medium": 45, "low": 20}.get(
                                    it["severity"], 50),
                    related_items=[it["item_id"]],
                    created_at=datetime.now().isoformat(timespec="seconds"),
                )
                self._gaps[gid] = g
        # 基于基线失败结果补充差距
        for r in base.list_results(status="fail"):
            gid = "gap_" + uuid.uuid4().hex[:8]
            g = Gap(
                gap_id=gid,
                title=f"[基线] {r['rule_title']}",
                severity=r["severity"],
                framework="baseline",
                domain=r["category"],
                requirement=r["detail"],
                actual="基线检查未通过",
                gap_desc=f"规则 {r['rule_id']} 未通过",
                impact=self._impact_text(r["severity"]),
                risk_score={"critical": 90, "high": 70,
                            "medium": 45, "low": 20}.get(
                                r["severity"], 50),
                related_rules=[r["rule_id"]],
                related_assets=[r["asset_id"]],
                created_at=datetime.now().isoformat(timespec="seconds"),
            )
            self._gaps[gid] = g
        summary = self.stats()
        self._history.append({"time": datetime.now().isoformat(
            timespec="seconds"), **summary})
        return {"gaps": [g.to_dict() for g in self._gaps.values()],
                "summary": summary}

    def _impact_text(self, severity: str) -> str:
        return {
            "critical": "可能导致核心数据泄露或业务中断，监管处罚风险高",
            "high": "存在显著攻击面，建议30天内整改",
            "medium": "存在中等风险，建议90天内整改",
            "low": "低风险改进项，可纳入例行运维",
        }.get(severity, "待评估")

    # ------------------------------------------------------------------ #
    def list_gaps(self, severity: Optional[str] = None,
                  framework: Optional[str] = None,
                  status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._gaps.values())
        out = [g.to_dict() for g in items]
        if severity:
            out = [g for g in out if g["severity"] == severity]
        if framework:
            out = [g for g in out if g["framework"] == framework]
        if status:
            out = [g for g in out if g["status"] == status]
        out.sort(key=lambda x: -x["risk_score"])
        return out

    def get_gap(self, gap_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            g = self._gaps.get(gap_id)
            return g.to_dict() if g else None

    def update_gap(self, gap_id: str, **kw: Any) -> Optional[Dict[str, Any]]:
        with self._lock:
            g = self._gaps.get(gap_id)
            if g is None:
                return None
            for k, v in kw.items():
                if hasattr(g, k) and v is not None:
                    setattr(g, k, v)
            return g.to_dict()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._gaps.values())
        by_sev: Dict[str, int] = {}
        by_fw: Dict[str, int] = {}
        for g in items:
            by_sev[g.severity] = by_sev.get(g.severity, 0) + 1
            by_fw[g.framework] = by_fw.get(g.framework, 0) + 1
        return {"total": len(items), "by_severity": by_sev,
                "by_framework": by_fw,
                "critical": by_sev.get("critical", 0),
                "high": by_sev.get("high", 0)}

    def trend(self) -> List[Dict[str, Any]]:
        return self._history[-30:]

    def gap_report(self) -> Dict[str, Any]:
        s = self.stats()
        return {"summary": s,
                "top": self.list_gaps()[:20],
                "generated_at": datetime.now().isoformat(
                    timespec="seconds")}


_default: Optional[GapAnalysisPhase] = None


def get_gap_analysis_phase() -> GapAnalysisPhase:
    global _default
    if _default is None:
        _default = GapAnalysisPhase()
    return _default
