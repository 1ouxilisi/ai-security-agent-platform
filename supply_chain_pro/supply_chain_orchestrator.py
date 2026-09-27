# -*- coding: utf-8 -*-
"""
supply_chain_orchestrator.py — 方向2 供应链安全 Pro：六阶段编排器。

阶段:
    1. sbom              软件物料清单生成
    2. component_analysis 组件漏洞分析
    3. license           许可证合规
    4. dependency        依赖分析
    5. risk              风险评级
    6. remediation       整改建议
    + AI 分析 + 报告生成
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .sbom_phase import SBOMPhase, get_sbom_phase
from .component_analysis_phase import (
    ComponentAnalysisPhase, get_component_analysis_phase)
from .license_compliance_phase import (
    LicenseCompliancePhase, get_license_phase)
from .dependency_analysis_phase import (
    DependencyAnalysisPhase, get_dependency_phase)
from .risk_rating_phase import RiskRatingPhase, get_risk_phase
from .remediation_phase import RemediationPhase, get_remediation_phase
from .ai_analysis import SupplyChainAIAnalysis, get_ai_analysis
from .report_generator import ReportGenerator, ReportData, \
    get_report_generator
from .realtime_push import push_event_sync


REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "supply_chain_pro")


STAGES = [
    ("sbom",     "SBOM 生成",      15),
    ("analysis", "组件漏洞分析",    35),
    ("license",  "许可证合规",     50),
    ("dependency", "依赖分析",      65),
    ("risk",     "风险评级",       80),
    ("remediation", "整改建议",     92),
    ("report",   "报告生成",      100),
]


@dataclass
class SCTask:
    task_id: str = ""
    target: str = ""
    status: str = "pending"
    stage: str = "init"
    progress: int = 0
    created_at: str = ""
    finished_at: Optional[str] = None
    error: Optional[str] = None
    # 六阶段产物
    sbom: Dict[str, Any] = field(default_factory=dict)
    component_analysis: Dict[str, Any] = field(default_factory=dict)
    license_report: Dict[str, Any] = field(default_factory=dict)
    dep_report: Dict[str, Any] = field(default_factory=dict)
    risk_report: Dict[str, Any] = field(default_factory=dict)
    remediation: Dict[str, Any] = field(default_factory=dict)
    ai: Dict[str, Any] = field(default_factory=dict)
    report_path: str = ""
    report_markdown: str = ""
    report_html: str = ""
    log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "target": self.target,
            "status": self.status, "stage": self.stage,
            "progress": self.progress,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "sbom": self.sbom,
            "component_analysis": self.component_analysis,
            "license_report": self.license_report,
            "dep_report": self.dep_report,
            "risk_report": self.risk_report,
            "remediation": self.remediation,
            "ai": self.ai,
            "report_path": self.report_path,
            "log": self.log[-100:],
        }


class SupplyChainOrchestrator:
    """六阶段编排器。"""

    def __init__(self,
                 sbom: Optional[SBOMPhase] = None,
                 analysis: Optional[ComponentAnalysisPhase] = None,
                 license_: Optional[LicenseCompliancePhase] = None,
                 dep: Optional[DependencyAnalysisPhase] = None,
                 risk: Optional[RiskRatingPhase] = None,
                 remediation: Optional[RemediationPhase] = None,
                 ai: Optional[SupplyChainAIAnalysis] = None,
                 report: Optional[ReportGenerator] = None) -> None:
        self.sbom = sbom or get_sbom_phase()
        self.analysis = analysis or get_component_analysis_phase()
        self.license_ = license_ or get_license_phase()
        self.dep = dep or get_dependency_phase()
        self.risk = risk or get_risk_phase()
        self.remediation = remediation or get_remediation_phase()
        self.ai = ai or get_ai_analysis()
        self.report = report or get_report_generator()
        self._tasks: Dict[str, SCTask] = {}

    # ------------------------------------------------------------------ #
    def create_task(self, target: str) -> SCTask:
        tid = uuid.uuid4().hex[:16]
        t = SCTask(
            task_id=tid, target=target,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._tasks[tid] = t
        return t

    def get_task(self, task_id: str) -> Optional[SCTask]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in sorted(
            self._tasks.values(), key=lambda x: x.created_at,
            reverse=True)]

    # ------------------------------------------------------------------ #
    def _set_stage(self, t: SCTask, key: str, label: str) -> None:
        for k, name, prog in STAGES:
            if k == key:
                t.stage = key
                t.progress = prog
                msg = f"[*] 进入阶段: {label}"
                t.log.append(msg)
                push_event_sync(t.task_id, "stage",
                                {"stage": key, "label": label,
                                 "progress": prog}, "step")
                return

    def _log(self, t: SCTask, msg: str,
             level: str = "info") -> None:
        t.log.append(msg)
        push_event_sync(t.task_id, "log", {"msg": msg}, level)

    # ------------------------------------------------------------------ #
    def run_full(self, target: str,
                 task_id: Optional[str] = None,
                 out_format: str = "cyclonedx",
                 use_osv: bool = True,
                 use_snyk: bool = False) -> SCTask:
        t = self._tasks.get(task_id) if task_id else None
        if t is None:
            t = self.create_task(target)
        t.status = "running"
        try:
            # 阶段1 SBOM
            self._set_stage(t, "sbom", "SBOM 生成")
            self._log(t, f"[*] 开始 SBOM: target={target}")
            r1 = self.sbom.generate(target, out_format=out_format)
            t.sbom = r1.to_dict()
            self._log(t, f"[+] SBOM 完成: "
                         f"{t.sbom.get('component_count',0)} 组件, "
                         f"fallback={t.sbom.get('fallback',False)}",
                      "ok")
            if t.sbom.get("notice"):
                self._log(t, f"[i] {t.sbom['notice']}", "warn")

            # 阶段2 组件分析
            self._set_stage(t, "analysis", "组件漏洞分析")
            comps = t.sbom.get("components", [])
            r2 = self.analysis.analyze(comps, use_osv=use_osv,
                                      use_snyk=use_snyk)
            t.component_analysis = r2.to_dict()
            self._log(t, f"[+] 组件分析: "
                         f"{r2.vuln_count} 漏洞, "
                         f"API={r2.api_used}", "ok")
            if r2.api_notice:
                self._log(t, f"[i] {r2.api_notice}", "info")

            # 阶段3 许可证
            self._set_stage(t, "license", "许可证合规")
            r3 = self.license_.check(comps)
            t.license_report = r3.to_dict()
            self._log(t, f"[+] 许可证: "
                         f"{len(r3.issues)} 问题, "
                         f"冲突 {len(r3.conflicts)}", "ok")

            # 阶段4 依赖分析
            self._set_stage(t, "dependency", "依赖分析")
            r4 = self.dep.analyze(comps,
                                  vulns=t.component_analysis.get(
                                      "vulns", []))
            t.dep_report = r4.to_dict()
            self._log(t, f"[+] 依赖分析: "
                         f"{r4.total} 总, "
                         f"冲突 {len(r4.conflicts)}, "
                         f"过期 {len(r4.outdated)}", "ok")

            # 阶段5 风险评级
            self._set_stage(t, "risk", "风险评级")
            r5 = self.risk.rate(comps,
                                t.component_analysis.get("vulns", []),
                                license_report=t.license_report,
                                dep_report=t.dep_report)
            t.risk_report = r5.to_dict()
            self._log(t, f"[+] 风险评级: "
                         f"整体 {r5.overall_score:.0f}/100 "
                         f"({r5.overall_band})", "ok")

            # 阶段6 整改建议
            self._set_stage(t, "remediation", "整改建议")
            r6 = self.remediation.generate(
                t.component_analysis.get("vulns", []),
                license_issues=t.license_report.get("issues", []),
                dep_report=t.dep_report)
            t.remediation = r6.to_dict()
            self._log(t, f"[+] 整改建议: "
                         f"{r6.summary.get('total',0)} 条 "
                         f"(P0={r6.summary.get('P0',0)})", "ok")

            # AI 分析
            self._log(t, "[*] AI 分析中…", "think")
            t.ai = self.ai.analyze(
                t.sbom, t.component_analysis,
                t.license_report, t.dep_report,
                t.risk_report, t.remediation).to_dict()
            for line in t.ai.get("thinking", []):
                self._log(t, line, "think")
            self._log(t, f"[+] AI 分析完成: "
                         f"攻击路径 "
                         f"{len(t.ai.get('attack_paths',[]))} 条", "ok")

            # 报告
            self._set_stage(t, "report", "报告生成")
            rd = ReportData(
                task_id=t.task_id, target=target,
                started_at=t.created_at,
                finished_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                sbom=t.sbom,
                component_analysis=t.component_analysis,
                license_report=t.license_report,
                dep_report=t.dep_report,
                risk_report=t.risk_report,
                remediation=t.remediation,
                ai=t.ai,
            )
            os.makedirs(REPORTS_DIR, exist_ok=True)
            t.report_path = self.report.save(rd, REPORTS_DIR, "html")
            t.report_markdown = self.report.generate_markdown(rd)
            t.report_html = self.report.generate_html(rd)
            self._log(t, f"[+] 报告已生成: {t.report_path}", "ok")

            t.status = "done"
            t.stage = "done"
            t.progress = 100
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
            push_event_sync(t.task_id, "done",
                            {"task_id": t.task_id}, "ok")
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = f"{type(e).__name__}: {e}"
            t.log.append(f"[!] 失败: {t.error}")
            push_event_sync(t.task_id, "error",
                            {"error": t.error}, "error")
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return t

    # ------------------------------------------------------------------ #
    # 单步接口
    # ------------------------------------------------------------------ #
    def step_sbom(self, target: str,
                  out_format: str = "cyclonedx") -> Dict[str, Any]:
        return self.sbom.generate(target, out_format=out_format).to_dict()

    def step_analysis(self, components: List[Dict[str, Any]],
                      use_osv: bool = True) -> Dict[str, Any]:
        return self.analysis.analyze(components, use_osv=use_osv).to_dict()

    def step_license(self, components: List[Dict[str, Any]]
                     ) -> Dict[str, Any]:
        return self.license_.check(components).to_dict()

    def step_dependency(self, components: List[Dict[str, Any]]
                        ) -> Dict[str, Any]:
        return self.dep.analyze(components).to_dict()

    def step_risk(self, sbom: Dict[str, Any],
                  analysis: Dict[str, Any],
                  license_: Dict[str, Any],
                  dep: Dict[str, Any]) -> Dict[str, Any]:
        return self.risk.rate(
            sbom.get("components", []),
            analysis.get("vulns", []),
            license_report=license_,
            dep_report=dep).to_dict()

    def step_remediation(self, analysis: Dict[str, Any],
                         license_: Dict[str, Any],
                         dep: Dict[str, Any]) -> Dict[str, Any]:
        return self.remediation.generate(
            analysis.get("vulns", []),
            license_issues=license_.get("issues", []),
            dep_report=dep).to_dict()


_default_orch: Optional[SupplyChainOrchestrator] = None


def get_orchestrator() -> SupplyChainOrchestrator:
    global _default_orch
    if _default_orch is None:
        _default_orch = SupplyChainOrchestrator()
    return _default_orch
