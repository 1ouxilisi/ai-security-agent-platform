# -*- coding: utf-8 -*-
"""
devsecops_orchestrator.py — DevSecOps 八阶段编排器。

阶段:
    1. cicd_integration  CI/CD 集成
    2. sast             SAST 静态代码分析
    3. sca              SCA 依赖漏洞扫描
    4. secrets          Secrets 扫描
    5. iac_security      IaC 安全
    6. container        容器安全
    7. security_gate     安全门禁
    8. risk_rating       风险评级
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .cicd_integration_phase import get_cicd_phase
from .sast_phase import get_sast_phase
from .sca_phase import get_sca_phase
from .secrets_phase import get_secrets_phase
from .iac_security_phase import get_iac_phase
from .container_security_phase import get_container_phase
from .security_gate_phase import get_gate_phase
from .risk_rating_phase import get_risk_phase
from .ai_analysis import get_ai_analysis
from .realtime_push import get_realtime_push
from .report_generator import (
    ReportGenerator, DevSecOpsReportData, get_report_generator,
)


REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "devsecops_pro")


STAGES = [
    ("cicd",     "CI/CD 集成",  10),
    ("sast",     "SAST 扫描",   25),
    ("sca",      "SCA 扫描",    40),
    ("secrets",  "Secrets 扫描", 55),
    ("iac",      "IaC 安全",    70),
    ("container", "容器安全",    82),
    ("gate",     "安全门禁",    92),
    ("risk",     "风险评级",    100),
]


@dataclass
class DevSecOpsTask:
    task_id: str = ""
    target: str = ""
    status: str = "pending"
    stage: str = "init"
    progress: int = 0
    created_at: str = ""
    finished_at: Optional[str] = None
    error: Optional[str] = None
    # 八阶段产物
    cicd: Dict[str, Any] = field(default_factory=dict)
    sast: Dict[str, Any] = field(default_factory=dict)
    sca: Dict[str, Any] = field(default_factory=dict)
    secrets: Dict[str, Any] = field(default_factory=dict)
    iac: Dict[str, Any] = field(default_factory=dict)
    container: Dict[str, Any] = field(default_factory=dict)
    gate: Dict[str, Any] = field(default_factory=dict)
    risk: Dict[str, Any] = field(default_factory=dict)
    ai: Dict[str, Any] = field(default_factory=dict)
    report_path: str = ""
    log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "target": self.target,
            "status": self.status, "stage": self.stage,
            "progress": self.progress,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "cicd": self.cicd, "sast": self.sast, "sca": self.sca,
            "secrets": self.secrets, "iac": self.iac,
            "container": self.container, "gate": self.gate,
            "risk": self.risk, "ai": self.ai,
            "report_path": self.report_path,
            "log": self.log[-100:],
        }


class DevSecOpsOrchestrator:
    """八阶段编排器。"""

    def __init__(self) -> None:
        self.cicd = get_cicd_phase()
        self.sast = get_sast_phase()
        self.sca = get_sca_phase()
        self.secrets = get_secrets_phase()
        self.iac = get_iac_phase()
        self.container = get_container_phase()
        self.gate = get_gate_phase()
        self.risk = get_risk_phase()
        self.ai = get_ai_analysis()
        self.rt = get_realtime_push()
        self.report = get_report_generator()
        self._tasks: Dict[str, DevSecOpsTask] = {}

    # ------------------------------------------------------------------ #
    def create_task(self, target: str) -> DevSecOpsTask:
        tid = uuid.uuid4().hex[:16]
        t = DevSecOpsTask(
            task_id=tid, target=target,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._tasks[tid] = t
        return t

    def get_task(self, task_id: str) -> Optional[DevSecOpsTask]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in sorted(
            self._tasks.values(), key=lambda x: x.created_at,
            reverse=True)]

    # ------------------------------------------------------------------ #
    def _stage(self, t: DevSecOpsTask, key: str, label: str,
               overall: int) -> None:
        t.stage = key
        t.progress = overall
        self.rt.emit_progress(t.task_id, key, label, overall, 0)
        self.rt.emit_log(t.task_id, "INFO", f"[*] 进入阶段: {label}")

    # ------------------------------------------------------------------ #
    def run_full(self, target: str,
                 task_id: Optional[str] = None) -> DevSecOpsTask:
        t = self._tasks.get(task_id) if task_id else None
        if t is None:
            t = self.create_task(target)
        t.status = "running"
        try:
            # 阶段1 CI/CD 集成（生成配置，不真实触发）
            self._stage(t, "cicd", "CI/CD 集成", 10)
            cfg = self.cicd.generate_config("github", repo=target)
            t.cicd = {
                "config": cfg.to_dict(),
                "tool_status": self.cicd.tool_status(),
            }
            self.rt.emit_log(t.task_id, "OK",
                             f"CI/CD 配置已生成: {cfg.path}")

            # 阶段2 SAST
            self._stage(t, "sast", "SAST 扫描", 25)
            try:
                t.sast = self.sast.scan(target)
            except Exception as e:  # noqa: BLE001
                t.sast = {"error": str(e)}
            self.rt.emit_log(t.task_id, "OK",
                             f"SAST 完成: {t.sast.get('count', 0)} 个发现")
            self.rt.emit_result(t.task_id, "sast", t.sast)

            # 阶段3 SCA
            self._stage(t, "sca", "SCA 扫描", 40)
            try:
                t.sca = self.sca.scan(target)
            except Exception as e:  # noqa: BLE001
                t.sca = {"error": str(e)}
            self.rt.emit_log(t.task_id, "OK",
                             f"SCA 完成: {t.sca.get('count', 0)} 个 CVE")

            # 阶段4 Secrets
            self._stage(t, "secrets", "Secrets 扫描", 55)
            try:
                t.secrets = self.secrets.scan(target)
            except Exception as e:  # noqa: BLE001
                t.secrets = {"error": str(e)}
            self.rt.emit_log(t.task_id, "OK",
                             f"Secrets 完成: {t.secrets.get('count', 0)} 个泄露")

            # 阶段5 IaC
            self._stage(t, "iac", "IaC 安全", 70)
            try:
                t.iac = self.iac.scan(target)
            except Exception as e:  # noqa: BLE001
                t.iac = {"error": str(e)}
            self.rt.emit_log(t.task_id, "OK",
                             f"IaC 完成: {t.iac.get('count', 0)} 个配置错误")

            # 阶段6 容器
            self._stage(t, "container", "容器安全", 82)
            try:
                t.container = self.container.scan_filesystem(target)
            except Exception as e:  # noqa: BLE001
                t.container = {"error": str(e)}
            self.rt.emit_log(t.task_id, "OK",
                             f"容器扫描完成: {t.container.get('count', 0)} 个发现")

            # 阶段7 安全门禁
            self._stage(t, "gate", "安全门禁", 92)
            gr = self.gate.evaluate(t.sast, t.sca, t.secrets,
                                    t.iac, t.container)
            t.gate = gr.to_dict()
            self.rt.emit_log(t.task_id,
                             "OK" if gr.decision == "pass" else "WARN",
                             f"门禁结论: {gr.decision} (score {gr.score})")

            # 阶段8 风险评级
            self._stage(t, "risk", "风险评级", 100)
            rr = self.risk.rate(t.sast, t.sca, t.secrets,
                                t.iac, t.container)
            t.risk = rr.to_dict()
            self.rt.emit_log(t.task_id, "OK",
                             f"风险评分: {rr.score}/100 ({rr.level})")

            # AI 分析
            self.rt.emit_thought(t.task_id, "AI 正在聚合八阶段结果…")
            ai_res = self.ai.analyze(t.sast, t.sca, t.secrets,
                                     t.iac, t.container,
                                     t.gate, t.risk)
            t.ai = ai_res.to_dict()
            self.rt.emit_thought(t.task_id,
                                 f"AI 完成：{len(ai_res.priority_list)} 项优先级")

            # 报告
            rd = DevSecOpsReportData(
                task_id=t.task_id, target=target,
                started_at=t.created_at,
                finished_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                cicd=t.cicd, sast=t.sast, sca=t.sca,
                secrets=t.secrets, iac=t.iac,
                container=t.container, gate=t.gate,
                risk=t.risk, ai=t.ai,
            )
            os.makedirs(REPORTS_DIR, exist_ok=True)
            t.report_path = self.report.save(rd, REPORTS_DIR, "html")
            self.rt.emit_log(t.task_id, "OK",
                             f"报告已生成: {t.report_path}")

            t.status = "done"
            t.stage = "done"
            t.progress = 100
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = f"{type(e).__name__}: {e}"
            t.log.append(f"[!] 失败: {t.error}")
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return t


_default: Optional[DevSecOpsOrchestrator] = None


def get_orchestrator() -> DevSecOpsOrchestrator:
    global _default
    if _default is None:
        _default = DevSecOpsOrchestrator()
    return _default
