# -*- coding: utf-8 -*-
"""
compliance_orchestrator.py — 合规审计七阶段编排器。

阶段:
    1. asset_inventory      资产盘点
    2. baseline_check      基线检查（100+ 规则）
    3. compliance_assess   合规评估（等保/ISO27001/PCI-DSS/SOC2）
    4. gap_analysis        差距分析
    5. remediation          整改跟踪
    6. retest               复测验证
    7. report               合规报告
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .asset_inventory_phase import get_asset_inventory_phase
from .baseline_check_phase import get_baseline_check_phase
from .compliance_assessment_phase import (
    get_compliance_assessment_phase)
from .gap_analysis_phase import get_gap_analysis_phase
from .remediation_tracking_phase import get_remediation_tracking_phase
from .retest_verification_phase import get_retest_verification_phase
from .compliance_report_phase import get_compliance_report_phase
from .ai_analysis import get_ai_analysis
from .realtime_push import get_realtime_push
from .report_generator import get_report_generator, REPORTS_DIR


STAGES = [
    ("asset_inventory",   "1.资产盘点", 12),
    ("baseline_check",    "2.基线检查", 28),
    ("compliance_assess", "3.合规评估", 45),
    ("gap_analysis",      "4.差距分析", 60),
    ("remediation",       "5.整改跟踪", 75),
    ("retest",            "6.复测验证", 88),
    ("report",            "7.合规报告", 100),
]


@dataclass
class ComplianceTask:
    task_id: str = ""
    name: str = ""
    status: str = "pending"
    stage: str = "init"
    progress: int = 0
    created_at: str = ""
    finished_at: Optional[str] = None
    error: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)
    log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "name": self.name,
            "status": self.status, "stage": self.stage,
            "progress": self.progress,
            "created_at": self.created_at,
            "finished_at": self.finished_at, "error": self.error,
            "results": self.results, "log": self.log[-80:],
        }


class ComplianceOrchestrator:
    """七阶段编排器。"""

    def __init__(self) -> None:
        self.inv = get_asset_inventory_phase()
        self.base = get_baseline_check_phase()
        self.ca = get_compliance_assessment_phase()
        self.gap = get_gap_analysis_phase()
        self.rm = get_remediation_tracking_phase()
        self.retest = get_retest_verification_phase()
        self.report_phase = get_compliance_report_phase()
        self.ai = get_ai_analysis()
        self.rt = get_realtime_push()
        self.gen = get_report_generator()
        self._tasks: Dict[str, ComplianceTask] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def create_task(self, name: str = "合规审计全流程") -> ComplianceTask:
        t = ComplianceTask(
            task_id="cpa_" + uuid.uuid4().hex[:10],
            name=name,
            created_at=datetime.now().isoformat(timespec="seconds"))
        with self._lock:
            self._tasks[t.task_id] = t
        return t

    def list_tasks(self) -> list:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()][::-1]

    def get_task(self, task_id: str) -> Optional[ComplianceTask]:
        with self._lock:
            return self._tasks.get(task_id)

    # ------------------------------------------------------------------ #
    def _log(self, t: ComplianceTask, level: str, msg: str) -> None:
        t.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] "
                     f"{level} {msg}")
        self.rt.emit_log(t.task_id, level, msg)

    def _think(self, t: ComplianceTask, thought: str) -> None:
        self.rt.emit_thought(t.task_id, thought)

    def _stage(self, t: ComplianceTask, key: str, label: str,
               overall: int) -> None:
        t.stage = key
        t.progress = overall
        self.rt.emit_progress(t.task_id, key, label, overall,
                              stage_progress=0)

    # ------------------------------------------------------------------ #
    def run_full(self, task_id: str) -> None:
        t = self._tasks.get(task_id)
        if t is None:
            return
        t.status = "running"
        try:
            # 阶段1 资产盘点
            self._stage(t, "asset_inventory", STAGES[0][1], 8)
            self._log(t, "INFO", "启动资产盘点（nmap/arp 真实发现 + 模拟兜底）")
            self._think(t, "自动发现服务器/网络/数据库/应用/终端资产")
            d1 = self.inv.discover_subnet("10.10.1.0/24")
            self.inv.export_inventory("json")
            s1 = self.inv.stats()
            t.results["asset_inventory"] = s1
            self._log(t, "OK", f"盘点资产 {s1['total']} 个，"
                               f"方法={d1.get('method')}")

            # 阶段2 基线检查
            self._stage(t, "baseline_check", STAGES[1][1], 24)
            self._log(t, "INFO", f"执行 {self.base.rule_count()} 条基线规则")
            self._think(t, "对资产逐项跑账户/认证/文件/网络/日志/服务/库/Web 检查")
            # 对前 3 个资产做检查
            assets = self.inv.list_assets()[:3]
            bresults = []
            for a in assets:
                r = self.base.run_check(a["asset_id"])
                bresults.append({"asset": a["name"],
                                 "pass_rate": r["pass_rate"],
                                 "failed": r["failed"]})
            t.results["baseline_check"] = {"stats": self.base.stats(),
                                           "per_asset": bresults}
            self._log(t, "OK", f"基线通过率 "
                               f"{self.base.stats()['pass_rate']}%")

            # 阶段3 合规评估
            self._stage(t, "compliance_assess", STAGES[2][1], 42)
            self._log(t, "INFO", "评估等保2.0/ISO27001/PCI-DSS/SOC2")
            self._think(t, "映射基线结果到合规控制项，计算各框架得分")
            assess = self.ca.auto_assess()
            t.results["compliance_assess"] = self.ca.overall_score()
            self._log(t, "OK", f"整体合规率 "
                               f"{self.ca.overall_score()['overall_score']}%")

            # 阶段4 差距分析
            self._stage(t, "gap_analysis", STAGES[3][1], 58)
            self._log(t, "INFO", "自动对比要求与实际，识别差距")
            self._think(t, "按严重度分级，关联资产/规则/合规项")
            gap = self.gap.analyze()
            t.results["gap_analysis"] = gap["summary"]
            for g in gap["gaps"][:5]:
                self.rt.emit_gap(task_id, g)
            self._log(t, "OK", f"识别差距 {gap['summary']['total']} 项")

            # 阶段5 整改跟踪
            self._stage(t, "remediation", STAGES[4][1], 73)
            self._log(t, "INFO", "生成整改任务并分配")
            self._think(t, "为 critical/high 差距创建整改任务，设置 SLA")
            for g in gap["gaps"]:
                if g["severity"] in ("critical", "high"):
                    self.rm.create_task(
                        title=g["title"], gap_id=g["gap_id"],
                        assignee="安全运维组", severity=g["severity"],
                        priority=g["severity"],
                        due_in_days=15 if g["severity"] == "critical" else 30)
            t.results["remediation"] = self.rm.sla_stats()
            self._log(t, "OK", f"整改任务 "
                               f"{self.rm.sla_stats()['total']} 项")

            # 阶段6 复测验证
            self._stage(t, "retest", STAGES[5][1], 86)
            self._log(t, "INFO", "整改后自动复测")
            self._think(t, "对已完成整改项复测，未通过回流")
            # 模拟：把部分整改任务标完成再复测
            tasks = self.rm.list_tasks()
            for tk in tasks[:2]:
                self.rm.update_task(tk["task_id"],
                                    status="in_progress",
                                    progress_note="已修复")
                self.rm.approve(tk["task_id"])
            for tk in tasks[:2]:
                self.retest.retest_gap(tk["gap_id"], tk["task_id"])
            t.results["retest"] = self.retest.stats()
            self._log(t, "OK", f"复测通过率 "
                               f"{self.retest.stats()['pass_rate']}%")

            # 阶段7 报告
            self._stage(t, "report", STAGES[6][1], 97)
            self._log(t, "INFO", "生成合规审计报告（MD/HTML）")
            self._think(t, "组装执行摘要/差距/建议/证据，导出报告")
            rep = self.gen.generate("both")
            t.results["report"] = {"md_path": rep["md_path"],
                                   "html_path": rep["html_path"]}
            self._log(t, "OK", "报告已生成")

            # AI 分析
            self._think(t, "AI 对差距排序、风险评估、趋势预测")
            ai = self.ai.analyze_gaps()
            t.results["ai_analysis"] = {
                "summary": ai["summary"],
                "advice_count": len(ai["advice"]),
                "risk": self.ai.risk_assessment()["risk_level"],
            }
            self.rt.emit_comply(task_id,
                                self.ca.overall_score())
            self.rt.emit_result(task_id, t.results)

            t.status = "done"
            t.finished_at = datetime.now().isoformat(timespec="seconds")
            self.rt.emit_progress(task_id, "done", "完成", 100,
                                  stage_progress=100, eta_seconds=0)
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = str(e)
            self._log(t, "ERROR", f"任务失败: {e}")
        finally:
            t.progress = 100 if t.status == "done" else t.progress


_default: Optional[ComplianceOrchestrator] = None


def get_orchestrator() -> ComplianceOrchestrator:
    global _default
    if _default is None:
        _default = ComplianceOrchestrator()
    return _default
