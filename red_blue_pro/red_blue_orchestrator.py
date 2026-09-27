# -*- coding: utf-8 -*-
"""
red_blue_orchestrator.py — 红蓝对抗 Pro 编排器。

红队六阶段: 侦察/初始访问/执行/提权/横向/目标
蓝队三阶段: 检测/响应/溯源
紫队复盘 + AI 分析 + 报告生成

通过 on_event 回调把进度/日志/思考推到 WebSocket。
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .red_recon_phase import get_red_recon_phase
from .red_initial_access_phase import get_red_initial_access_phase
from .red_execution_phase import get_red_execution_phase
from .red_privesc_phase import get_red_privesc_phase
from .red_lateral_phase import get_red_lateral_phase
from .red_objective_phase import get_red_objective_phase
from .blue_detection_phase import get_blue_detection_phase
from .blue_response_phase import get_blue_response_phase
from .blue_attribution_phase import get_blue_attribution_phase
from .purple_debrief import get_purple_debrief
from .ai_analysis import get_ai_analysis
from .report_generator import (
    get_report_generator, ReportGenerator, ReportData,
)

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "red_blue_pro")

STAGES = [
    ("recon", "红·侦察", 8),
    ("initial_access", "红·初始访问", 22),
    ("execution", "红·执行", 36),
    ("privesc", "红·提权", 50),
    ("lateral", "红·横向", 64),
    ("objective", "红·目标", 76),
    ("detection", "蓝·检测", 84),
    ("response", "蓝·响应", 90),
    ("attribution", "蓝·溯源", 94),
    ("purple", "紫·复盘", 97),
    ("report", "报告", 100),
]


@dataclass
class RBTask:
    task_id: str = ""
    target: str = ""
    status: str = "pending"
    stage: str = "init"
    progress: int = 0
    created_at: str = ""
    finished_at: Optional[str] = None
    error: Optional[str] = None
    red: Dict[str, Any] = field(default_factory=dict)
    blue: Dict[str, Any] = field(default_factory=dict)
    purple: Dict[str, Any] = field(default_factory=dict)
    analysis: Dict[str, Any] = field(default_factory=dict)
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
            "finished_at": self.finished_at, "error": self.error,
            "red": self.red, "blue": self.blue, "purple": self.purple,
            "analysis": self.analysis, "report_path": self.report_path,
            "log": self.log[-100:],
        }


class RedBlueOrchestrator:
    """红蓝对抗编排器。"""

    def __init__(self,
                 on_event: Optional[Callable[[Dict[str, Any]], None]] = None
                 ) -> None:
        self.recon = get_red_recon_phase()
        self.ia = get_red_initial_access_phase()
        self.exec = get_red_execution_phase()
        self.priv = get_red_privesc_phase()
        self.lat = get_red_lateral_phase()
        self.obj = get_red_objective_phase()
        self.det = get_blue_detection_phase()
        self.resp = get_blue_response_phase()
        self.attr = get_blue_attribution_phase()
        self.purple = get_purple_debrief()
        self.ai = get_ai_analysis()
        self.report = get_report_generator()
        self._tasks: Dict[str, RBTask] = {}
        self.on_event = on_event or (lambda ev: None)

    def _emit(self, ev: Dict[str, Any]) -> None:
        try:
            self.on_event(ev)
        except Exception:
            pass

    def _log(self, t: RBTask, level: str, msg: str,
             side: str = "red") -> None:
        line = f"[{level}] [{side}] {msg}"
        t.log.append(line)
        self._emit({"type": "log", "task_id": t.task_id,
                    "level": level, "message": msg, "side": side})

    def _progress(self, t: RBTask, overall: int, step: str,
                  step_pct: int, eta: int) -> None:
        t.progress = overall
        self._emit({"type": "progress", "task_id": t.task_id,
                    "overall": overall, "step": step,
                    "step_pct": step_pct, "eta_seconds": eta})

    def _stage(self, t: RBTask, key: str, label: str,
               side: str = "red") -> None:
        t.stage = key
        self._emit({"type": "stage", "task_id": t.task_id,
                    "stage": key, "status": "running", "side": side})
        self._log(t, "INFO", f"进入阶段: {label}", side)

    def create_task(self, target: str) -> RBTask:
        tid = uuid.uuid4().hex[:16]
        t = RBTask(task_id=tid, target=target,
                   created_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._tasks[tid] = t
        return t

    def get_task(self, task_id: str) -> Optional[RBTask]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in sorted(
            self._tasks.values(), key=lambda x: x.created_at,
            reverse=True)]

    # ------------------------------------------------------------------ #
    def run_full(self, target: str,
                 task_id: Optional[str] = None) -> RBTask:
        t = self._tasks.get(task_id) if task_id else None
        if t is None:
            t = self.create_task(target)
        t.status = "running"
        try:
            # 红队六阶段
            self._stage(t, "recon", "侦察", "red")
            self._progress(t, 8, "OSINT 侦察", 30, 20)
            self._emit({"type": "thinking", "task_id": t.task_id,
                        "thought": "先做 OSINT 子域名/邮箱，定位攻击面"})
            t.red["recon"] = self.recon.osint_dashboard(target).to_dict()
            self._log(t, "SUCCESS",
                      f"子域名 {t.red['recon'].get('subdomain_count',0)} "
                      f"邮箱 {t.red['recon'].get('email_count',0)}", "red")

            self._stage(t, "initial_access", "初始访问", "red")
            self._progress(t, 22, "初始访问框架", 40, 15)
            t.red["initial_access"] = {
                "module": "ia", "tool": "framework",
                "templates": self.ia.phishing_templates(),
                "spray": self.ia.password_spray(
                    target).to_dict(),
            }
            self._log(t, "INFO", "钓鱼/Exploit/凭据框架就绪", "red")

            self._stage(t, "execution", "执行", "red")
            self._progress(t, 36, "执行框架", 50, 10)
            t.red["execution"] = self.exec.execute_demo()
            self._log(t, "INFO", "命令/代码执行模板就绪", "red")

            self._stage(t, "privesc", "提权", "red")
            self._progress(t, 50, "提权审计", 60, 10)
            t.red["privesc"] = self.priv.audit().to_dict()
            self._log(t, "SUCCESS",
                      f"提权发现 {t.red['privesc'].get('finding_count',0)}",
                      "red")

            self._stage(t, "lateral", "横向", "red")
            self._progress(t, 64, "横向框架", 75, 10)
            t.red["lateral"] = self.lat.tool_status()
            self._log(t, "INFO", "SMB/WMI/WinRM/PtH 框架就绪", "red")

            self._stage(t, "objective", "目标", "red")
            self._progress(t, 76, "目标达成", 85, 10)
            t.red["objective"] = {
                "exfil": self.obj.cred_export().to_dict(),
                "cleanup": self.obj.log_clean().to_dict(),
            }
            self._log(t, "SUCCESS", "红队六阶段完成", "red")

            # 蓝队三阶段
            self._stage(t, "detection", "检测", "blue")
            self._progress(t, 84, "蓝队检测", 50, 10)
            t.blue["detection"] = {
                "module": "detection",
                "alerts": self.det.anomaly_login().alerts +
                          self.det.analyze_windows_log().alerts,
                "alert_count": 0,
            }
            t.blue["detection"]["alert_count"] = len(
                t.blue["detection"]["alerts"])
            self._log(t, "SUCCESS",
                      f"蓝队告警 {t.blue['detection']['alert_count']}",
                      "blue")

            self._stage(t, "response", "响应", "blue")
            self._progress(t, 90, "应急响应", 60, 8)
            t.blue["response"] = self.resp.run_full(target)
            self._log(t, "INFO", "IR 流程建议已生成", "blue")

            self._stage(t, "attribution", "溯源", "blue")
            self._progress(t, 94, "溯源分析", 70, 8)
            t.blue["attribution"] = self.attr.full_attribution().to_dict()
            self._log(t, "SUCCESS", "攻击时间线已重建", "blue")

            # 紫队复盘
            self._stage(t, "purple", "紫队复盘", "purple")
            red_stages = [{"name": k, "success": bool(t.red.get(k)),
                           "severity": "high"}
                          for k in ("recon", "initial_access", "execution",
                                    "privesc", "lateral", "objective")]
            blue_alerts = [{"phase": k} for k in
                           ("detection", "response", "attribution")]
            pd = self.purple.compare(red_stages, blue_alerts)
            t.purple = pd.to_dict()
            self._log(t, "SUCCESS",
                      f"检测覆盖率 {t.purple.get('coverage',0)}%",
                      "purple")

            # AI 分析
            self._emit({"type": "thinking", "task_id": t.task_id,
                        "thought": "汇总红蓝紫产物，生成攻击链图与评级"})
            t.analysis = self.ai.analyze(t.red, t.blue)

            # 报告
            self._stage(t, "report", "报告", "purple")
            self._progress(t, 98, "生成报告", 100, 5)
            rd = ReportData(
                task_id=t.task_id, target=target,
                started_at=t.created_at,
                finished_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                red=t.red, blue=t.blue, purple=t.purple,
                analysis=t.analysis)
            os.makedirs(REPORTS_DIR, exist_ok=True)
            t.report_path = self.report.save(rd, REPORTS_DIR, "html")
            t.report_markdown = self.report.generate_markdown(rd)
            t.report_html = self.report.generate_html(rd)
            self._log(t, "SUCCESS", f"报告已生成: {t.report_path}",
                      "purple")

            t.status = "done"
            t.stage = "done"
            t.progress = 100
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
            self._emit({"type": "done", "task_id": t.task_id,
                        "status": "done"})
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = f"{type(e).__name__}: {e}"
            self._log(t, "ERROR", f"失败: {t.error}", "purple")
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return t


_default_orch: Optional[RedBlueOrchestrator] = None


def get_orchestrator() -> RedBlueOrchestrator:
    global _default_orch
    if _default_orch is None:
        _default_orch = RedBlueOrchestrator()
    return _default_orch
