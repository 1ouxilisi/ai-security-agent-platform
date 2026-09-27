# -*- coding: utf-8 -*-
"""
src_orchestrator.py — SRC Pro 八阶段编排器。

阶段:
    1. platform_management  平台管理
    2. submission           漏洞提交
    3. review               漏洞审核
    4. bounty               赏金管理
    5. community            白帽社区
    6. enterprise           企业门户
    7. knowledge            漏洞知识库
    8. analysis             数据分析
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .platform_management_phase import get_platform_management_phase
from .vulnerability_submission_phase import get_submission_phase
from .vulnerability_review_phase import get_review_phase
from .bounty_management_phase import get_bounty_phase
from .hacker_community_phase import get_community_phase
from .enterprise_portal_phase import get_enterprise_phase
from .vulnerability_knowledge_base_phase import get_knowledge_phase
from .data_analysis_phase import get_analysis_phase
from .ai_analysis import get_ai_analysis
from .realtime_push import get_realtime_push
from .report_generator import get_report_generator, REPORTS_DIR

STAGES = [
    ("platform_management", "1.平台管理", 10),
    ("submission",         "2.漏洞提交", 22),
    ("review",             "3.漏洞审核", 38),
    ("bounty",             "4.赏金管理", 52),
    ("community",          "5.白帽社区", 64),
    ("enterprise",         "6.企业门户", 76),
    ("knowledge",          "7.漏洞知识库", 88),
    ("analysis",           "8.数据分析", 100),
]


@dataclass
class SRCTask:
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
            "finished_at": self.finished_at,
            "error": self.error, "results": self.results,
            "log": self.log[-80:],
        }


class SRCOrchestrator:
    """SRC 八阶段编排器。"""

    def __init__(self) -> None:
        self.pm = get_platform_management_phase()
        self.sub = get_submission_phase()
        self.rev = get_review_phase()
        self.bm = get_bounty_phase()
        self.com = get_community_phase()
        self.ent = get_enterprise_phase()
        self.kb = get_knowledge_phase()
        self.ana = get_analysis_phase()
        self.ai = get_ai_analysis()
        self.rt = get_realtime_push()
        self.report = get_report_generator()
        self._tasks: Dict[str, SRCTask] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def create_task(self, name: str = "SRC 全流程运营巡检") -> SRCTask:
        t = SRCTask(
            task_id="src_" + uuid.uuid4().hex[:10],
            name=name,
            created_at=datetime.now().isoformat(timespec="seconds"))
        with self._lock:
            self._tasks[t.task_id] = t
        return t

    def list_tasks(self) -> list:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()][::-1]

    def get_task(self, task_id: str) -> Optional[SRCTask]:
        with self._lock:
            return self._tasks.get(task_id)

    # ------------------------------------------------------------------ #
    def _log(self, t: SRCTask, level: str, msg: str) -> None:
        t.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] "
                     f"{level} {msg}")
        self.rt.emit_log(t.task_id, level, msg)

    def _think(self, t: SRCTask, thought: str) -> None:
        self.rt.emit_thought(t.task_id, thought)

    def _stage(self, t: SRCTask, key: str, label: str,
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
            # 阶段1 平台管理
            self._stage(t, "platform_management", STAGES[0][1], 8)
            self._log(t, "INFO", "加载平台/白帽/企业/规则/公告")
            self._think(t, "正在汇总平台配置与白帽企业数据")
            t.results["platform"] = self.pm.stats()
            self._log(t, "OK",
                      f"白帽 {self.pm.stats()['hackers_total']}，"
                      f"企业 {self.pm.stats()['enterprises_total']}")

            # 阶段2 漏洞提交
            self._stage(t, "submission", STAGES[1][1], 20)
            self._log(t, "INFO", "扫描提交队列，频率与重复检测")
            self._think(t, "正在检测重复提交与提交频率")
            seed = self.sub.submit(
                title="AI 巡检：新增越权样本",
                vuln_type="A01 失效的访问控制",
                severity="medium",
                repro_steps="1. 登录 2. 改 id",
                poc="curl id=1", impact="可遍历",
                fix_advice="服务端校验归属")
            t.results["submission"] = self.sub.stats()
            self.rt.emit_vuln(task_id, seed)
            self._log(t, "OK", f"漏洞总量 {self.sub.stats()['total']}")

            # 阶段3 漏洞审核
            self._stage(t, "review", STAGES[2][1], 36)
            self._log(t, "INFO", "AI 初审 + 人工复核流程")
            ai = self.ai.batch_review(self.sub.list(limit=10))
            t.results["review"] = {**self.rev.stats(),
                                   "ai": ai}
            self._log(t, "OK", f"AI 疑似误报 {ai['false_positive_suspected']}")

            # 阶段4 赏金管理
            self._stage(t, "bounty", STAGES[3][1], 50)
            self._log(t, "INFO", "按等级与影响计算赏金")
            pay = self.bm.grant(seed["vuln_id"], "hkr_seed",
                               self.bm.calculate("medium")["amount"])
            self.rt.emit_bounty(task_id, pay)
            t.results["bounty"] = self.bm.stats()
            self._log(t, "OK", f"累计赏金 ¥{self.bm.stats()['total_gross']}")

            # 阶段5 白帽社区
            self._stage(t, "community", STAGES[4][1], 62)
            self._log(t, "INFO", "汇总社区/讨论/荣誉墙")
            t.results["community"] = self.com.behavior_analysis()
            self._log(t, "OK", "社区数据已汇总")

            # 阶段6 企业门户
            self._stage(t, "enterprise", STAGES[5][1], 74)
            ents = self.pm.list_enterprises()
            eid = ents[0]["enterprise_id"] if ents else "ent_seed"
            t.results["enterprise"] = self.ent.dashboard(eid)
            self._log(t, "OK", "企业安全态势已生成")

            # 阶段7 知识库
            self._stage(t, "knowledge", STAGES[6][1], 86)
            t.results["knowledge"] = self.kb.stats()
            self._log(t, "OK", "知识库条目已统计")

            # 阶段8 数据分析
            self._stage(t, "analysis", STAGES[7][1], 98)
            self._log(t, "INFO", "趋势/ROI/风险评估")
            t.results["analysis"] = self.ana.full_report()
            t.results["report"] = self.report.generate("both")
            self._log(t, "OK", "SRC 运营报告已生成")

            self.rt.emit_result(task_id, t.results)
            t.status = "done"
            t.finished_at = datetime.now().isoformat(timespec="seconds")
            self.rt.emit_progress(task_id, "done", "完成", 100,
                                 stage_progress=100, eta_seconds=0)
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = str(e)
            self._log(t, "ERROR", f"任务失败: {e}")


_default: Optional[SRCOrchestrator] = None


def get_orchestrator() -> SRCOrchestrator:
    global _default
    if _default is None:
        _default = SRCOrchestrator()
    return _default
