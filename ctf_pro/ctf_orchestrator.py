# -*- coding: utf-8 -*-
"""
ctf_orchestrator.py — CTF Pro 八阶段编排器。

阶段:
    1. competition_management 赛事管理
    2. challenge_management   题目管理
    3. challenge_deployment   题目部署
    4. game_play              比赛进行
    5. realtime_ranking       实时排名
    6. postmortem             比赛复盘
    7. training_mode          训练模式
    8. team_management        战队管理
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .competition_management_phase import get_competition_phase
from .challenge_management_phase import (
    get_challenge_phase, CHALLENGE_CATEGORIES)
from .challenge_deployment_phase import get_deployment_phase
from .game_play_phase import get_gameplay_phase
from .realtime_ranking_phase import get_ranking_phase
from .postmortem_phase import get_postmortem_phase
from .training_mode_phase import get_training_phase
from .team_management_phase import get_team_phase
from .ai_analysis import get_ai_analysis
from .realtime_push import get_realtime_push
from .report_generator import get_report_generator, REPORTS_DIR


STAGES = [
    ("competition_management", "1.赛事管理", 12),
    ("challenge_management", "2.题目管理", 25),
    ("challenge_deployment", "3.题目部署", 40),
    ("game_play", "4.比赛进行", 55),
    ("realtime_ranking", "5.实时排名", 68),
    ("postmortem", "6.比赛复盘", 80),
    ("training_mode", "7.训练模式", 90),
    ("team_management", "8.战队管理", 100),
]


@dataclass
class CtfTask:
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


class CtfOrchestrator:
    """八阶段编排器。"""

    def __init__(self) -> None:
        self.comp = get_competition_phase()
        self.chal = get_challenge_phase()
        self.dep = get_deployment_phase()
        self.gp = get_gameplay_phase()
        self.rank = get_ranking_phase()
        self.pm = get_postmortem_phase()
        self.train = get_training_phase()
        self.team = get_team_phase()
        self.ai = get_ai_analysis()
        self.rt = get_realtime_push()
        self.report = get_report_generator()
        self._tasks: Dict[str, CtfTask] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def create_task(self, name: str = "CTF 八阶段全流程"
                    ) -> CtfTask:
        t = CtfTask(
            task_id="ctf_" + uuid.uuid4().hex[:10],
            name=name,
            created_at=datetime.now().isoformat(timespec="seconds"))
        with self._lock:
            self._tasks[t.task_id] = t
        return t

    def list_tasks(self) -> list:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()][::-1]

    def get_task(self, task_id: str) -> Optional[CtfTask]:
        with self._lock:
            return self._tasks.get(task_id)

    # ------------------------------------------------------------------ #
    def _log(self, t: CtfTask, level: str, msg: str) -> None:
        t.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] "
                     f"{level} {msg}")
        self.rt.emit_log(t.task_id, level, msg)

    def _think(self, t: CtfTask, thought: str) -> None:
        self.rt.emit_thought(t.task_id, thought)

    def _stage(self, t: CtfTask, key: str, label: str,
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
            # 阶段1 赛事管理
            self._stage(t, "competition_management", STAGES[0][1], 8)
            self._log(t, "INFO", "创建演示赛事与报名")
            c = self.comp.create_competition(
                name="AI Hacking CTF 春季赛",
                description="八阶段全流程演示赛事",
                comp_type="Jeopardy", organizer="AI Hacking Agent")
            self.comp.register(c["comp_id"], "team",
                               name="战队-阿尔法", captain="admin")
            self.comp.change_status(c["comp_id"], "running")
            t.results["competition"] = c["comp_id"]
            self._log(t, "OK", f"赛事 {c['comp_id']} 已启动")

            # 阶段2 题目管理
            self._stage(t, "challenge_management", STAGES[1][1], 22)
            self._log(t, "INFO", "批量创建 8 大题型演示题目")
            created = []
            for cat in CHALLENGE_CATEGORIES:
                ch = self.chal.create_challenge(
                    title=f"演示-{cat}-入门题",
                    category=cat, difficulty="简单",
                    flag="flag{" + uuid.uuid4().hex[:10] + "}",
                    competition_id=c["comp_id"])
                self.chal.change_status(ch["chal_id"], "published")
                created.append(ch["chal_id"])
            t.results["challenges"] = created
            self._log(t, "OK", f"创建 {len(created)} 道题目")

            # 阶段3 题目部署
            self._stage(t, "challenge_deployment", STAGES[2][1], 38)
            self._log(t, "INFO", "调用 Docker 部署题目容器")
            docker_ready = bool(self.dep.docker_status().get(
                "daemon_running"))
            self._think(t, "优先调用真实 docker；未安装则用内置"
                          "模拟部署框架兜底")
            deps = []
            for cid in created[:3]:
                d = self.dep.deploy(cid, "team-alpha",
                                    flag_template="flag{tg_"+"{team_id}"+"}")
                deps.append(d["deploy_id"])
                self.gp.register_answer(cid, [d["flag"]], 200)
            t.results["deployments"] = deps
            t.results["docker_ready"] = docker_ready
            self._log(t, "OK", f"部署 {len(deps)} 个容器 "
                               f"(docker_ready={docker_ready})")

            # 阶段4 比赛进行
            self._stage(t, "game_play", STAGES[3][1], 52)
            self._log(t, "INFO", "模拟提交 flag / 判题 / 一血")
            tm = self.team.create_team("战队-阿尔法", "admin")
            self.rank.ensure_team("team-alpha", "战队-阿尔法")
            subs = []
            for dep_id in deps:
                dep = self.dep._get(dep_id)
                s = self.gp.submit(dep.chal_id, "team-alpha", dep.flag)
                subs.append(s)
                self.rt.emit_submission(task_id, s)
            t.results["submissions"] = len(subs)
            self._log(t, "OK", f"提交 {len(subs)} 次，判题完成")

            # 阶段5 实时排名
            self._stage(t, "realtime_ranking", STAGES[4][1], 66)
            lb = self.rank.rebuild()
            self.rt.emit_ranking(task_id, lb)
            t.results["leaderboard"] = lb
            self._log(t, "OK", f"积分榜已重建，Top1: "
                               f"{lb[0]['team_name'] if lb else '-'}")

            # 阶段6 比赛复盘
            self._stage(t, "postmortem", STAGES[5][1], 78)
            for cid in created:
                meta = self.chal.get_challenge(cid)
                if meta:
                    self.pm.register_challenge(
                        cid, meta["title"], meta["category"],
                        meta["difficulty"])
            pm = self.pm.generate_postmortem(t.name)
            t.results["postmortem"] = pm
            self._log(t, "OK", "复盘报告已生成")

            # 阶段7 训练模式
            self._stage(t, "training_mode", STAGES[6][1], 88)
            rec = self.train.start_training("admin", "category", "Web")
            self.train.finish_training(rec["rec_id"], True, 200, "Web")
            ab = self.train.ability_assessment("admin")
            t.results["training"] = {"ability": ab}
            self._log(t, "OK", f"训练记录已写入，能力分 {ab}")

            # 阶段8 战队管理
            self._stage(t, "team_management", STAGES[7][1], 98)
            self.team.record_match(tm["team_id"],
                                   c["name"], 1, 600, 3)
            t.results["team"] = self.team.stats()
            self._log(t, "OK", "战队统计已更新")

            # AI 分析 + 报告
            ai = self.ai.postmortem_analysis(
                self.pm.solve_statistics())
            t.results["ai_analysis"] = ai
            t.results["report"] = self.report.generate("both")
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


_default: Optional[CtfOrchestrator] = None


def get_orchestrator() -> CtfOrchestrator:
    global _default
    if _default is None:
        _default = CtfOrchestrator()
    return _default
