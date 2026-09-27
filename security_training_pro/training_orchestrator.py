# -*- coding: utf-8 -*-
"""
training_orchestrator.py — 安全培训八阶段编排器。

阶段:
    1. course_management   课程管理
    2. learning_path       学习路径
    3. lab_environment    实验环境（Docker）
    4. exam_system         考试系统
    5. phishing            钓鱼演练
    6. student             学员管理
    7. instructor          讲师管理
    8. analysis            数据分析
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .course_management_phase import get_course_management_phase
from .learning_path_phase import get_learning_path_phase
from .lab_environment_phase import get_lab_environment_phase
from .exam_system_phase import get_exam_system_phase
from .phishing_simulation_phase import get_phishing_simulation_phase
from .student_management_phase import get_student_management_phase
from .instructor_management_phase import get_instructor_management_phase
from .data_analysis_phase import get_data_analysis_phase
from .ai_analysis import get_ai_analysis
from .realtime_push import get_realtime_push
from .report_generator import get_report_generator, REPORTS_DIR


STAGES = [
    ("course_management", "1.课程管理", 10),
    ("learning_path",     "2.学习路径", 22),
    ("lab_environment",   "3.实验环境", 38),
    ("exam_system",       "4.考试系统", 54),
    ("phishing",          "5.钓鱼演练", 68),
    ("student",           "6.学员管理", 80),
    ("instructor",        "7.讲师管理", 90),
    ("analysis",          "8.数据分析", 100),
]


@dataclass
class TrainingTask:
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


class TrainingOrchestrator:
    """八阶段编排器。"""

    def __init__(self) -> None:
        self.course = get_course_management_phase()
        self.path = get_learning_path_phase()
        self.lab = get_lab_environment_phase()
        self.exam = get_exam_system_phase()
        self.phish = get_phishing_simulation_phase()
        self.stu = get_student_management_phase()
        self.ins = get_instructor_management_phase()
        self.analysis = get_data_analysis_phase()
        self.ai = get_ai_analysis()
        self.rt = get_realtime_push()
        self.report = get_report_generator()
        self._tasks: Dict[str, TrainingTask] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def create_task(self, name: str = "安全培训全流程演练"
                    ) -> TrainingTask:
        t = TrainingTask(
            task_id="stp_" + uuid.uuid4().hex[:10],
            name=name,
            created_at=datetime.now().isoformat(timespec="seconds"))
        with self._lock:
            self._tasks[t.task_id] = t
        return t

    def list_tasks(self) -> list:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()][::-1]

    def get_task(self, task_id: str) -> Optional[TrainingTask]:
        with self._lock:
            return self._tasks.get(task_id)

    # ------------------------------------------------------------------ #
    def _log(self, t: TrainingTask, level: str, msg: str) -> None:
        t.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] "
                     f"{level} {msg}")
        self.rt.emit_log(t.task_id, level, msg)

    def _think(self, t: TrainingTask, thought: str) -> None:
        self.rt.emit_thought(t.task_id, thought)

    def _stage(self, t: TrainingTask, key: str, label: str,
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
            # 阶段1 课程管理
            self._stage(t, *STAGES[0][:2], STAGES[0][2])
            self._log(t, "INFO", "汇总课程 / 章节 / 课件 / 视频")
            self._think(t, "统计课程分类与发布状态，校验课程模板")
            t.results["course_management"] = self.course.stats()
            self._log(t, "OK", f"课程 {t.results['course_management']['total']} 门")
            time.sleep(0.1)

            # 阶段2 学习路径
            self._stage(t, *STAGES[1][:2], STAGES[1][2])
            self._log(t, "INFO", "评估学习路径进度与推荐")
            self._think(t, "基于学员基础推荐路径，优化进度偏低路径")
            t.results["learning_path"] = self.path.stats()
            self._log(t, "OK", f"路径 {t.results['learning_path']['total']} 条")

            # 阶段3 实验环境
            self._stage(t, *STAGES[2][:2], STAGES[2][2])
            self._log(t, "INFO", "探测 Docker 并部署实验环境")
            dstat = self.lab.docker_status()
            self._think(t, "优先真实 docker run；未安装则内置模拟兜底")
            t.results["lab_environment"] = self.lab.stats()
            self._log(t, "OK",
                      f"docker={dstat.get('daemon_running')}，"
                      f"实验 {t.results['lab_environment']['total']}")

            # 阶段4 考试系统
            self._stage(t, *STAGES[3][:2], STAGES[3][2])
            self._log(t, "INFO", "组卷 / 判题 / 证书")
            self._think(t, "自动判客观题，主观题转 AI 批改")
            t.results["exam_system"] = self.exam.stats()
            self._log(t, "OK", f"通过率 {t.results['exam_system']['pass_rate']}%")

            # 阶段5 钓鱼演练
            self._stage(t, *STAGES[4][:2], STAGES[4][2])
            self._log(t, "INFO", "发起钓鱼演练并跟踪点击")
            self._think(t, "按用户行为分级风险，输出培训建议")
            t.results["phishing"] = self.phish.stats()
            self._log(t, "OK", f"事件 {t.results['phishing']['total_events']}")

            # 阶段6 学员管理
            self._stage(t, *STAGES[5][:2], STAGES[5][2])
            self._log(t, "INFO", "学员档案 / 能力 / 行为")
            t.results["student"] = self.stu.stats()
            self._log(t, "OK", f"学员 {t.results['student']['total']}")

            # 阶段7 讲师管理
            self._stage(t, *STAGES[6][:2], STAGES[6][2])
            self._log(t, "INFO", "讲师排名 / 绩效 / 收益")
            t.results["instructor"] = self.ins.stats()
            self._log(t, "OK", f"讲师 {t.results['instructor']['total']}")

            # 阶段8 数据分析
            self._stage(t, *STAGES[7][:2], STAGES[7][2])
            self._log(t, "INFO", "聚合 ROI / 通过率 / 能力分布")
            self._think(t, "生成可视化面板与改进建议")
            t.results["analysis"] = self.analysis.visualizations()

            # AI 分析
            self._think(t, "AI 正在生成课程内容 / 出题 / 能力评估")
            t.results["ai_analysis"] = {
                "course_demo": self.ai.generate_course_content("XSS", "简单")["outline"][0],
                "questions": len(self.ai.generate_questions("SQL注入")["questions"]),
                "advice": self.ai.study_advice({"Web安全": 60, "密码学": 30})["advice"],
            }

            t.results["report"] = self.report.generate("both")
            self._log(t, "OK", "报告已生成")
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


_default: Optional[TrainingOrchestrator] = None


def get_orchestrator() -> TrainingOrchestrator:
    global _default
    if _default is None:
        _default = TrainingOrchestrator()
    return _default
