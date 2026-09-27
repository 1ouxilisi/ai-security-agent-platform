# -*- coding: utf-8 -*-
"""
training_dashboard.py — 安全培训大屏仪表盘。

聚合:
    - KPI（学员/课程/实验/考试/通过率/完成率/证书/讲师）
    - 学习进度 / 考试通过率 / 能力分布
    - 钓鱼演练结果 / 学员活跃 / 课程完成率
    - 证书统计 / 讲师排名 / 实时事件流
"""

from __future__ import annotations

import random
from typing import Any, Dict, Optional


class TrainingDashboard:
    """培训大屏聚合器。"""

    def __init__(self) -> None:
        from .course_management_phase import (
            get_course_management_phase)
        from .learning_path_phase import get_learning_path_phase
        from .lab_environment_phase import get_lab_environment_phase
        from .exam_system_phase import get_exam_system_phase
        from .phishing_simulation_phase import (
            get_phishing_simulation_phase)
        from .student_management_phase import (
            get_student_management_phase)
        from .instructor_management_phase import (
            get_instructor_management_phase)
        from .data_analysis_phase import get_data_analysis_phase
        self.course = get_course_management_phase()
        self.path = get_learning_path_phase()
        self.lab = get_lab_environment_phase()
        self.exam = get_exam_system_phase()
        self.phish = get_phishing_simulation_phase()
        self.stu = get_student_management_phase()
        self.ins = get_instructor_management_phase()
        self.analysis = get_data_analysis_phase()

    # ------------------------------------------------------------------ #
    def kpi_cards(self) -> Dict[str, Any]:
        cs = self.course.stats()
        ss = self.stu.stats()
        es = self.exam.stats()
        ls = self.lab.stats()
        is_ = self.ins.stats()
        return {
            "学员数": ss["total"],
            "课程数": cs["total"],
            "实验数": ls["total"],
            "考试数": es["paper_total"],
            "题库题数": es["question_total"],
            "通过率": f"{es['pass_rate']}%",
            "完成率": f"{cs['published']}/{cs['total']}",
            "证书数": es["certificates"],
            "讲师数": is_["total"],
        }

    def learning_progress(self) -> Dict[str, Any]:
        st = self.stu.stats()
        return {
            "total_study_minutes": st["total_study_minutes"],
            "active": st["by_status"].get("活跃", 0),
            "avg_progress": self.path.stats()["avg_progress"],
        }

    def pass_rate(self) -> Dict[str, Any]:
        return self.exam.stats()

    def ability_distribution(self) -> Dict[str, Any]:
        return self.analysis.ability_improvement()

    def phishing_result(self) -> Dict[str, Any]:
        return self.analysis.phishing_analysis()

    def student_activity(self) -> Dict[str, Any]:
        return self.analysis.student_behavior()

    def instructor_rank(self) -> list:
        return self.ins.rank("rating")

    def cert_stats(self) -> Dict[str, Any]:
        es = self.exam.stats()
        return {"certificates": es["certificates"],
                "by_issue": "按月累计（演示）"}

    # ------------------------------------------------------------------ #
    def live_event_stream(self, n: int = 12) -> list:
        rng = random.Random(2026)
        events = ["学员开始学习", "学员交卷", "实验环境启动",
                  "钓鱼邮件已发送", "学员通过考试", "新证书颁发",
                  "讲师发布新课程", "学员完成章节"]
        out = []
        for _ in range(n):
            out.append({
                "time": f"{rng.randint(0,23):02d}:{rng.randint(0,59):02d}",
                "event": rng.choice(events),
                "level": rng.choice(["INFO", "OK", "EVENT"]),
            })
        return out

    def full_screen(self) -> Dict[str, Any]:
        return {
            "kpi": self.kpi_cards(),
            "learning": self.learning_progress(),
            "pass_rate": self.pass_rate(),
            "ability": self.ability_distribution(),
            "phishing": self.phishing_result(),
            "activity": self.student_activity(),
            "instructors": self.instructor_rank(),
            "certs": self.cert_stats(),
            "events": self.live_event_stream(),
            "roi": self.analysis.roi_analysis(),
        }


_default: Optional[TrainingDashboard] = None


def get_dashboard() -> TrainingDashboard:
    global _default
    if _default is None:
        _default = TrainingDashboard()
    return _default
