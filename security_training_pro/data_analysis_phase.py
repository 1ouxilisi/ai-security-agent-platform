# -*- coding: utf-8 -*-
"""
data_analysis_phase.py — 阶段8：数据分析。

功能:
    - 学习数据 / 考试通过率 / 课程完成率
    - 能力提升 / 培训 ROI / 学员行为 / 讲师绩效
    - 钓鱼演练分析 / 可视化 / 导出 / 报表
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional


class DataAnalysisPhase:
    """阶段8：数据分析。聚合前 7 阶段数据。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def _sources(self):
        from .course_management_phase import get_course_management_phase
        from .learning_path_phase import get_learning_path_phase
        from .lab_environment_phase import get_lab_environment_phase
        from .exam_system_phase import get_exam_system_phase
        from .phishing_simulation_phase import get_phishing_simulation_phase
        from .student_management_phase import get_student_management_phase
        from .instructor_management_phase import (
            get_instructor_management_phase)
        return {
            "course": get_course_management_phase(),
            "path": get_learning_path_phase(),
            "lab": get_lab_environment_phase(),
            "exam": get_exam_system_phase(),
            "phish": get_phishing_simulation_phase(),
            "stu": get_student_management_phase(),
            "ins": get_instructor_management_phase(),
        }

    # ------------------------------------------------------------------ #
    def learning_data(self) -> Dict[str, Any]:
        s = self._sources()
        st = s["stu"].stats()
        return {
            "total_study_minutes": st["total_study_minutes"],
            "avg_minutes": round(
                st["total_study_minutes"] / max(1, st["total"]), 1),
            "active": st["by_status"].get("活跃", 0),
            "dormant": st["by_status"].get("休眠", 0),
            "completed_courses": st.get("total_certs", 0),
        }

    def exam_pass_rate(self) -> Dict[str, Any]:
        s = self._sources()
        es = s["exam"].stats()
        return {
            "overall_pass_rate": es["pass_rate"],
            "avg_score": es["avg_score"],
            "submitted": es["submitted"],
            "by_type": es["by_type"],
        }

    def course_completion(self) -> Dict[str, Any]:
        s = self._sources()
        cs = s["course"].stats()
        return {
            "total_courses": cs["total"],
            "published": cs["published"],
            "by_category": cs["by_category"],
            "total_students": cs["total_students"],
        }

    def ability_improvement(self) -> Dict[str, Any]:
        s = self._sources()
        students = s["stu"].list_students()
        domains: Dict[str, List[float]] = {}
        for st in students:
            for d, v in (st.get("ability") or {}).items():
                domains.setdefault(d, []).append(v)
        avg = {d: round(sum(v) / max(1, len(v)), 1)
               for d, v in domains.items()}
        return {"domains": avg,
                "weakest": sorted(avg.items(), key=lambda x: x[1])[:3]}

    def roi_analysis(self) -> Dict[str, Any]:
        # 演示口径：投入 = 学员数*人均成本；产出 = 风险降低折算
        s = self._sources()
        st = s["stu"].stats()
        students = st["total"]
        cost = students * 800.0
        risk_reduction = 0.32  # 演练后风险事件下降 32%
        value = students * 800.0 * 2.4
        return {
            "students": students,
            "training_cost": round(cost, 0),
            "estimated_value": round(value, 0),
            "roi": round((value - cost) / max(1, cost) * 100, 1),
            "risk_reduction_pct": risk_reduction * 100,
        }

    def student_behavior(self) -> Dict[str, Any]:
        s = self._sources()
        students = s["stu"].list_students()
        active = sum(1 for x in students if x["status"] == "活跃")
        churn = sum(1 for x in students if x["status"] == "已退学")
        return {
            "total": len(students),
            "active": active,
            "retention": round(active / max(1, len(students)) * 100, 1),
            "churn": churn,
        }

    def instructor_performance(self) -> Dict[str, Any]:
        s = self._sources()
        return s["ins"].stats()

    def phishing_analysis(self) -> Dict[str, Any]:
        s = self._sources()
        ps = s["phish"].stats()
        camps = s["phish"].list_campaigns()
        click_rates = []
        for c in camps:
            total = max(1, len(c["targets"]))
            clicked = sum(1 for e in c["events"]
                          if e["type"] == "clicked")
            click_rates.append(round(clicked / total * 100, 1))
        return {
            **ps,
            "avg_click_rate": round(
                sum(click_rates) / max(1, len(click_rates)), 1),
        }

    # ------------------------------------------------------------------ #
    def visualizations(self) -> Dict[str, Any]:
        return {
            "learning": self.learning_data(),
            "exam": self.exam_pass_rate(),
            "completion": self.course_completion(),
            "ability": self.ability_improvement(),
            "roi": self.roi_analysis(),
            "behavior": self.student_behavior(),
            "instructor": self.instructor_performance(),
            "phishing": self.phishing_analysis(),
        }

    def export_report(self) -> Dict[str, Any]:
        return {"report": self.visualizations(),
                "format": "json",
                "note": "可导出为 CSV / PDF（见报告生成模块）"}

    def stats(self) -> Dict[str, Any]:
        v = self.visualizations()
        return {"panels": list(v.keys()),
                "roi": v["roi"]["roi"],
                "pass_rate": v["exam"]["overall_pass_rate"]}


_default: Optional[DataAnalysisPhase] = None


def get_data_analysis_phase() -> DataAnalysisPhase:
    global _default
    if _default is None:
        _default = DataAnalysisPhase()
    return _default
