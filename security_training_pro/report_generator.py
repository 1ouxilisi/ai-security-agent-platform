# -*- coding: utf-8 -*-
"""
report_generator.py — 安全培训报告生成（MD/HTML）。

内容:
    - 执行摘要 / 培训概况 / 课程 / 学习 / 考试 / 能力
    - 钓鱼演练 / 讲师 / ROI / 改进建议 / 图表可视化
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "security_training_pro")


class ReportGenerator:
    """培训报告生成器。"""

    def __init__(self) -> None:
        os.makedirs(REPORTS_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    def collect_data(self) -> Dict[str, Any]:
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
        from .training_dashboard import get_dashboard

        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "course": get_course_management_phase().stats(),
            "path": get_learning_path_phase().stats(),
            "lab": get_lab_environment_phase().stats(),
            "exam": get_exam_system_phase().stats(),
            "phish": get_phishing_simulation_phase().stats(),
            "student": get_student_management_phase().stats(),
            "instructor": get_instructor_management_phase().stats(),
            "analysis": get_data_analysis_phase().visualizations(),
            "dashboard": get_dashboard().full_screen(),
        }

    # ------------------------------------------------------------------ #
    def to_markdown(self, data: Optional[Dict[str, Any]] = None
                    ) -> str:
        d = data or self.collect_data()
        c, e, s = d["course"], d["exam"], d["student"]
        p, ph, ins = d["path"], d["phish"], d["instructor"]
        a = d["analysis"]
        L = []
        L.append("# 安全培训专业报告")
        L.append("")
        L.append(f"- 生成时间：{d['generated_at']}")
        L.append("")
        L.append("## 1. 执行摘要")
        L.append("")
        L.append(f"- 学员总数：**{s['total']}**")
        L.append(f"- 课程总数：{c['total']}（已发布 {c['published']}）")
        L.append(f"- 题库：{e['question_total']} 题，试卷 {e['paper_total']} 份")
        L.append(f"- 平均通过率：{e['pass_rate']}%")
        L.append(f"- 颁发证书：{e['certificates']}")
        L.append(f"- 讲师：{ins['total']} 人，平均评分 {ins['avg_rating']}")
        L.append("")
        L.append("## 2. 课程分析")
        L.append("")
        for k, v in c["by_category"].items():
            L.append(f"- {k}: {v} 门")
        L.append("")
        L.append("## 3. 学习分析")
        L.append("")
        L.append(f"- 学习总时长（分钟）：{s['total_study_minutes']}")
        L.append(f"- 路径平均进度：{p['avg_progress']}%")
        L.append("")
        L.append("## 4. 考试分析")
        L.append("")
        L.append(f"- 已交卷：{e['submitted']}，平均分 {e['avg_score']}")
        L.append(f"- 通过率：{e['pass_rate']}%")
        L.append("")
        L.append("## 5. 能力分析")
        L.append("")
        for dname, score in sorted(a["ability"].get("domains", {}).items()):
            L.append(f"- {dname}: {score}")
        L.append("")
        L.append("## 6. 钓鱼演练分析")
        L.append("")
        L.append(f"- 演练活动：{ph['campaigns']}")
        L.append(f"- 点击事件：{ph['clicked']}，输入凭据：{ph['credentials']}")
        L.append("")
        L.append("## 7. 讲师分析")
        L.append("")
        L.append(f"- 讲师总数：{ins['total']}，总收益 {ins['total_revenue']}")
        L.append("")
        L.append("## 8. ROI 分析")
        L.append("")
        roi = a["roi"]
        L.append(f"- 培训投入：{roi['training_cost']}")
        L.append(f"- 估算价值：{roi['estimated_value']}")
        L.append(f"- ROI：**{roi['roi']}%**")
        L.append("")
        L.append("## 9. 改进建议")
        L.append("")
        L.append("1. 对通过率 <60% 的课程重做教学内容与习题")
        L.append("2. 钓鱼演练后对高风险用户 7 天内复测")
        L.append("3. 按能力短板自动推送补强学习路径")
        L.append("4. 引入实操自动评分，降低人工批改成本")
        L.append("")
        return "\n".join(L)

    # ------------------------------------------------------------------ #
    def to_html(self, md: str) -> str:
        import html as _h
        body = _h.escape(md)
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>安全培训专业报告</title>
<style>
body{{font-family:-apple-system,Segoe UI,Microsoft YaHei,sans-serif;
background:#0f1419;color:#e6e6e6;padding:32px;line-height:1.7;}}
pre{{white-space:pre-wrap;background:#1a2029;padding:20px;border-radius:8px;
border:1px solid #2a3441;}}
h1,h2{{color:#4fc3f7;}}
</style></head><body>
<pre>{body}</pre>
</body></html>"""

    # ------------------------------------------------------------------ #
    def generate(self, fmt: str = "both") -> Dict[str, Any]:
        data = self.collect_data()
        md = self.to_markdown(data)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        md_path = os.path.join(REPORTS_DIR, f"training_report_{ts}.md")
        html_path = os.path.join(REPORTS_DIR, f"training_report_{ts}.html")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        html = self.to_html(md)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return {"md_path": md_path, "html_path": html_path,
                "markdown": md, "html": html,
                "stats": {
                    "students": data["student"]["total"],
                    "courses": data["course"]["total"],
                    "pass_rate": data["exam"]["pass_rate"],
                    "roi": data["analysis"]["roi"]["roi"],
                }}


_default: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _default
    if _default is None:
        _default = ReportGenerator()
    return _default
