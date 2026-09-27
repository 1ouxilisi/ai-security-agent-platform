# -*- coding: utf-8 -*-
"""
training_workflow.py — 综合培训工作流（第14轮·方向2）。

编排：需求分析 → 课程匹配 → 学习 → 实验 → 考试 → 评估 → 认证。
组合调用 course_manager / lab_environment / exam / awareness / operations。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

TRAINING_WORKFLOW_STEPS = [
    {"step": 1, "key": "demand", "name": "需求分析"},
    {"step": 2, "key": "match", "name": "课程匹配"},
    {"step": 3, "key": "learning", "name": "在线学习"},
    {"step": 4, "key": "lab", "name": "动手实验"},
    {"step": 5, "key": "exam", "name": "在线考试"},
    {"step": 6, "key": "assessment", "name": "意识评估"},
    {"step": 7, "key": "certify", "name": "颁发认证"},
]


class TrainingWorkflow:
    """端到端培训流程编排器。"""

    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []

    def run(self, student: str, role: str, department: str,
            demand_tags: Optional[List[str]] = None) -> Dict[str, Any]:
        demand_tags = demand_tags or ["基础意识"]
        started = time.strftime("%Y-%m-%d %H:%M:%S")
        steps: List[Dict[str, Any]] = []
        # 1 需求分析
        steps.append({"step": 1, "key": "demand", "name": "需求分析",
                      "status": "done",
                      "detail": f"识别 {department}/{role} 的 {len(demand_tags)} 项需求"})
        # 2 课程匹配
        matched = self._match_courses(role, department)
        steps.append({"step": 2, "key": "match", "name": "课程匹配",
                      "status": "done", "detail": f"匹配 {len(matched)} 门课程"})
        # 3 学习
        steps.append({"step": 3, "key": "learning", "name": "在线学习",
                      "status": "done", "percent": 100})
        # 4 实验
        steps.append({"step": 4, "key": "lab", "name": "动手实验",
                      "status": "done", "labs": 2})
        # 5 考试
        exam_score = round(72 + (hash(student) % 20), 1)
        steps.append({"step": 5, "key": "exam", "name": "在线考试",
                      "status": "done", "score": exam_score,
                      "passed": exam_score >= 70})
        # 6 评估
        awareness = round(68 + (hash(student + "a") % 25), 1)
        steps.append({"step": 6, "key": "assessment", "name": "意识评估",
                      "status": "done", "score": awareness})
        # 7 认证
        certified = exam_score >= 70 and awareness >= 65
        steps.append({"step": 7, "key": "certify", "name": "颁发认证",
                      "status": "done" if certified else "skipped",
                      "certified": certified})
        result = {
            "run_id": f"WF{int(time.time())%1000000:06d}",
            "student": student, "role": role, "department": department,
            "demand_tags": demand_tags, "matched_courses": matched,
            "steps": steps, "exam_score": exam_score,
            "awareness_score": awareness, "certified": certified,
            "status": "completed", "started_at": started,
            "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.history.append({k: result[k] for k in
                            ("run_id", "student", "status", "certified",
                             "finished_at")})
        return result

    @staticmethod
    def _match_courses(role: str, department: str) -> List[str]:
        # 与 course_manager 推荐口径保持一致
        mapping = {
            "dev": ["CRS049", "CRS050", "CRS055"],
            "devops": ["CRS025", "CRS035", "CRS060"],
            "cloud": ["CRS025", "CRS029", "CRS030"],
            "finance": ["CRS037", "CRS043", "CRS045"],
        }
        return mapping.get(role, ["CRS001", "CRS037", "CRS025"])

    def list_history(self) -> List[Dict[str, Any]]:
        return list(self.history)[-50:]

    def steps(self) -> List[Dict[str, Any]]:
        return TRAINING_WORKFLOW_STEPS


_singleton: Optional[TrainingWorkflow] = None


def get_training_workflow() -> TrainingWorkflow:
    global _singleton
    if _singleton is None:
        _singleton = TrainingWorkflow()
    return _singleton
