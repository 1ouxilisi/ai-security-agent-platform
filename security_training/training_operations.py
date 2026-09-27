# -*- coding: utf-8 -*-
"""
training_operations.py — 培训运营管理（第14轮·方向2）。

学员管理、讲师管理、班级管理、学习记录、培训计划、
柯氏四级评估（反应/学习/行为/结果）、ROI 分析、综合仪表盘。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


class TrainingOperations:
    """培训运营中心。"""

    def __init__(self) -> None:
        self.students: Dict[str, Dict[str, Any]] = {}
        self.instructors: Dict[str, Dict[str, Any]] = {}
        self.classes: Dict[str, Dict[str, Any]] = {}
        self.records: List[Dict[str, Any]] = []
        self.plans: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self) -> None:
        for i in range(1, 31):
            sid = f"EMP{i:04d}"
            self.students[sid] = {
                "student_id": sid, "name": f"员工{i}",
                "department": ["研发部", "财务部", "人事部",
                               "市场部"][i % 4],
                "level": ["初级", "中级", "高级"][i % 3],
                "enrolled_at": f"2026-{i % 9 + 1:02d}-01",
                "status": "active",
            }
        for i in range(1, 6):
            self.instructors[f"INS{i:02d}"] = {
                "instructor_id": f"INS{i:02d}", "name": f"讲师{i}",
                "topic": ["网络安全", "云安全", "合规", "社会工程", "开发安全"][i - 1],
                "rating": round(4.2 + (i % 3) * 0.2, 1), "courses": i * 2,
            }

    # ---- 学员 ----
    def list_students(self, department: Optional[str] = None) -> Dict[str, Any]:
        rows = list(self.students.values())
        if department:
            rows = [s for s in rows if s["department"] == department]
        return {"students": rows, "total": len(rows)}

    # ---- 讲师 ----
    def list_instructors(self) -> Dict[str, Any]:
        rows = list(self.instructors.values())
        return {"instructors": rows, "total": len(rows)}

    # ---- 班级 ----
    def create_class(self, name: str, instructor_id: str,
                     student_ids: List[str], course_id: str) -> Dict[str, Any]:
        cid = f"CLS{int(time.time())%1000000:06d}"
        self.classes[cid] = {
            "class_id": cid, "name": name, "instructor_id": instructor_id,
            "course_id": course_id, "students": student_ids,
            "size": len(student_ids), "status": "open",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"ok": True, "class": self.classes[cid]}

    def list_classes(self) -> Dict[str, Any]:
        rows = list(self.classes.values())
        return {"classes": rows, "total": len(rows)}

    # ---- 学习记录 ----
    def log_record(self, student_id: str, action: str,
                   detail: str) -> Dict[str, Any]:
        rec = {"record_id": f"R{len(self.records)+1:05d}",
               "student_id": student_id, "action": action, "detail": detail,
               "at": time.strftime("%Y-%m-%d %H:%M:%S")}
        self.records.append(rec)
        return {"ok": True, "record": rec}

    def learning_records(self, student_id: Optional[str] = None) -> Dict[str, Any]:
        rows = self.records
        if student_id:
            rows = [r for r in rows if r["student_id"] == student_id]
        return {"records": rows[-200:], "total": len(rows)}

    # ---- 培训计划 ----
    def create_plan(self, name: str, target: str,
                    start: str, end: str,
                    courses: List[str]) -> Dict[str, Any]:
        pid = f"PL{int(time.time())%1000000:06d}"
        self.plans[pid] = {"plan_id": pid, "name": name, "target": target,
                           "start": start, "end": end, "courses": courses,
                           "course_count": len(courses),
                           "status": "planned",
                           "progress": round((len(courses) % 5) * 20, 1)}
        return {"ok": True, "plan": self.plans[pid]}

    def list_plans(self) -> Dict[str, Any]:
        return {"plans": list(self.plans.values()), "total": len(self.plans)}

    # ---- 柯氏四级评估 ----
    def kirkpatrick_evaluation(self, class_id: str) -> Dict[str, Any]:
        c = self.classes.get(class_id, {"size": 20, "name": "默认班"})
        n = c.get("size", 20)
        return {
            "class_id": class_id, "class_name": c.get("name"),
            "level1_reaction": {
                "name": "L1 反应层（学员满意度）",
                "score": round(4.3 + (n % 5) * 0.1, 1), "scale": 5.0,
                "sample": n},
            "level2_learning": {
                "name": "L2 学习层（考试提升）",
                "pre_avg": 60 + (n % 10), "post_avg": 78 + (n % 8),
                "delta": 18 + (n % 7)},
            "level3_behavior": {
                "name": "L3 行为层（岗位行为改变率）",
                "rate_pct": round(55 + (n % 25), 1)},
            "level4_results": {
                "name": "L4 结果层（业务指标）",
                "incident_reduction_pct": round(20 + (n % 30), 1),
                "phishing_click_drop_pct": round(15 + (n % 25), 1)},
        }

    # ---- ROI ----
    def roi_analysis(self, cost: float = 0.0,
                     avoided_loss: float = 0.0) -> Dict[str, Any]:
        cost = cost or 120000.0          # 年度培训投入
        avoided = avoided_loss or 380000.0  # 避免的损失
        roi = round((avoided - cost) / cost * 100, 1)
        return {"investment": cost, "avoided_loss": avoided, "roi_pct": roi,
                "assumption": "基于历史演练：事故平均损失 × 预期下降比例",
                "note": "ROI 为估算，仅供管理层决策参考"}

    # ---- 综合仪表盘 ----
    def dashboard(self) -> Dict[str, Any]:
        active_classes = [c for c in self.classes.values()
                          if c["status"] == "open"]
        return {
            "students": len(self.students),
            "instructors": len(self.instructors),
            "open_classes": len(active_classes),
            "plans": len(self.plans),
            "learning_records": len(self.records),
            "avg_instructor_rating": round(
                sum(i["rating"] for i in self.instructors.values()) /
                max(1, len(self.instructors)), 2),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
