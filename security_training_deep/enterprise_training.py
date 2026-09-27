#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_training_deep/enterprise_training.py — 企业培训管理深度。

覆盖六大子域：
    1. 培训计划：年度计划/部门计划/季度排期/预算管理
    2. 培训执行：报名/签到/授课/记录/反馈收集
    3. 培训评估：柯氏四级评估/反应层/学习层/行为层/结果层
    4. 培训资源：讲师库/教材库/设备管理/外部资源
    5. 培训统计：覆盖率/完成率/参与率/学时统计/趋势
    6. 培训合规：合规要求/合规检查/合规报告/整改跟踪
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
PLAN_TYPES: Dict[str, str] = {
    "annual": "年度计划", "quarterly": "季度计划",
    "monthly": "月度计划", "ad_hoc": "临时计划",
}

TRAINING_STATUS: Dict[str, str] = {
    "planned": "已计划", "in_progress": "进行中",
    "completed": "已完成", "cancelled": "已取消",
}

COMPLIANCE_FRAMEWORKS: Dict[str, str] = {
    "iso27001": "ISO 27001",
    "soc2": "SOC 2",
    "pci_dss": "PCI DSS",
    "gdpr": "GDPR",
    "等保2.0": "等保2.0",
    " HIPAA": "HIPAA",
}


# --------------------------------------------------------------------------- #
# 培训计划
# --------------------------------------------------------------------------- #
class TrainingPlanManager:
    """培训计划：年度/季度/部门计划。"""

    def __init__(self) -> None:
        self.plans: Dict[str, Dict[str, Any]] = {}
        self._seed_default_plans()

    def _seed_default_plans(self) -> None:
        defaults = [
            ("2026年度安全培训总计划", "annual", "全公司", "完成全员安全意识培训与核心岗位技能培训。", 500000),
            ("Q3技术部门专项培训", "quarterly", "技术部", "面向研发团队的安全编码与SDL培训。", 80000),
            ("新员工入职安全培训", "monthly", "人力资源部", "每月新员工入职安全规范必修培训。", 20000),
        ]
        for name, ptype, dept, desc, budget in defaults:
            pid = f"plan_{uuid.uuid4().hex[:8]}"
            self.plans[pid] = {
                "id": pid, "name": name, "type": ptype,
                "department": dept, "description": desc,
                "budget": budget, "status": "planned",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "items": [],
            }

    def create_plan(self, name: str, ptype: str, department: str,
                    description: str = "", budget: float = 0) -> Dict[str, Any]:
        pid = f"plan_{uuid.uuid4().hex[:8]}"
        plan = {
            "id": pid, "name": name, "type": ptype,
            "department": department, "description": description,
            "budget": budget, "status": "planned",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "items": [],
        }
        self.plans[pid] = plan
        return plan

    def add_plan_item(self, plan_id: str, item_name: str, scheduled_date: str,
                      attendees: int) -> Optional[Dict[str, Any]]:
        p = self.plans.get(plan_id)
        if not p:
            return None
        item = {
            "id": f"pi_{uuid.uuid4().hex[:8]}",
            "name": item_name, "scheduled_date": scheduled_date,
            "expected_attendees": attendees, "status": "planned",
        }
        p["items"].append(item)
        return item

    def list_plans(self, department: str = "", ptype: str = "") -> List[Dict[str, Any]]:
        results = list(self.plans.values())
        if department:
            results = [p for p in results if p["department"] == department]
        if ptype:
            results = [p for p in results if p["type"] == ptype]
        return results

    def get_plan(self, plan_id: str) -> Optional[Dict[str, Any]]:
        return self.plans.get(plan_id)


# --------------------------------------------------------------------------- #
# 培训执行
# --------------------------------------------------------------------------- #
class TrainingExecution:
    """培训执行：报名/签到/记录/反馈。"""

    def __init__(self) -> None:
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.registrations: Dict[str, Dict[str, Any]] = {}
        self.feedbacks: List[Dict[str, Any]] = []

    def create_session(self, title: str, trainer: str, scheduled_date: str,
                       location: str = "线上", capacity: int = 50) -> Dict[str, Any]:
        sid = f"ses_{uuid.uuid4().hex[:8]}"
        session = {
            "id": sid, "title": title, "trainer": trainer,
            "scheduled_date": scheduled_date, "location": location,
            "capacity": capacity, "enrolled": 0,
            "status": "planned", "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.sessions[sid] = session
        return session

    def enroll(self, session_id: str, user: str, department: str = "") -> Optional[Dict[str, Any]]:
        s = self.sessions.get(session_id)
        if not s or s["enrolled"] >= s["capacity"]:
            return None
        rid = f"reg_{uuid.uuid4().hex[:8]}"
        reg = {
            "id": rid, "session_id": session_id, "user": user,
            "department": department, "status": "enrolled",
            "enrolled_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.registrations[rid] = reg
        s["enrolled"] += 1
        return reg

    def check_in(self, registration_id: str) -> Optional[Dict[str, Any]]:
        r = self.registrations.get(registration_id)
        if not r:
            return None
        r["status"] = "attended"
        r["checked_in_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return r

    def submit_feedback(self, session_id: str, user: str, rating: int,
                        comment: str = "") -> Dict[str, Any]:
        fb = {
            "id": f"fb_{uuid.uuid4().hex[:8]}",
            "session_id": session_id, "user": user,
            "rating": rating, "comment": comment,
            "submitted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.feedbacks.append(fb)
        return fb

    def list_sessions(self, status: str = "") -> List[Dict[str, Any]]:
        results = list(self.sessions.values())
        if status:
            results = [s for s in results if s["status"] == status]
        return results


# --------------------------------------------------------------------------- #
# 培训评估（柯氏四级）
# --------------------------------------------------------------------------- #
class TrainingEvaluator:
    """柯氏四级培训评估模型。"""

    def __init__(self, execution: TrainingExecution) -> None:
        self.execution = execution
        self.evaluations: Dict[str, Dict[str, Any]] = {}

    def level1_reaction(self, session_id: str) -> Dict[str, Any]:
        """反应层：学员满意度。"""
        s = self.execution.sessions.get(session_id)
        sfb = [f for f in self.execution.feedbacks if f["session_id"] == session_id]
        avg_rating = round(sum(f["rating"] for f in sfb) / max(1, len(sfb)), 2) if sfb else 0
        return {
            "session_id": session_id,
            "level": 1, "level_name": "反应层评估",
            "feedback_count": len(sfb),
            "avg_rating": avg_rating,
            "satisfaction_pct": round(avg_rating / 5 * 100, 1) if avg_rating else 0,
        }

    def level2_learning(self, session_id: str, pre_scores: List[int],
                        post_scores: List[int]) -> Dict[str, Any]:
        """学习层：知识掌握度提升。"""
        pre_avg = round(sum(pre_scores) / max(1, len(pre_scores)), 1) if pre_scores else 0
        post_avg = round(sum(post_scores) / max(1, len(post_scores)), 1) if post_scores else 0
        improvement = round(post_avg - pre_avg, 1)
        improvement_pct = round(improvement / max(1, pre_avg) * 100, 1) if pre_avg else 0
        return {
            "session_id": session_id,
            "level": 2, "level_name": "学习层评估",
            "pre_avg_score": pre_avg, "post_avg_score": post_avg,
            "improvement": improvement, "improvement_pct": improvement_pct,
        }

    def level3_behavior(self, session_id: str, observation_period_days: int = 30,
                        behavioral_changes: int = 0, total_observed: int = 0) -> Dict[str, Any]:
        """行为层：工作行为改变。"""
        behavior_pct = round(behavioral_changes / max(1, total_observed) * 100, 1) if total_observed else 0
        return {
            "session_id": session_id,
            "level": 3, "level_name": "行为层评估",
            "observation_days": observation_period_days,
            "behavioral_changes": behavioral_changes,
            "total_observed": total_observed,
            "behavior_change_pct": behavior_pct,
        }

    def level4_results(self, session_id: str, metrics: Dict[str, float]) -> Dict[str, Any]:
        """结果层：业务指标改善。"""
        return {
            "session_id": session_id,
            "level": 4, "level_name": "结果层评估",
            "metrics": metrics,
            "summary": "培训对业务指标的影响分析",
        }

    def full_evaluation(self, session_id: str) -> Dict[str, Any]:
        l1 = self.level1_reaction(session_id)
        return {
            "session_id": session_id,
            "evaluation_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "level1_reaction": l1,
            "overall_score": l1["avg_rating"],
        }


# --------------------------------------------------------------------------- #
# 培训资源
# --------------------------------------------------------------------------- #
class TrainingResourceManager:
    """培训资源：讲师/教材/设备。"""

    def __init__(self) -> None:
        self.instructors: Dict[str, Dict[str, Any]] = {}
        self.materials: Dict[str, Dict[str, Any]] = {}
        self.equipment: Dict[str, Dict[str, Any]] = {}
        self._seed_default_resources()

    def _seed_default_resources(self) -> None:
        instructors = [
            ("张安全", "首席讲师", ["Web安全", "渗透测试"], "10年"),
            ("李防御", "高级讲师", ["应急响应", "SIEM"], "8年"),
            ("王合规", "合规专家", ["ISO27001", "等保2.0"], "12年"),
        ]
        for name, title, skills, exp in instructors:
            iid = f"inst_{uuid.uuid4().hex[:8]}"
            self.instructors[iid] = {
                "id": iid, "name": name, "title": title,
                "skills": skills, "experience_years": exp,
                "hourly_rate": 2000,
            }

        materials = [
            ("Web安全基础教材", "textbook", "web_security"),
            ("应急响应手册", "handbook", "incident_response"),
            ("渗透测试工具集", "toolkit", "offensive"),
        ]
        for name, mtype, cat in materials:
            mid = f"mat_{uuid.uuid4().hex[:8]}"
            self.materials[mid] = {
                "id": mid, "name": name, "type": mtype,
                "category": cat, "version": "1.0",
            }

    def list_instructors(self, skill: str = "") -> List[Dict[str, Any]]:
        results = list(self.instructors.values())
        if skill:
            results = [i for i in results if skill in i["skills"]]
        return results

    def list_materials(self, category: str = "") -> List[Dict[str, Any]]:
        results = list(self.materials.values())
        if category:
            results = [m for m in results if m["category"] == category]
        return results


# --------------------------------------------------------------------------- #
# 培训统计
# --------------------------------------------------------------------------- #
class TrainingStatistics:
    """培训统计：覆盖率/完成率/参与率。"""

    def __init__(self, execution: TrainingExecution) -> None:
        self.execution = execution

    def coverage_stats(self, total_employees: int) -> Dict[str, Any]:
        sessions = list(self.execution.sessions.values())
        total_enrolled = sum(s["enrolled"] for s in sessions)
        covered = len({r["user"] for r in self.execution.registrations.values()})
        coverage_pct = round(covered / max(1, total_employees) * 100, 1)
        return {
            "total_employees": total_employees,
            "covered_employees": covered,
            "coverage_pct": coverage_pct,
            "total_sessions": len(sessions),
            "total_enrollments": total_enrolled,
        }

    def completion_stats(self) -> Dict[str, Any]:
        regs = list(self.execution.registrations.values())
        total = len(regs)
        completed = len([r for r in regs if r["status"] == "attended"])
        completion_pct = round(completed / max(1, total) * 100, 1)
        return {
            "total_enrollments": total,
            "completed": completed,
            "not_completed": total - completed,
            "completion_pct": completion_pct,
        }

    def attendance_by_department(self) -> Dict[str, int]:
        dept_counts: Dict[str, int] = {}
        for r in self.execution.registrations.values():
            dept = r.get("department", "未分配")
            dept_counts[dept] = dept_counts.get(dept, 0) + 1
        return dept_counts


# --------------------------------------------------------------------------- #
# 培训合规
# --------------------------------------------------------------------------- #
class TrainingCompliance:
    """培训合规：合规要求/检查/报告。"""

    def __init__(self) -> None:
        self.compliance_requirements: Dict[str, List[Dict[str, Any]]] = {
            "iso27001": [
                {"requirement": "全员安全意识培训", "frequency": "每年", "mandatory": True},
                {"requirement": "管理层安全培训", "frequency": "每年", "mandatory": True},
            ],
            "pci_dss": [
                {"requirement": "支付卡安全培训", "frequency": "每年", "mandatory": True},
                {"requirement": "开发人员安全编码培训", "frequency": "每年", "mandatory": True},
            ],
            "等保2.0": [
                {"requirement": "网络安全法培训", "frequency": "每年", "mandatory": True},
                {"requirement": "安全操作规范培训", "frequency": "每半年", "mandatory": True},
            ],
        }
        self.compliance_checks: List[Dict[str, Any]] = []

    def get_requirements(self, framework: str = "") -> Dict[str, Any]:
        if framework:
            return {framework: self.compliance_requirements.get(framework, [])}
        return self.compliance_requirements

    def run_compliance_check(self, framework: str, employees_trained: int,
                             total_employees: int) -> Dict[str, Any]:
        coverage_pct = round(employees_trained / max(1, total_employees) * 100, 1)
        reqs = self.compliance_requirements.get(framework, [])
        mandatory_met = all(coverage_pct >= 90 for _ in reqs) if reqs else False
        check = {
            "id": f"comp_{uuid.uuid4().hex[:8]}",
            "framework": framework,
            "check_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "coverage_pct": coverage_pct,
            "requirements_count": len(reqs),
            "compliant": coverage_pct >= 90,
            "gaps": [r for r in reqs] if coverage_pct < 90 else [],
        }
        self.compliance_checks.append(check)
        return check

    def compliance_report(self) -> Dict[str, Any]:
        return {
            "total_checks": len(self.compliance_checks),
            "frameworks_covered": len(self.compliance_requirements),
            "recent_checks": self.compliance_checks[-5:],
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_plan_mgr: Optional[TrainingPlanManager] = None
_execution: Optional[TrainingExecution] = None
_evaluator: Optional[TrainingEvaluator] = None
_resource_mgr: Optional[TrainingResourceManager] = None
_statistics: Optional[TrainingStatistics] = None
_compliance: Optional[TrainingCompliance] = None


def get_plan_manager() -> TrainingPlanManager:
    global _plan_mgr
    if _plan_mgr is None:
        _plan_mgr = TrainingPlanManager()
    return _plan_mgr


def get_training_execution() -> TrainingExecution:
    global _execution
    if _execution is None:
        _execution = TrainingExecution()
    return _execution


def get_training_evaluator() -> TrainingEvaluator:
    global _evaluator
    if _evaluator is None:
        _evaluator = TrainingEvaluator(get_training_execution())
    return _evaluator


def get_resource_manager() -> TrainingResourceManager:
    global _resource_mgr
    if _resource_mgr is None:
        _resource_mgr = TrainingResourceManager()
    return _resource_mgr


def get_training_statistics() -> TrainingStatistics:
    global _statistics
    if _statistics is None:
        _statistics = TrainingStatistics(get_training_execution())
    return _statistics


def get_training_compliance() -> TrainingCompliance:
    global _compliance
    if _compliance is None:
        _compliance = TrainingCompliance()
    return _compliance
