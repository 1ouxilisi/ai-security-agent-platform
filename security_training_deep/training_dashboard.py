#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_training_deep/training_dashboard.py — 安全培训深度控制台数据聚合层。

聚合7大模块数据，提供统一的仪表盘视角：
    - 培训总览：课程/实验/考试/认证/意识 全局统计
    - 课程概览：课程数量/分类分布/评分统计
    - 实验概览：实验数量/靶场状态/完成率
    - 考试认证概览：考试场次/通过率/证书发放
    - 能力评估概览：评估人数/平均水平/差距分布
    - 企业培训概览：计划完成率/覆盖率/合规状态
    - 安全意识概览：钓鱼点击趋势/参与度
    - 系统设置：参数配置
"""

from __future__ import annotations

import time
from typing import Any, Dict


# --------------------------------------------------------------------------- #
# 系统设置
# --------------------------------------------------------------------------- #
SYSTEM_SETTINGS: Dict[str, Any] = {
    "platform_name": "安全培训与认证深度平台",
    "default_pass_score": 60,
    "certificate_validity_days": 365,
    "phishing_simulation_enabled": True,
    "max_lab_runtime_minutes": 120,
    "auto_backup_enabled": True,
    "notification_channels": ["email", "sms", "webhook"],
    "supported_languages": ["zh-CN", "en-US"],
    "branding": {
        "primary_color": "#58a6ff",
        "dark_mode": True,
    },
}


# --------------------------------------------------------------------------- #
# 仪表盘聚合层
# --------------------------------------------------------------------------- #
class TrainingDashboard:
    """安全培训深度控制台数据聚合层。"""

    def __init__(self) -> None:
        self.settings = SYSTEM_SETTINGS.copy()

    # ------------------------------------------------------------------ #
    # 总览
    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        from security_training_deep.course_system import get_course_manager
        from security_training_deep.lab_environment import get_lab_manager, get_range_env
        from security_training_deep.exam_certification import (
            get_exam_manager, get_certificate_manager, get_question_bank,
        )
        from security_training_deep.competency_assessment import get_assessor
        from security_training_deep.enterprise_training import (
            get_plan_manager, get_training_execution, get_training_compliance,
        )
        from security_training_deep.security_awareness import (
            get_awareness_course, get_phishing_simulation, get_awareness_activity,
        )

        cm = get_course_manager()
        lm = get_lab_manager()
        re = get_range_env()
        em = get_exam_manager()
        cbm = get_certificate_manager()
        qb = get_question_bank()
        assessor = get_assessor()
        pm = get_plan_manager()
        te = get_training_execution()
        comp = get_training_compliance()
        awc = get_awareness_course()
        phish = get_phishing_simulation()
        act = get_awareness_activity()

        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "course_stats": {
                "total_courses": len(cm.courses),
                "published": len(cm.list_courses(status="published")),
                "categories": len(set(c["category"] for c in cm.courses.values())),
            },
            "lab_stats": {
                "total_labs": len(lm.labs),
                "total_assignments": len(lm.assignments),
                "active_ranges": len(re.list_ranges(status="running")),
                "total_ranges": len(re.ranges),
            },
            "exam_stats": {
                "total_exams": len(em.exams),
                "published_exams": len(em.list_exams(status="published")),
                "total_questions": len(qb.questions),
                "total_certificates": len(cbm.certificates),
            },
            "competency_stats": {
                "users_assessed": len(assessor.user_skills),
                "total_assessments": len(assessor.assessments),
            },
            "enterprise_stats": {
                "total_plans": len(pm.plans),
                "total_sessions": len(te.sessions),
                "total_registrations": len(te.registrations),
                "compliance_frameworks": len(comp.compliance_requirements),
            },
            "awareness_stats": {
                "awareness_courses": len(awc.courses),
                "phishing_campaigns": len(phish.campaigns),
                "awareness_activities": len(act.activities),
            },
        }

    # ------------------------------------------------------------------ #
    # 课程概览
    # ------------------------------------------------------------------ #
    def course_overview(self) -> Dict[str, Any]:
        from security_training_deep.course_system import (
            get_course_manager, get_path_manager, get_template_manager,
            get_quality_manager, get_recommender, COURSE_CATEGORIES,
        )
        cm = get_course_manager()
        pm = get_path_manager()
        tm = get_template_manager()
        qm = get_quality_manager()
        rec = get_recommender()

        by_category: Dict[str, int] = {}
        for c in cm.courses.values():
            by_category[c["category"]] = by_category.get(c["category"], 0) + 1

        return {
            "total_courses": len(cm.courses),
            "by_category": by_category,
            "category_names": COURSE_CATEGORIES,
            "learning_paths": len(pm.paths),
            "course_templates": len(tm.templates),
            "quality_report": qm.quality_report(),
            "total_recommendation_profiles": len(rec.user_history),
        }

    # ------------------------------------------------------------------ #
    # 实验概览
    # ------------------------------------------------------------------ #
    def lab_overview(self) -> Dict[str, Any]:
        from security_training_deep.lab_environment import (
            get_lab_manager, get_range_env, get_env_manager,
            get_lab_evaluator, get_lab_sandbox,
        )
        lm = get_lab_manager()
        re = get_range_env()
        em = get_env_manager()
        le = get_lab_evaluator()
        sb = get_lab_sandbox()

        by_diff: Dict[str, int] = {}
        for l in lm.labs.values():
            by_diff[l["difficulty"]] = by_diff.get(l["difficulty"], 0) + 1

        return {
            "total_labs": len(lm.labs),
            "total_assignments": len(lm.assignments),
            "graded_assignments": len(le.evaluations),
            "by_difficulty": by_diff,
            "ranges": {
                "total": len(re.ranges),
                "running": len(re.list_ranges(status="running")),
                "stopped": len(re.list_ranges(status="stopped")),
            },
            "resource_pool": em.get_resource_status(),
            "active_sandboxes": len(sb.sandboxes),
            "execution_logs": len(sb.execution_logs),
        }

    # ------------------------------------------------------------------ #
    # 考试认证概览
    # ------------------------------------------------------------------ #
    def exam_overview(self) -> Dict[str, Any]:
        from security_training_deep.exam_certification import (
            get_question_bank, get_exam_manager, get_exam_executor,
            get_certificate_manager, get_certification_system, QUESTION_TYPES,
        )
        qb = get_question_bank()
        em = get_exam_manager()
        ex = get_exam_executor()
        cm = get_certificate_manager()
        cs = get_certification_system()

        by_type: Dict[str, int] = {}
        for q in qb.questions.values():
            by_type[q["type"]] = by_type.get(q["type"], 0) + 1

        return {
            "total_questions": len(qb.questions),
            "by_type": by_type,
            "type_names": QUESTION_TYPES,
            "total_exams": len(em.exams),
            "total_attempts": len(ex.attempts),
            "total_certificates": len(cm.certificates),
            "cert_paths": len(cs.cert_paths),
            "user_credits_tracked": len(cs.user_credits),
        }

    # ------------------------------------------------------------------ #
    # 能力评估概览
    # ------------------------------------------------------------------ #
    def competency_overview(self) -> Dict[str, Any]:
        from security_training_deep.competency_assessment import (
            get_competency_model, get_assessor, get_development,
            get_badge, get_report,
        )
        model = get_competency_model()
        assessor = get_assessor()
        dev = get_development()
        badge = get_badge()
        report = get_report()

        total_skills = 0
        skill_count = 0
        for skills in assessor.user_skills.values():
            total_skills += sum(skills.values())
            skill_count += len(skills)
        avg_level = round(total_skills / max(1, skill_count), 1)

        return {
            "users_assessed": len(assessor.user_skills),
            "total_assessments": len(assessor.assessments),
            "average_skill_level": avg_level,
            "skill_domains": len(model.skill_domains),
            "roles_defined": len(model.role_requirements),
            "development_plans": len(dev.development_plans),
            "total_badges": len(badge.badges),
        }

    # ------------------------------------------------------------------ #
    # 企业培训概览
    # ------------------------------------------------------------------ #
    def enterprise_overview(self) -> Dict[str, Any]:
        from security_training_deep.enterprise_training import (
            get_plan_manager, get_training_execution, get_training_evaluator,
            get_resource_manager, get_training_statistics, get_training_compliance,
        )
        pm = get_plan_manager()
        te = get_training_execution()
        ev = get_training_evaluator()
        rm = get_resource_manager()
        ts = get_training_statistics()
        comp = get_training_compliance()

        return {
            "total_plans": len(pm.plans),
            "total_sessions": len(te.sessions),
            "total_registrations": len(te.registrations),
            "total_feedbacks": len(te.feedbacks),
            "instructors": len(rm.instructors),
            "materials": len(rm.materials),
            "completion_stats": ts.completion_stats(),
            "compliance_frameworks": len(comp.compliance_requirements),
            "compliance_checks": len(comp.compliance_checks),
        }

    # ------------------------------------------------------------------ #
    # 安全意识概览
    # ------------------------------------------------------------------ #
    def awareness_overview(self) -> Dict[str, Any]:
        from security_training_deep.security_awareness import (
            get_awareness_course, get_phishing_simulation, get_awareness_activity,
            get_awareness_material, get_awareness_metrics, get_awareness_culture,
        )
        awc = get_awareness_course()
        phish = get_phishing_simulation()
        act = get_awareness_activity()
        mat = get_awareness_material()
        metrics = get_awareness_metrics()
        culture = get_awareness_culture()

        return {
            "awareness_courses": len(awc.courses),
            "phishing_campaigns": len(phish.campaigns),
            "total_phish_logs": len(phish.click_logs),
            "awareness_activities": len(act.activities),
            "awareness_materials": len(mat.materials),
            "culture_initiatives": len(culture.initiatives),
            "awareness_score": metrics.awareness_score(),
        }

    # ------------------------------------------------------------------ #
    # 系统设置
    # ------------------------------------------------------------------ #
    def get_settings(self) -> Dict[str, Any]:
        return self.settings.copy()

    def update_settings(self, data: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in data.items():
            if k in self.settings:
                if isinstance(self.settings[k], dict) and isinstance(v, dict):
                    self.settings[k].update(v)
                else:
                    self.settings[k] = v
        return self.settings


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_dashboard: Optional[TrainingDashboard] = None


def get_training_dashboard() -> TrainingDashboard:
    global _dashboard
    if _dashboard is None:
        _dashboard = TrainingDashboard()
    return _dashboard
