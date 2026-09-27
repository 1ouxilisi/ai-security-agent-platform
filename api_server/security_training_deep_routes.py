# -*- coding: utf-8 -*-
"""
security_training_deep_routes.py — 第26轮升级方向4：安全培训与认证平台深度 REST API（60+端点）。

路由前缀: /api/v1/security-training-deep
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/security-training-deep", tags=["安全培训深度平台"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from security_training_deep.course_system import (
        get_course_manager, get_content_manager, get_path_manager,
        get_template_manager, get_quality_manager, get_recommender,
        COURSE_LEVELS, COURSE_STATUS, COURSE_CATEGORIES, COURSE_TYPES,
    )
    from security_training_deep.lab_environment import (
        get_lab_manager, get_range_env, get_env_manager,
        get_lab_guide, get_lab_evaluator, get_lab_sandbox,
        LAB_DIFFICULTY, LAB_STATUS, LAB_CATEGORIES,
    )
    from security_training_deep.exam_certification import (
        get_question_bank, get_exam_manager, get_exam_executor,
        get_exam_grader, get_certificate_manager, get_certification_system,
        QUESTION_TYPES, EXAM_STATUS, CERT_LEVELS, PASS_SCORE,
    )
    from security_training_deep.competency_assessment import (
        get_competency_model, get_assessor, get_gap_analyzer,
        get_development, get_badge, get_report,
        SKILL_DOMAINS, SKILL_LEVELS, ROLE_COMPETENCY,
    )
    from security_training_deep.enterprise_training import (
        get_plan_manager, get_training_execution, get_training_evaluator,
        get_resource_manager, get_training_statistics, get_training_compliance,
        PLAN_TYPES, TRAINING_STATUS,
    )
    from security_training_deep.security_awareness import (
        get_awareness_course, get_phishing_simulation, get_awareness_activity,
        get_awareness_material, get_awareness_metrics, get_awareness_culture,
        AWARENESS_TOPICS, ACTIVITY_TYPES,
    )
    from security_training_deep.training_dashboard import (
        get_training_dashboard, SYSTEM_SETTINGS,
    )
    _MOD_AVAILABLE = True
    logger.info("security_training_deep_routes: modules loaded OK")
except Exception as e:
    logger.exception("security_training_deep_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from security_training_deep.course_system import (  # noqa
            get_course_manager, get_content_manager, get_path_manager,
            get_template_manager, get_quality_manager, get_recommender,
            COURSE_LEVELS, COURSE_STATUS, COURSE_CATEGORIES, COURSE_TYPES,
        )
        from security_training_deep.lab_environment import (  # noqa
            get_lab_manager, get_range_env, get_env_manager,
            get_lab_guide, get_lab_evaluator, get_lab_sandbox,
            LAB_DIFFICULTY, LAB_STATUS, LAB_CATEGORIES,
        )
        from security_training_deep.exam_certification import (  # noqa
            get_question_bank, get_exam_manager, get_exam_executor,
            get_exam_grader, get_certificate_manager, get_certification_system,
            QUESTION_TYPES, EXAM_STATUS, CERT_LEVELS, PASS_SCORE,
        )
        from security_training_deep.competency_assessment import (  # noqa
            get_competency_model, get_assessor, get_gap_analyzer,
            get_development, get_badge, get_report,
            SKILL_DOMAINS, SKILL_LEVELS, ROLE_COMPETENCY,
        )
        from security_training_deep.enterprise_training import (  # noqa
            get_plan_manager, get_training_execution, get_training_evaluator,
            get_resource_manager, get_training_statistics, get_training_compliance,
            PLAN_TYPES, TRAINING_STATUS,
        )
        from security_training_deep.security_awareness import (  # noqa
            get_awareness_course, get_phishing_simulation, get_awareness_activity,
            get_awareness_material, get_awareness_metrics, get_awareness_culture,
            AWARENESS_TOPICS, ACTIVITY_TYPES,
        )
        from security_training_deep.training_dashboard import (  # noqa
            get_training_dashboard, SYSTEM_SETTINGS,
        )
        _MOD_AVAILABLE = True
        logger.info("security_training_deep_routes: fallback import OK")
    except Exception as e2:
        logger.exception("security_training_deep_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 任务存储
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = uuid.uuid4().hex[:16]
    TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish_task(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in TASKS:
        t = TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        chars = [c for c in obj if ord(c) >= 32 or c in ("\t", "\n", "\r")]
        s = "".join(chars)
        return s.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def err(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": msg}, status_code=code)


# --------------------------------------------------------------------------- #
# Pydantic 模型
# --------------------------------------------------------------------------- #
class CourseCreate(BaseModel):
    title: str = "未命名课程"
    category: str = "web_security"
    level: str = "beginner"
    type: str = "video"
    description: str = ""
    tags: List[str] = Field(default_factory=list)
    instructor: str = ""
    duration_minutes: int = 30


class CourseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    level: Optional[str] = None
    tags: Optional[List[str]] = None
    instructor: Optional[str] = None


class ChapterCreate(BaseModel):
    title: str
    description: str = ""


class SectionCreate(BaseModel):
    title: str
    content_type: str = "text"
    content: str = ""


class ReviewCreate(BaseModel):
    user: str = "匿名"
    rating: int = 5
    comment: str = ""


class LabCreate(BaseModel):
    title: str = "未命名实验"
    category: str = "web_pentest"
    difficulty: str = "medium"
    description: str = ""
    duration_minutes: int = 45


class AssignmentSubmit(BaseModel):
    answer: str = ""


class RangeCreate(BaseModel):
    name: str
    type: str = "vulnerable"
    image: str = ""


class QuestionCreate(BaseModel):
    question: str
    type: str = "single_choice"
    category: str = "web_security"
    difficulty: str = "medium"
    options: List[str] = Field(default_factory=list)
    answer_index: int = 0
    explanation: str = ""
    score: int = 5


class ExamCreate(BaseModel):
    title: str
    description: str = ""
    duration_minutes: int = 60
    question_ids: List[str] = Field(default_factory=list)
    passing_score: int = PASS_SCORE


class AnswerSubmit(BaseModel):
    answer: Any = None


class CertGenerate(BaseModel):
    user: str
    cert_name: str
    cert_level: str = "associate"
    score: float = 80.0
    expiry_days: int = 365


class SelfAssess(BaseModel):
    user: str
    skills: Dict[str, int] = Field(default_factory=dict)


class GapAnalyze(BaseModel):
    user: str
    target_role: str


class BadgeAward(BaseModel):
    user: str
    skill: str
    level: int = 3


class PlanCreate(BaseModel):
    name: str
    type: str = "quarterly"
    department: str = "全公司"
    description: str = ""
    budget: float = 0


class SessionCreate(BaseModel):
    title: str
    trainer: str
    scheduled_date: str = ""
    location: str = "线上"
    capacity: int = 50


class EnrollRequest(BaseModel):
    user: str
    department: str = ""


class FeedbackSubmit(BaseModel):
    user: str
    rating: int = 5
    comment: str = ""


class PhishingCampaignCreate(BaseModel):
    name: str
    target_users: List[str] = Field(default_factory=list)
    template: str = "urgent_login"


class PhishAction(BaseModel):
    user: str


class ActivityCreate(BaseModel):
    name: str
    type: str = "awareness_month"
    description: str = ""
    scheduled_date: str = ""


class ComplianceCheck(BaseModel):
    framework: str = "iso27001"
    employees_trained: int = 0
    total_employees: int = 100


class SettingsUpdate(BaseModel):
    data: Dict[str, Any] = Field(default_factory=dict)


# =========================================================================== #
# 1. 课程体系 API
# =========================================================================== #

@router.get("/courses")
def list_courses(category: str = Query(""), level: str = Query(""),
                 status: str = Query(""), keyword: str = Query("")):
    try:
        cm = get_course_manager()
        return ok(cm.list_courses(category=category, level=level, status=status, keyword=keyword))
    except Exception as e:
        return err(str(e))


@router.post("/courses")
def create_course(body: CourseCreate):
    try:
        cm = get_course_manager()
        return ok(cm.create_course(body.model_dump()))
    except Exception as e:
        return err(str(e))


@router.get("/courses/{course_id}")
def get_course(course_id: str):
    try:
        cm = get_course_manager()
        c = cm.get_course(course_id)
        if not c:
            return err("课程不存在", 404)
        return ok(c)
    except Exception as e:
        return err(str(e))


@router.put("/courses/{course_id}")
def update_course(course_id: str, body: CourseUpdate):
    try:
        cm = get_course_manager()
        c = cm.update_course(course_id, body.model_dump(exclude_none=True))
        if not c:
            return err("课程不存在", 404)
        return ok(c)
    except Exception as e:
        return err(str(e))


@router.delete("/courses/{course_id}")
def delete_course(course_id: str):
    try:
        cm = get_course_manager()
        if not cm.delete_course(course_id):
            return err("课程不存在", 404)
        return ok({"deleted": True, "id": course_id})
    except Exception as e:
        return err(str(e))


@router.put("/courses/{course_id}/status")
def change_course_status(course_id: str, status: str = Query(...)):
    try:
        cm = get_course_manager()
        c = cm.change_status(course_id, status)
        if not c:
            return err("课程或状态无效", 404)
        return ok(c)
    except Exception as e:
        return err(str(e))


@router.post("/courses/{course_id}/chapters")
def add_chapter(course_id: str, body: ChapterCreate):
    try:
        content = get_content_manager()
        ch = content.add_chapter(course_id, body.title, body.description)
        if not ch:
            return err("课程不存在", 404)
        return ok(ch)
    except Exception as e:
        return err(str(e))


@router.post("/courses/{course_id}/chapters/{chapter_id}/sections")
def add_section(course_id: str, chapter_id: str, body: SectionCreate):
    try:
        content = get_content_manager()
        sec = content.add_section(course_id, chapter_id, body.title, body.content_type, body.content)
        if not sec:
            return err("章节或课程不存在", 404)
        return ok(sec)
    except Exception as e:
        return err(str(e))


@router.get("/courses/{course_id}/outline")
def get_course_outline(course_id: str):
    try:
        content = get_content_manager()
        outline = content.get_course_outline(course_id)
        if not outline:
            return err("课程不存在", 404)
        return ok(outline)
    except Exception as e:
        return err(str(e))


@router.post("/courses/{course_id}/reviews")
def add_review(course_id: str, body: ReviewCreate):
    try:
        qm = get_quality_manager()
        r = qm.add_review(course_id, body.user, body.rating, body.comment)
        if not r:
            return err("课程不存在或评分无效", 400)
        return ok(r)
    except Exception as e:
        return err(str(e))


@router.get("/courses/{course_id}/reviews")
def get_reviews(course_id: str):
    try:
        qm = get_quality_manager()
        return ok(qm.get_reviews(course_id))
    except Exception as e:
        return err(str(e))


@router.get("/learning-paths")
def list_learning_paths(role: str = Query("")):
    try:
        pm = get_path_manager()
        return ok(pm.list_paths(role=role))
    except Exception as e:
        return err(str(e))


@router.get("/course-templates")
def list_templates():
    try:
        tm = get_template_manager()
        return ok(tm.list_templates())
    except Exception as e:
        return err(str(e))


@router.get("/quality/report")
def quality_report():
    try:
        qm = get_quality_manager()
        return ok(qm.quality_report())
    except Exception as e:
        return err(str(e))


@router.get("/recommend/role/{role}")
def recommend_for_role(role: str, limit: int = Query(5)):
    try:
        rec = get_recommender()
        return ok(rec.recommend_for_role(role, limit))
    except Exception as e:
        return err(str(e))


@router.get("/meta/course-categories")
def course_meta():
    return ok({
        "categories": COURSE_CATEGORIES, "levels": COURSE_LEVELS,
        "types": COURSE_TYPES, "statuses": COURSE_STATUS,
    })


# =========================================================================== #
# 2. 实验环境 API
# =========================================================================== #

@router.get("/labs")
def list_labs(category: str = Query(""), difficulty: str = Query("")):
    try:
        lm = get_lab_manager()
        return ok(lm.list_labs(category=category, difficulty=difficulty))
    except Exception as e:
        return err(str(e))


@router.post("/labs")
def create_lab(body: LabCreate):
    try:
        lm = get_lab_manager()
        return ok(lm.create_lab(body.model_dump()))
    except Exception as e:
        return err(str(e))


@router.get("/labs/{lab_id}")
def get_lab(lab_id: str):
    try:
        lm = get_lab_manager()
        lab = lm.get_lab(lab_id)
        if not lab:
            return err("实验不存在", 404)
        return ok(lab)
    except Exception as e:
        return err(str(e))


@router.post("/labs/{lab_id}/assign")
def assign_lab(lab_id: str, user: str = Query(...)):
    try:
        lm = get_lab_manager()
        a = lm.assign_lab(lab_id, user)
        if not a:
            return err("实验不存在", 404)
        return ok(a)
    except Exception as e:
        return err(str(e))


@router.post("/assignments/{assignment_id}/start")
def start_assignment(assignment_id: str):
    try:
        lm = get_lab_manager()
        a = lm.start_lab(assignment_id)
        if not a:
            return err("分配记录不存在", 404)
        return ok(a)
    except Exception as e:
        return err(str(e))


@router.post("/assignments/{assignment_id}/submit")
def submit_assignment(assignment_id: str, body: AssignmentSubmit):
    try:
        lm = get_lab_manager()
        a = lm.submit_lab(assignment_id, body.answer)
        if not a:
            return err("分配记录不存在", 404)
        return ok(a)
    except Exception as e:
        return err(str(e))


@router.post("/assignments/{assignment_id}/grade")
def grade_assignment(assignment_id: str):
    try:
        le = get_lab_evaluator()
        result = le.auto_grade(assignment_id)
        if not result:
            return err("分配记录不存在", 404)
        return ok(result)
    except Exception as e:
        return err(str(e))


@router.get("/ranges")
def list_ranges(rtype: str = Query(""), status: str = Query("")):
    try:
        re = get_range_env()
        return ok(re.list_ranges(rtype=rtype, status=status))
    except Exception as e:
        return err(str(e))


@router.post("/ranges")
def create_range(body: RangeCreate):
    try:
        re = get_range_env()
        return ok(re.create_range(body.name, body.type, body.image))
    except Exception as e:
        return err(str(e))


@router.post("/ranges/{range_id}/start")
def start_range(range_id: str):
    try:
        re = get_range_env()
        r = re.start_range(range_id)
        if not r:
            return err("靶场不存在", 404)
        return ok(r)
    except Exception as e:
        return err(str(e))


@router.post("/ranges/{range_id}/stop")
def stop_range(range_id: str):
    try:
        re = get_range_env()
        r = re.stop_range(range_id)
        if not r:
            return err("靶场不存在", 404)
        return ok(r)
    except Exception as e:
        return err(str(e))


@router.post("/ranges/{range_id}/snapshots")
def take_snapshot(range_id: str, name: str = Query("")):
    try:
        re = get_range_env()
        s = re.take_snapshot(range_id, name)
        if not s:
            return err("靶场不存在", 404)
        return ok(s)
    except Exception as e:
        return err(str(e))


@router.get("/resources")
def resource_status():
    try:
        em = get_env_manager()
        return ok(em.get_resource_status())
    except Exception as e:
        return err(str(e))


@router.get("/images")
def list_images():
    try:
        em = get_env_manager()
        return ok(em.list_images())
    except Exception as e:
        return err(str(e))


@router.post("/sandboxes")
def create_sandbox(user: str = Query(...), lab_id: str = Query(...)):
    try:
        sb = get_lab_sandbox()
        return ok(sb.create_sandbox(user, lab_id))
    except Exception as e:
        return err(str(e))


@router.post("/sandboxes/{sandbox_id}/execute")
def execute_sandbox(sandbox_id: str, command: str = Query(...)):
    try:
        sb = get_lab_sandbox()
        return ok(sb.execute_in_sandbox(sandbox_id, command))
    except Exception as e:
        return err(str(e))


@router.get("/meta/lab-categories")
def lab_meta():
    return ok({
        "categories": LAB_CATEGORIES, "difficulties": LAB_DIFFICULTY,
        "statuses": LAB_STATUS,
    })


# =========================================================================== #
# 3. 考试认证 API
# =========================================================================== #

@router.get("/questions")
def list_questions(category: str = Query(""), difficulty: str = Query(""),
                   qtype: str = Query("")):
    try:
        qb = get_question_bank()
        return ok(qb.list_questions(category=category, difficulty=difficulty, qtype=qtype))
    except Exception as e:
        return err(str(e))


@router.post("/questions")
def add_question(body: QuestionCreate):
    try:
        qb = get_question_bank()
        return ok(qb.add_question(body.model_dump()))
    except Exception as e:
        return err(str(e))


@router.delete("/questions/{question_id}")
def delete_question(question_id: str):
    try:
        qb = get_question_bank()
        if not qb.delete_question(question_id):
            return err("题目不存在", 404)
        return ok({"deleted": True, "id": question_id})
    except Exception as e:
        return err(str(e))


@router.get("/exams")
def list_exams(status: str = Query("")):
    try:
        em = get_exam_manager()
        return ok(em.list_exams(status=status))
    except Exception as e:
        return err(str(e))


@router.post("/exams")
def create_exam(body: ExamCreate):
    try:
        em = get_exam_manager()
        return ok(em.create_exam(body.title, body.description, body.duration_minutes,
                                  body.question_ids, body.passing_score))
    except Exception as e:
        return err(str(e))


@router.post("/exams/{exam_id}/publish")
def publish_exam(exam_id: str, start_time: str = Query(""), end_time: str = Query("")):
    try:
        em = get_exam_manager()
        e = em.publish_exam(exam_id, start_time, end_time)
        if not e:
            return err("考试不存在", 404)
        return ok(e)
    except Exception as e:
        return err(str(e))


@router.post("/exams/{exam_id}/start")
def start_exam(exam_id: str, user: str = Query(...)):
    try:
        ex = get_exam_executor()
        a = ex.start_exam(exam_id, user)
        if not a:
            return err("考试不可用或不存在", 404)
        return ok(a)
    except Exception as e:
        return err(str(e))


@router.post("/attempts/{attempt_id}/answer")
def submit_answer(attempt_id: str, question_id: str = Query(...), body: AnswerSubmit = None):
    try:
        ex = get_exam_executor()
        a = ex.submit_answer(attempt_id, question_id, body.answer if body else None)
        if not a:
            return err("考试记录不存在", 404)
        return ok(a)
    except Exception as e:
        return err(str(e))


@router.post("/attempts/{attempt_id}/submit")
def submit_exam(attempt_id: str):
    try:
        ex = get_exam_executor()
        a = ex.submit_exam(attempt_id)
        if not a:
            return err("考试记录不存在", 404)
        return ok(a)
    except Exception as e:
        return err(str(e))


@router.post("/attempts/{attempt_id}/grade")
def grade_exam(attempt_id: str):
    try:
        grader = get_exam_grader()
        result = grader.grade_exam(attempt_id)
        if not result:
            return err("考试记录不存在", 404)
        return ok(result)
    except Exception as e:
        return err(str(e))


@router.post("/certificates/generate")
def generate_certificate(body: CertGenerate):
    try:
        cm = get_certificate_manager()
        return ok(cm.generate_certificate(body.user, body.cert_name, body.cert_level,
                                         body.score, body.expiry_days))
    except Exception as e:
        return err(str(e))


@router.get("/certificates/verify/{cert_number}")
def verify_certificate(cert_number: str):
    try:
        cm = get_certificate_manager()
        result = cm.verify_certificate(cert_number)
        if not result:
            return err("证书编号不存在", 404)
        return ok(result)
    except Exception as e:
        return err(str(e))


@router.get("/certificates")
def list_certificates(user: str = Query("")):
    try:
        cm = get_certificate_manager()
        return ok(cm.list_certificates(user=user))
    except Exception as e:
        return err(str(e))


@router.delete("/certificates/{cert_id}/revoke")
def revoke_certificate(cert_id: str, reason: str = Query("")):
    try:
        cm = get_certificate_manager()
        if not cm.revoke_certificate(cert_id, reason):
            return err("证书不存在", 404)
        return ok({"revoked": True, "id": cert_id})
    except Exception as e:
        return err(str(e))


@router.get("/cert-paths")
def cert_paths():
    try:
        cs = get_certification_system()
        return ok(cs.get_cert_paths())
    except Exception as e:
        return err(str(e))


@router.get("/meta/exam-meta")
def exam_meta():
    return ok({
        "question_types": QUESTION_TYPES, "exam_statuses": EXAM_STATUS,
        "cert_levels": CERT_LEVELS, "pass_score": PASS_SCORE,
    })


# =========================================================================== #
# 4. 能力评估 API
# =========================================================================== #

@router.get("/skills/tree")
def skill_tree():
    try:
        model = get_competency_model()
        return ok(model.get_skill_tree())
    except Exception as e:
        return err(str(e))


@router.get("/roles")
def list_roles():
    try:
        model = get_competency_model()
        return ok({"roles": model.list_roles(), "requirements": ROLE_COMPETENCY})
    except Exception as e:
        return err(str(e))


@router.post("/assessments/self")
def self_assess(body: SelfAssess):
    try:
        assessor = get_assessor()
        return ok(assessor.self_assess(body.user, body.skills))
    except Exception as e:
        return err(str(e))


@router.get("/users/{user}/skills")
def get_user_skills(user: str):
    try:
        assessor = get_assessor()
        return ok(assessor.get_user_skills(user))
    except Exception as e:
        return err(str(e))


@router.post("/gap-analyze")
def gap_analyze(body: GapAnalyze):
    try:
        ga = get_gap_analyzer()
        result = ga.analyze_gap(body.user, body.target_role)
        if not result:
            return err("目标角色不存在", 404)
        return ok(result)
    except Exception as e:
        return err(str(e))


@router.post("/badges/award")
def award_badge(body: BadgeAward):
    try:
        badge = get_badge()
        b = badge.award_badge(body.user, body.skill, body.level)
        if not b:
            return err("技能或等级无效", 400)
        return ok(b)
    except Exception as e:
        return err(str(e))


@router.get("/users/{user}/badges")
def get_user_badges(user: str):
    try:
        badge = get_badge()
        return ok(badge.get_user_badges(user))
    except Exception as e:
        return err(str(e))


@router.get("/reports/personal/{user}")
def personal_report(user: str):
    try:
        report = get_report()
        return ok(report.personal_report(user))
    except Exception as e:
        return err(str(e))


@router.get("/reports/team")
def team_report(users: str = Query("")):
    try:
        report = get_report()
        user_list = [u.strip() for u in users.split(",") if u.strip()] if users else []
        return ok(report.team_report(user_list))
    except Exception as e:
        return err(str(e))


# =========================================================================== #
# 5. 企业培训 API
# =========================================================================== #

@router.get("/plans")
def list_plans(department: str = Query(""), ptype: str = Query("")):
    try:
        pm = get_plan_manager()
        return ok(pm.list_plans(department=department, ptype=ptype))
    except Exception as e:
        return err(str(e))


@router.post("/plans")
def create_plan(body: PlanCreate):
    try:
        pm = get_plan_manager()
        return ok(pm.create_plan(body.name, body.type, body.department,
                                  body.description, body.budget))
    except Exception as e:
        return err(str(e))


@router.get("/sessions")
def list_sessions(status: str = Query("")):
    try:
        te = get_training_execution()
        return ok(te.list_sessions(status=status))
    except Exception as e:
        return err(str(e))


@router.post("/sessions")
def create_session(body: SessionCreate):
    try:
        te = get_training_execution()
        return ok(te.create_session(body.title, body.trainer, body.scheduled_date,
                                    body.location, body.capacity))
    except Exception as e:
        return err(str(e))


@router.post("/sessions/{session_id}/enroll")
def enroll_session(session_id: str, body: EnrollRequest):
    try:
        te = get_training_execution()
        r = te.enroll(session_id, body.user, body.department)
        if not r:
            return err("课程不存在或名额已满", 400)
        return ok(r)
    except Exception as e:
        return err(str(e))


@router.post("/registrations/{registration_id}/checkin")
def check_in(registration_id: str):
    try:
        te = get_training_execution()
        r = te.check_in(registration_id)
        if not r:
            return err("注册记录不存在", 404)
        return ok(r)
    except Exception as e:
        return err(str(e))


@router.post("/sessions/{session_id}/feedback")
def submit_feedback(session_id: str, body: FeedbackSubmit):
    try:
        te = get_training_execution()
        return ok(te.submit_feedback(session_id, body.user, body.rating, body.comment))
    except Exception as e:
        return err(str(e))


@router.get("/statistics/coverage")
def coverage_stats(total_employees: int = Query(100)):
    try:
        ts = get_training_statistics()
        return ok(ts.coverage_stats(total_employees))
    except Exception as e:
        return err(str(e))


@router.get("/statistics/completion")
def completion_stats():
    try:
        ts = get_training_statistics()
        return ok(ts.completion_stats())
    except Exception as e:
        return err(str(e))


@router.get("/statistics/by-department")
def dept_stats():
    try:
        ts = get_training_statistics()
        return ok(ts.attendance_by_department())
    except Exception as e:
        return err(str(e))


@router.get("/instructors")
def list_instructors(skill: str = Query("")):
    try:
        rm = get_resource_manager()
        return ok(rm.list_instructors(skill=skill))
    except Exception as e:
        return err(str(e))


@router.get("/training-materials")
def list_training_materials(category: str = Query("")):
    try:
        rm = get_resource_manager()
        return ok(rm.list_materials(category=category))
    except Exception as e:
        return err(str(e))


@router.get("/compliance/requirements")
def compliance_requirements(framework: str = Query("")):
    try:
        comp = get_training_compliance()
        return ok(comp.get_requirements(framework))
    except Exception as e:
        return err(str(e))


@router.post("/compliance/check")
def run_compliance_check(body: ComplianceCheck):
    try:
        comp = get_training_compliance()
        return ok(comp.run_compliance_check(body.framework, body.employees_trained,
                                            body.total_employees))
    except Exception as e:
        return err(str(e))


# =========================================================================== #
# 6. 安全意识 API
# =========================================================================== #

@router.get("/awareness-courses")
def list_awareness_courses(topic: str = Query("")):
    try:
        ac = get_awareness_course()
        return ok(ac.list_courses(topic=topic))
    except Exception as e:
        return err(str(e))


@router.post("/phishing/campaigns")
def create_phishing_campaign(body: PhishingCampaignCreate):
    try:
        ph = get_phishing_simulation()
        return ok(ph.create_campaign(body.name, body.target_users, body.template))
    except Exception as e:
        return err(str(e))


@router.get("/phishing/campaigns")
def list_phishing_campaigns():
    try:
        ph = get_phishing_simulation()
        return ok(ph.list_campaigns())
    except Exception as e:
        return err(str(e))


@router.post("/phishing/{campaign_id}/click")
def phishing_click(campaign_id: str, body: PhishAction):
    try:
        ph = get_phishing_simulation()
        r = ph.simulate_click(campaign_id, body.user)
        if not r:
            return err("活动不存在", 404)
        return ok(r)
    except Exception as e:
        return err(str(e))


@router.post("/phishing/{campaign_id}/report")
def phishing_report(campaign_id: str, body: PhishAction):
    try:
        ph = get_phishing_simulation()
        r = ph.simulate_report(campaign_id, body.user)
        if not r:
            return err("活动不存在", 404)
        return ok(r)
    except Exception as e:
        return err(str(e))


@router.get("/phishing/{campaign_id}/results")
def phishing_results(campaign_id: str):
    try:
        ph = get_phishing_simulation()
        r = ph.campaign_results(campaign_id)
        if not r:
            return err("活动不存在", 404)
        return ok(r)
    except Exception as e:
        return err(str(e))


@router.get("/awareness-activities")
def list_awareness_activities(atype: str = Query("")):
    try:
        act = get_awareness_activity()
        return ok(act.list_activities(atype=atype))
    except Exception as e:
        return err(str(e))


@router.post("/awareness-activities")
def create_awareness_activity(body: ActivityCreate):
    try:
        act = get_awareness_activity()
        return ok(act.create_activity(body.name, body.type, body.description, body.scheduled_date))
    except Exception as e:
        return err(str(e))


@router.get("/awareness-materials")
def list_awareness_materials(topic: str = Query(""), mtype: str = Query("")):
    try:
        mat = get_awareness_material()
        return ok(mat.list_materials(topic=topic, mtype=mtype))
    except Exception as e:
        return err(str(e))


@router.get("/metrics/awareness")
def awareness_metrics(department: str = Query("")):
    try:
        m = get_awareness_metrics()
        return ok(m.awareness_score(department))
    except Exception as e:
        return err(str(e))


@router.get("/metrics/trend")
def awareness_trend():
    try:
        m = get_awareness_metrics()
        return ok(m.trend_analysis())
    except Exception as e:
        return err(str(e))


@router.get("/culture/initiatives")
def list_culture_initiatives():
    try:
        culture = get_awareness_culture()
        return ok(culture.list_initiatives())
    except Exception as e:
        return err(str(e))


@router.get("/meta/awareness-meta")
def awareness_meta():
    return ok({
        "topics": AWARENESS_TOPICS, "activity_types": ACTIVITY_TYPES,
    })


# =========================================================================== #
# 7. 控制台 & 设置 API
# =========================================================================== #

@router.get("/dashboard/overview")
def dashboard_overview():
    try:
        d = get_training_dashboard()
        return ok(d.overview())
    except Exception as e:
        return err(str(e))


@router.get("/dashboard/courses")
def dashboard_courses():
    try:
        d = get_training_dashboard()
        return ok(d.course_overview())
    except Exception as e:
        return err(str(e))


@router.get("/dashboard/labs")
def dashboard_labs():
    try:
        d = get_training_dashboard()
        return ok(d.lab_overview())
    except Exception as e:
        return err(str(e))


@router.get("/dashboard/exams")
def dashboard_exams():
    try:
        d = get_training_dashboard()
        return ok(d.exam_overview())
    except Exception as e:
        return err(str(e))


@router.get("/dashboard/competency")
def dashboard_competency():
    try:
        d = get_training_dashboard()
        return ok(d.competency_overview())
    except Exception as e:
        return err(str(e))


@router.get("/dashboard/enterprise")
def dashboard_enterprise():
    try:
        d = get_training_dashboard()
        return ok(d.enterprise_overview())
    except Exception as e:
        return err(str(e))


@router.get("/dashboard/awareness")
def dashboard_awareness():
    try:
        d = get_training_dashboard()
        return ok(d.awareness_overview())
    except Exception as e:
        return err(str(e))


@router.get("/settings")
def get_settings():
    try:
        d = get_training_dashboard()
        return ok(d.get_settings())
    except Exception as e:
        return err(str(e))


@router.put("/settings")
def update_settings(body: SettingsUpdate):
    try:
        d = get_training_dashboard()
        return ok(d.update_settings(body.data))
    except Exception as e:
        return err(str(e))


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        if task_id not in TASKS:
            return err("任务不存在", 404)
        return ok(TASKS[task_id])
    except Exception as e:
        return err(str(e))
