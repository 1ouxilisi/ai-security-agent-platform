# -*- coding: utf-8 -*-
"""
security_training_pro_routes.py — 方向3 安全培训 Pro REST API（50+ 端点 + WebSocket）。

路由前缀: /api/v1/security-training-pro
统一响应: {"success": bool, "data": ..., "error": ...}
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/security-training-pro",
                   tags=["SecurityTrainingPro-方向3"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from security_training_pro import (
        get_orchestrator, get_dashboard, get_realtime_push,
        get_course_management_phase, get_learning_path_phase,
        get_lab_environment_phase, get_exam_system_phase,
        get_phishing_simulation_phase, get_student_management_phase,
        get_instructor_management_phase, get_data_analysis_phase,
        get_ai_analysis, get_report_generator, STAGES, REPORTS_DIR,
        COURSE_CATEGORIES,
    )
    _ORCH = get_orchestrator()
    _DASH = get_dashboard()
    _RT = get_realtime_push()
    _COURSE = get_course_management_phase()
    _PATH = get_learning_path_phase()
    _LAB = get_lab_environment_phase()
    _EXAM = get_exam_system_phase()
    _PHISH = get_phishing_simulation_phase()
    _STU = get_student_management_phase()
    _INS = get_instructor_management_phase()
    _ANA = get_data_analysis_phase()
    _AI = get_ai_analysis()
    _REP = get_report_generator()
    _MOD_AVAILABLE = True
    logger.info("security_training_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("security_training_pro_routes: load failed: %s", e)
    _ORCH = _DASH = _RT = None  # type: ignore
    _COURSE = _PATH = _LAB = _EXAM = None  # type: ignore
    _PHISH = _STU = _INS = _ANA = _AI = _REP = None  # type: ignore


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c == "\n" or c == "\t"
                       or ord(c) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data),
                         "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE or _ORCH is None:
        return fail("安全培训 Pro 模块未加载", 503)
    return None


# =========================================================================== #
# 0. 任务管理（八阶段一键全流程）
# =========================================================================== #
@router.post("/start")
def start_training(name: str = Body("安全培训全流程演练", embed=True)):
    g = _guard()
    if g:
        return g
    t = _ORCH.create_task(name)
    threading.Thread(target=_ORCH.run_full,
                     args=(t.task_id,), daemon=True).start()
    return ok({"task_id": t.task_id, "name": name,
               "status": t.status, "stage": t.stage,
               "progress": t.progress})


@router.get("/tasks")
def list_tasks():
    g = _guard()
    if g:
        return g
    return ok({"tasks": _ORCH.list_tasks()})


@router.get("/task/{task_id}")
def task_detail(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok(t.to_dict())


@router.get("/task/{task_id}/status")
def task_status(task_id: str):
    g = _guard()
    if g:
        return g
    t = _ORCH.get_task(task_id)
    if t is None:
        return fail("task not found", 404)
    return ok({"task_id": task_id, "status": t.status,
               "stage": t.stage, "progress": t.progress,
               "log": t.log[-30:]})


@router.get("/stages")
def stages():
    g = _guard()
    if g:
        return g
    return ok({"stages": [{"key": k, "label": n, "progress": p}
                          for k, n, p in STAGES]})


# =========================================================================== #
# 1. 阶段1 课程管理
# =========================================================================== #
@router.get("/courses/categories")
def course_categories():
    g = _guard()
    if g:
        return g
    return ok({"categories": _COURSE.categories()})


@router.get("/courses")
def course_list(category: Optional[str] = Query(None),
                status: Optional[str] = Query(None),
                difficulty: Optional[str] = Query(None),
                keyword: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"courses": _COURSE.list_courses(
        category, status, difficulty, keyword)})


@router.post("/courses")
def course_create(name: str = Body(...), description: str = Body(""),
                  category: str = Body("Web安全"),
                  difficulty: str = Body("入门"),
                  duration_min: int = Body(60),
                  credit: float = Body(1.0), price: float = Body(0.0),
                  instructor: str = Body("")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_COURSE.create_course(name, description, category,
                                         difficulty, duration_min,
                                         credit, price, instructor))
    except ValueError as e:
        return fail(str(e))


@router.get("/courses/{course_id}")
def course_detail(course_id: str):
    g = _guard()
    if g:
        return g
    c = _COURSE.get_course(course_id)
    if c is None:
        return fail("course not found", 404)
    return ok(c)


@router.put("/courses/{course_id}")
def course_update(course_id: str, payload: Dict[str, Any] = Body(...)):
    g = _guard()
    if g:
        return g
    r = _COURSE.update_course(course_id, **payload)
    if r is None:
        return fail("course not found", 404)
    return ok(r)


@router.post("/courses/{course_id}/status")
def course_status(course_id: str,
                  status: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    try:
        r = _COURSE.change_status(course_id, status)
    except ValueError as e:
        return fail(str(e))
    if r is None:
        return fail("course not found", 404)
    return ok(r)


@router.post("/courses/{course_id}/chapters")
def chapter_add(course_id: str, title: str = Body(...),
                content: str = Body(""),
                duration_min: int = Body(0)):
    g = _guard()
    if g:
        return g
    r = _COURSE.add_chapter(course_id, title, content, duration_min)
    if r is None:
        return fail("course not found", 404)
    return ok(r)


@router.put("/courses/{course_id}/chapters/reorder")
def chapter_reorder(course_id: str, order: List[str] = Body(...)):
    g = _guard()
    if g:
        return g
    r = _COURSE.reorder_chapters(course_id, order)
    if r is None:
        return fail("course not found", 404)
    return ok(r)


@router.post("/courses/{course_id}/materials")
def material_upload(course_id: str, chapter_id: str = Body(...),
                    filename: str = Body(...), mtype: str = Body("pdf")):
    g = _guard()
    if g:
        return g
    r = _COURSE.upload_material(course_id, chapter_id, filename, mtype)
    if r is None:
        return fail("chapter not found", 404)
    return ok(r)


@router.post("/courses/{course_id}/videos")
def video_add(course_id: str, title: str = Body(...),
              filename: str = Body(...),
              duration_min: int = Body(0),
              subtitle: bool = Body(False)):
    g = _guard()
    if g:
        return g
    r = _COURSE.add_video(course_id, title, filename,
                          duration_min, subtitle)
    if r is None:
        return fail("course not found", 404)
    return ok(r)


@router.post("/courses/{course_id}/comments")
def comment_add(course_id: str, user: str = Body(...),
                rating: int = Body(5), comment: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_COURSE.add_comment(course_id, user, rating, comment))


@router.get("/courses/templates/list")
def course_templates():
    g = _guard()
    if g:
        return g
    return ok({"templates": _COURSE.templates()})


@router.get("/courses/stats/summary")
def course_stats():
    g = _guard()
    if g:
        return g
    return ok(_COURSE.stats())


# =========================================================================== #
# 2. 阶段2 学习路径
# =========================================================================== #
@router.get("/paths")
def path_list():
    g = _guard()
    if g:
        return g
    return ok({"paths": _PATH.list_paths()})


@router.post("/paths")
def path_create(name: str = Body(...), description: str = Body(""),
                level: str = Body("入门"),
                courses: List[str] = Body(default=[])):
    g = _guard()
    if g:
        return g
    try:
        return ok(_PATH.create_path(name, description, level, courses))
    except ValueError as e:
        return fail(str(e))


@router.get("/paths/{path_id}")
def path_detail(path_id: str):
    g = _guard()
    if g:
        return g
    p = _PATH.get_path(path_id)
    if p is None:
        return fail("path not found", 404)
    return ok(p)


@router.get("/knowledge/map")
def knowledge_map(topic: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok(_PATH.knowledge_map(topic))


@router.post("/paths/recommend")
def path_recommend(goal: str = Body(""), base: str = Body("入门"),
                   interest: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok({"recommended": _PATH.recommend(goal, base, interest)})


@router.post("/paths/{path_id}/progress")
def path_progress(path_id: str, student: str = Body(...),
                  progress: float = Body(0.0),
                  study_hours: float = Body(0.0)):
    g = _guard()
    if g:
        return g
    return ok(_PATH.update_progress(path_id, student,
                                    progress, study_hours))


@router.get("/paths/templates/list")
def path_templates():
    g = _guard()
    if g:
        return g
    return ok({"templates": _PATH.templates()})


@router.get("/paths/{path_id}/evaluate")
def path_evaluate(path_id: str):
    g = _guard()
    if g:
        return g
    return ok(_PATH.evaluate(path_id))


@router.get("/paths/optimize/all")
def path_optimize():
    g = _guard()
    if g:
        return g
    return ok(_PATH.optimize())


@router.get("/paths/stats/summary")
def path_stats():
    g = _guard()
    if g:
        return g
    return ok(_PATH.stats())


# =========================================================================== #
# 3. 阶段3 实验环境
# =========================================================================== #
@router.get("/labs")
def lab_list(category: Optional[str] = Query(None),
             difficulty: Optional[str] = Query(None),
             status: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"labs": _LAB.list_labs(category, difficulty, status)})


@router.post("/labs")
def lab_create(name: str = Body(...), category: str = Body("Web实验"),
               difficulty: str = Body("入门"), image: str = Body("")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_LAB.create_lab(name, category, difficulty, image))
    except ValueError as e:
        return fail(str(e))


@router.get("/labs/docker/status")
def lab_docker():
    g = _guard()
    if g:
        return g
    return ok(_LAB.docker_status())


@router.post("/labs/{lab_id}/start")
def lab_start(lab_id: str, student: str = Body("student", embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_LAB.start_lab(lab_id, student))


@router.post("/labs/{lab_id}/stop")
def lab_stop(lab_id: str):
    g = _guard()
    if g:
        return g
    return ok(_LAB.stop_lab(lab_id))


@router.post("/labs/{lab_id}/report")
def lab_report(lab_id: str, result: str = Body(""),
               analysis: str = Body(""), summary: str = Body(""),
               screenshot: str = Body("")):
    g = _guard()
    if g:
        return g
    r = _LAB.submit_report(lab_id, result, analysis, summary, screenshot)
    if r is None:
        return fail("lab not found", 404)
    return ok(r)


@router.post("/labs/{lab_id}/grade")
def lab_grade(lab_id: str,
              manual_score: float = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    r = _LAB.grade_manual(lab_id, manual_score)
    if r is None:
        return fail("lab not found", 404)
    return ok(r)


@router.get("/labs/stats/summary")
def lab_stats():
    g = _guard()
    if g:
        return g
    return ok(_LAB.stats())


# =========================================================================== #
# 4. 阶段4 考试系统
# =========================================================================== #
@router.get("/exam/questions")
def q_list(category: Optional[str] = Query(None),
           qtype: Optional[str] = Query(None),
           difficulty: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"questions": _EXAM.list_questions(category, qtype,
                                                difficulty)})


@router.post("/exam/questions")
def q_add(qtype: str = Body(...), stem: str = Body(...),
          answer: str = Body(...), category: str = Body("Web安全"),
          difficulty: str = Body("入门"), knowledge: str = Body(""),
          score: float = Body(5.0),
          options: List[str] = Body(default=[]),
          analysis: str = Body("")):
    g = _guard()
    if g:
        return g
    try:
        return ok(_EXAM.add_question(qtype, stem, answer, category,
                                     difficulty, knowledge, score,
                                     options, analysis))
    except ValueError as e:
        return fail(str(e))


@router.post("/exam/papers")
def paper_gen(name: str = Body(...), mode: str = Body("random"),
              qids: List[str] = Body(default=[]),
              by_category: Optional[str] = Body(None),
              count: int = Body(10)):
    g = _guard()
    if g:
        return g
    return ok(_EXAM.generate_paper(name, mode, qids, by_category, count))


@router.get("/exam/papers")
def paper_list():
    g = _guard()
    if g:
        return g
    return ok({"papers": _EXAM.list_papers()})


@router.post("/exam/start")
def exam_start(paper_id: str = Body(...),
               student: str = Body("student")):
    g = _guard()
    if g:
        return g
    r = _EXAM.start_exam(paper_id, student)
    if r is None:
        return fail("paper not found", 404)
    return ok(r)


@router.post("/exam/records/{record_id}/answer")
def exam_answer(record_id: str, qid: str = Body(...),
                answer: str = Body(...)):
    g = _guard()
    if g:
        return g
    r = _EXAM.save_answer(record_id, qid, answer)
    if r is None:
        return fail("record not found", 404)
    return ok(r)


@router.post("/exam/records/{record_id}/submit")
def exam_submit(record_id: str):
    g = _guard()
    if g:
        return g
    r = _EXAM.submit_exam(record_id)
    if r is None:
        return fail("record not found", 404)
    return ok(r)


@router.get("/exam/records")
def exam_records(student: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"records": _EXAM.list_records(student)})


@router.post("/exam/records/{record_id}/certificate")
def exam_cert(record_id: str):
    g = _guard()
    if g:
        return g
    r = _EXAM.issue_certificate(record_id)
    if r is None:
        return fail("record not found", 404)
    return ok(r)


@router.get("/exam/certificates/{cert_id}/verify")
def cert_verify(cert_id: str):
    g = _guard()
    if g:
        return g
    return ok(_EXAM.verify_certificate(cert_id))


@router.get("/exam/monitoring")
def exam_monitoring():
    g = _guard()
    if g:
        return g
    return ok(_EXAM.monitoring())


@router.get("/exam/stats/summary")
def exam_stats():
    g = _guard()
    if g:
        return g
    return ok(_EXAM.stats())


# =========================================================================== #
# 5. 阶段5 钓鱼演练
# =========================================================================== #
@router.get("/phishing/templates")
def phish_templates():
    g = _guard()
    if g:
        return g
    return ok({"templates": _PHISH.list_templates()})


@router.post("/phishing/templates")
def phish_add_template(name: str = Body(...), ttype: str = Body("邮件模板"),
                       subject: str = Body(""), body: str = Body(""),
                       landing: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_PHISH.add_template(name, ttype, subject, body, landing))


@router.post("/phishing/campaigns")
def phish_create(name: str = Body(...),
                 template_id: str = Body(...),
                 targets: List[str] = Body(default=[]),
                 departments: List[str] = Body(default=[]),
                 schedule: str = Body("now")):
    g = _guard()
    if g:
        return g
    r = _PHISH.create_campaign(name, template_id, targets,
                               departments, schedule)
    if r is None:
        return fail("template not found", 404)
    return ok(r)


@router.get("/phishing/campaigns")
def phish_campaigns():
    g = _guard()
    if g:
        return g
    return ok({"campaigns": _PHISH.list_campaigns()})


@router.post("/phishing/campaigns/{camp_id}/send")
def phish_send(camp_id: str):
    g = _guard()
    if g:
        return g
    r = _PHISH.send_campaign(camp_id)
    if r is None:
        return fail("campaign not found", 404)
    return ok(r)


@router.post("/phishing/campaigns/{camp_id}/track")
def phish_track(camp_id: str, user: str = Body(...),
                etype: str = Body(...), device: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_PHISH.track_event(camp_id, user, etype, device))


@router.get("/phishing/campaigns/{camp_id}/risk")
def phish_risk(camp_id: str):
    g = _guard()
    if g:
        return g
    return ok(_PHISH.risk_assessment(camp_id))


@router.get("/phishing/campaigns/{camp_id}/report")
def phish_report(camp_id: str):
    g = _guard()
    if g:
        return g
    return ok(_PHISH.campaign_report(camp_id))


@router.get("/phishing/stats/summary")
def phish_stats():
    g = _guard()
    if g:
        return g
    return ok(_PHISH.stats())


# =========================================================================== #
# 6. 阶段6 学员管理
# =========================================================================== #
@router.post("/students/register")
def stu_register(name: str = Body(...), email: str = Body(""),
                 org: str = Body(""), source: str = Body("个人注册")):
    g = _guard()
    if g:
        return g
    return ok(_STU.register(name, email, org, source))


@router.post("/students/import")
def stu_import(names: List[str] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_STU.bulk_import(names))


@router.get("/students")
def stu_list(status: Optional[str] = Query(None),
             group: Optional[str] = Query(None),
             keyword: Optional[str] = Query(None)):
    g = _guard()
    if g:
        return g
    return ok({"students": _STU.list_students(status, group, keyword)})


@router.get("/students/{sid}")
def stu_detail(sid: str):
    g = _guard()
    if g:
        return g
    s = _STU.get_student(sid)
    if s is None:
        return fail("student not found", 404)
    return ok(s)


@router.post("/students/{sid}/progress")
def stu_progress(sid: str, course_id: str = Body(...),
                 progress: float = Body(0.0), minutes: int = Body(0)):
    g = _guard()
    if g:
        return g
    return ok(_STU.update_progress(sid, course_id, progress, minutes))


@router.get("/students/{sid}/ability")
def stu_ability(sid: str):
    g = _guard()
    if g:
        return g
    return ok(_STU.ability_report(sid))


@router.get("/students/{sid}/behavior")
def stu_behavior(sid: str):
    g = _guard()
    if g:
        return g
    return ok(_STU.behavior_analysis(sid))


@router.post("/students/{sid}/group")
def stu_group(sid: str, group: str = Body(..., embed=True)):
    g = _guard()
    if g:
        return g
    return ok(_STU.assign_group(sid, group))


@router.get("/students/stats/summary")
def stu_stats():
    g = _guard()
    if g:
        return g
    return ok(_STU.stats())


# =========================================================================== #
# 7. 阶段7 讲师管理
# =========================================================================== #
@router.post("/instructors/register")
def ins_register(name: str = Body(...), email: str = Body(""),
                 domain: str = Body("Web安全"),
                 experience_years: int = Body(3),
                 certs: List[str] = Body(default=[]),
                 bio: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_INS.register(name, email, domain, experience_years,
                            certs, bio))


@router.get("/instructors")
def ins_list():
    g = _guard()
    if g:
        return g
    return ok({"instructors": _INS.list_instructors()})


@router.get("/instructors/{iid}")
def ins_detail(iid: str):
    g = _guard()
    if g:
        return g
    i = _INS.get_instructor(iid)
    if i is None:
        return fail("instructor not found", 404)
    return ok(i)


@router.post("/instructors/{iid}/approve")
def ins_approve(iid: str, approved: bool = Body(True, embed=True)):
    g = _guard()
    if g:
        return g
    r = _INS.approve(iid, approved)
    if r is None:
        return fail("instructor not found", 404)
    return ok(r)


@router.get("/instructors/rank/list")
def ins_rank(by: str = Query("rating")):
    g = _guard()
    if g:
        return g
    return ok({"rank": _INS.rank(by)})


@router.post("/instructors/{iid}/review")
def ins_review(iid: str, student: str = Body(...),
               rating: int = Body(5), comment: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_INS.add_review(iid, student, rating, comment))


@router.get("/instructors/stats/summary")
def ins_stats():
    g = _guard()
    if g:
        return g
    return ok(_INS.stats())


# =========================================================================== #
# 8. 阶段8 数据分析
# =========================================================================== #
@router.get("/analysis/learning")
def an_learning():
    g = _guard()
    if g:
        return g
    return ok(_ANA.learning_data())


@router.get("/analysis/pass-rate")
def an_pass():
    g = _guard()
    if g:
        return g
    return ok(_ANA.exam_pass_rate())


@router.get("/analysis/completion")
def an_completion():
    g = _guard()
    if g:
        return g
    return ok(_ANA.course_completion())


@router.get("/analysis/ability")
def an_ability():
    g = _guard()
    if g:
        return g
    return ok(_ANA.ability_improvement())


@router.get("/analysis/roi")
def an_roi():
    g = _guard()
    if g:
        return g
    return ok(_ANA.roi_analysis())


@router.get("/analysis/phishing")
def an_phish():
    g = _guard()
    if g:
        return g
    return ok(_ANA.phishing_analysis())


@router.get("/analysis/visualizations")
def an_viz():
    g = _guard()
    if g:
        return g
    return ok(_ANA.visualizations())


@router.get("/analysis/export")
def an_export():
    g = _guard()
    if g:
        return g
    return ok(_ANA.export_report())


# =========================================================================== #
# 9. AI 分析
# =========================================================================== #
@router.post("/ai/course-content")
def ai_course(topic: str = Body(...), level: str = Body("入门")):
    g = _guard()
    if g:
        return g
    return ok(_AI.generate_course_content(topic, level))


@router.post("/ai/questions")
def ai_questions(knowledge: str = Body(...),
                 difficulty: str = Body("简单"),
                 qtype: str = Body("单选题"),
                 count: int = Body(3)):
    g = _guard()
    if g:
        return g
    return ok(_AI.generate_questions(knowledge, difficulty,
                                     qtype, count))


@router.post("/ai/grade")
def ai_grade(question: str = Body(...), answer: str = Body(""),
             rubric: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_AI.grade_subjective(question, answer, rubric))


@router.post("/ai/path-recommend")
def ai_path(goal: str = Body(""), base: str = Body("入门"),
            interest: str = Body("")):
    g = _guard()
    if g:
        return g
    return ok(_AI.recommend_path(goal, base, interest))


@router.post("/ai/study-advice")
def ai_advice(ability: Dict[str, float] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_AI.study_advice(ability))


@router.post("/ai/ability-assess")
def ai_assess(scores: Dict[str, float] = Body(...)):
    g = _guard()
    if g:
        return g
    return ok(_AI.ability_assessment(scores))


@router.get("/ai/history")
def ai_history(limit: int = Query(50)):
    g = _guard()
    if g:
        return g
    return ok({"history": _AI.history(limit)})


# =========================================================================== #
# 10. 培训大屏仪表盘
# =========================================================================== #
@router.get("/dashboard/kpi")
def dash_kpi():
    g = _guard()
    if g:
        return g
    return ok(_DASH.kpi_cards())


@router.get("/dashboard/full")
def dash_full():
    g = _guard()
    if g:
        return g
    return ok(_DASH.full_screen())


@router.get("/dashboard/events")
def dash_events(n: int = Query(12)):
    g = _guard()
    if g:
        return g
    return ok({"events": _DASH.live_event_stream(n)})


@router.get("/dashboard/instructors")
def dash_ins():
    g = _guard()
    if g:
        return g
    return ok({"rank": _DASH.instructor_rank()})


# =========================================================================== #
# 11. 报告生成
# =========================================================================== #
@router.post("/report/generate")
def report_gen(fmt: str = Body("both", embed=True)):
    g = _guard()
    if g:
        return g
    r = _REP.generate(fmt)
    return ok({k: v for k, v in r.items() if k != "html"})


@router.get("/report/latest")
def report_latest():
    g = _guard()
    if g:
        return g
    if not os.path.isdir(REPORTS_DIR):
        return ok({"files": []})
    files = sorted(os.listdir(REPORTS_DIR), reverse=True)
    return ok({"dir": REPORTS_DIR, "files": files[:20]})


# =========================================================================== #
# 12. WebSocket 实时推送
# =========================================================================== #
@router.websocket("/ws/{task_id}")
async def ws_endpoint(websocket: WebSocket, task_id: str):
    """实时推送进度/日志/思考/事件/结果。"""
    await websocket.accept()
    if not _MOD_AVAILABLE:
        await websocket.send_json({"type": "error",
                                   "message": "模块未加载"})
        await websocket.close()
        return
    _RT.subscribe(task_id, websocket)
    for ev in _RT.history(task_id):
        try:
            await websocket.send_json(ev)
        except Exception:
            break
    try:
        sent_index = len(_RT.history(task_id))
        while True:
            hist = _RT.history(task_id)
            if len(hist) > sent_index:
                for ev in hist[sent_index:]:
                    await websocket.send_json(ev)
                sent_index = len(hist)
            await websocket.send_json({"type": "ping",
                                       "ts": time.time()})
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _RT.unsubscribe(task_id, websocket)
