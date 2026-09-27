# -*- coding: utf-8 -*-
"""
security_training_routes.py — 安全培训与意识平台 REST API（第14轮·方向2）。

路由前缀: /api/v1/security-training
统一响应: {"success": bool, "data": ..., "error": ...}
30+ 端点，覆盖课程/实验/考试认证/钓鱼演练/意识评估/运营/综合工作流。
所有端点 try/except 兜底；任务用内存字典模拟异步；_clean() 清理控制字符。

合规红线：钓鱼演练仅为模拟与意识评估，绝不真实发送邮件/短信。
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

router = APIRouter(prefix="/api/v1/security-training",
                   tags=["安全培训与意识平台"])

# --------------------------------------------------------------------------- #
# 模块加载（try-import，缺失时回退模拟数据）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from security_training.course_manager import (
        CourseManager, COURSE_CATEGORIES, COURSE_LIBRARY,
    )
    from security_training.lab_environment import LabEnvironmentManager, RANGE_LIBRARY
    from security_training.exam_certification import ExamCertManager, EXAM_BANK
    from security_training.phishing_simulation import PhishingSimulation
    from security_training.awareness_assessment import (
        AwarenessAssessor, AWARENESS_QUESTIONNAIRE,
    )
    from security_training.training_operations import TrainingOperations
    from security_training.training_workflow import (
        get_training_workflow, TRAINING_WORKFLOW_STEPS,
    )
    _MOD_AVAILABLE = True
    logger.info("security_training_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("security_training_routes: load failed: %s", e)


# 进程内单例（保持内存状态）
def _singletons() -> Dict[str, Any]:
    return {
        "course": CourseManager(), "lab": LabEnvironmentManager(),
        "exam": ExamCertManager(), "phish": PhishingSimulation(),
        "aware": AwarenessAssessor(), "ops": TrainingOperations(),
    }


_S: Dict[str, Any] = {}
if _MOD_AVAILABLE:
    _S = _singletons()
    _WF = get_training_workflow()
else:
    _WF = None


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = uuid.uuid4().hex[:16]
    _TASKS[tid] = {"task_id": tid, "kind": kind, "status": "pending",
                   "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "finished_at": None, "result": None, "error": None}
    return tid


def _finish(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in _TASKS:
        t = _TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应 + _clean 递归清理控制字符
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("安全培训模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ProgressReq(BaseModel):
    student: str = "demo_user"
    course_id: str = "CRS001"
    chapter_done: int = 1


class QuizReq(BaseModel):
    course_id: str = "CRS001"
    answers: Dict[str, str] = Field(default_factory=dict)


class RecommendReq(BaseModel):
    role: str = "general"
    dept: str = "tech"
    history: List[str] = Field(default_factory=list)
    limit: int = 8


class StartLabReq(BaseModel):
    student: str = "demo_user"
    lab_id: str = "LAB001"


class CheckpointReq(BaseModel):
    session_id: str = ""
    checkpoint: str = "low"
    evidence: str = ""


class BuildPaperReq(BaseModel):
    paper_code: str = "PAPER-BASIC"
    strategy: Optional[str] = None


class GradeExamReq(BaseModel):
    student: str = "demo_user"
    paper_id: str = ""
    answers: Dict[str, str] = Field(default_factory=dict)


class MonitorReq(BaseModel):
    student: str = "demo_user"
    paper_id: str = ""


class MonitorEventReq(BaseModel):
    event: str = "tab_switch"


class CertVerifyReq(BaseModel):
    serial: str = ""
    checksum: Optional[str] = None


class GroupReq(BaseModel):
    name: str = "默认演练组"
    members: List[str] = Field(default_factory=list)
    department: str = "研发部"


class DrillReq(BaseModel):
    plan_name: str = "季度钓鱼演练"
    tpl_ids: List[str] = Field(default_factory=lambda: ["TPL-M01", "TPL-S01"])
    group_ids: List[str] = Field(default_factory=list)
    channel: str = "email"


class AssessReq(BaseModel):
    student: str = "demo_user"
    department: str = "研发部"
    answers: Dict[str, str] = Field(default_factory=dict)


class ClassReq(BaseModel):
    name: str = "新员工安全班"
    instructor_id: str = "INS01"
    student_ids: List[str] = Field(default_factory=list)
    course_id: str = "CRS001"


class PlanReq(BaseModel):
    name: str = "年度安全培训计划"
    target: str = "全员"
    start: str = "2026-01-01"
    end: str = "2026-12-31"
    courses: List[str] = Field(default_factory=list)


class WorkflowReq(BaseModel):
    student: str = "demo_user"
    role: str = "dev"
    department: str = "研发部"
    demand_tags: List[str] = Field(default_factory=lambda: ["基础意识"])


# =========================================================================== #
# 1. 课程管理（8 个端点）
# =========================================================================== #
@router.get("/courses")
def list_courses(category: Optional[str] = Query(default=None),
                 difficulty: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["course"].list_courses(category, difficulty))
    except Exception as e:  # noqa: BLE001
        logger.exception("list_courses error")
        return fail(f"查询失败: {e}")


@router.get("/courses/{course_id}")
def get_course(course_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["course"].get_course(course_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/categories")
def list_categories():
    try:
        g = _guard()
        if g:
            return g
        return ok({"categories": COURSE_CATEGORIES,
                   "course_total": len(COURSE_LIBRARY)})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/learning-paths")
def learning_paths():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["course"].list_paths())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.post("/recommend")
def recommend(req: RecommendReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["course"].recommend(req.role, req.dept, req.history, req.limit))
    except Exception as e:  # noqa: BLE001
        logger.exception("recommend error")
        return fail(f"推荐失败: {e}")


@router.post("/progress")
def update_progress(req: ProgressReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["course"].update_progress(req.student, req.course_id,
                                               req.chapter_done))
    except Exception as e:  # noqa: BLE001
        return fail(f"更新进度失败: {e}")


@router.get("/progress/{student}")
def student_progress(student: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["course"].student_progress(student))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.post("/quiz/grade")
def grade_quiz(req: QuizReq):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task("quiz")
        result = _S["course"].grade_quiz(req.course_id, req.answers)
        _finish(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:  # noqa: BLE001
        logger.exception("grade_quiz error")
        return fail(f"测验评分失败: {e}")


# =========================================================================== #
# 2. 实验环境（7 个端点）
# =========================================================================== #
@router.get("/labs")
def list_labs(range_key: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["lab"].list_labs(range_key))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/ranges")
def list_ranges():
    try:
        g = _guard()
        if g:
            return g
        return ok({"ranges": RANGE_LIBRARY})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.post("/labs/start")
def start_lab(req: StartLabReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["lab"].start_lab(req.student, req.lab_id))
    except Exception as e:  # noqa: BLE001
        logger.exception("start_lab error")
        return fail(f"启动实验失败: {e}")


@router.post("/labs/checkpoint")
def submit_checkpoint(req: CheckpointReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["lab"].submit_checkpoint(req.session_id, req.checkpoint,
                                              req.evidence))
    except Exception as e:  # noqa: BLE001
        return fail(f"提交检查点失败: {e}")


@router.post("/labs/{session_id}/grade")
def grade_lab(session_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["lab"].auto_grade(session_id))
    except Exception as e:  # noqa: BLE001
        logger.exception("grade_lab error")
        return fail(f"自动评分失败: {e}")


@router.get("/labs/reports")
def lab_reports(student: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["lab"].list_reports(student))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/labs/sandbox/health")
def sandbox_health():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["lab"].sandbox_health())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


# =========================================================================== #
# 3. 考试与认证（7 个端点）
# =========================================================================== #
@router.get("/exam/bank-stats")
def bank_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["exam"].bank_stats())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.post("/exam/build")
def build_paper(req: BuildPaperReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["exam"].build_paper(req.paper_code, req.strategy))
    except Exception as e:  # noqa: BLE001
        logger.exception("build_paper error")
        return fail(f"组卷失败: {e}")


@router.post("/exam/grade")
def grade_exam(req: GradeExamReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["exam"].grade_exam(req.student, req.paper_id, req.answers))
    except Exception as e:  # noqa: BLE001
        logger.exception("grade_exam error")
        return fail(f"考试评分失败: {e}")


@router.post("/exam/monitor")
def start_monitor(req: MonitorReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["exam"].start_monitor(req.student, req.paper_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"开启监控失败: {e}")


@router.post("/exam/monitor/{monitor_id}/event")
def log_monitor_event(monitor_id: str, req: MonitorEventReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["exam"].log_event(monitor_id, req.event))
    except Exception as e:  # noqa: BLE001
        return fail(f"记录事件失败: {e}")


@router.get("/exam/analytics")
def exam_analytics():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["exam"].score_analytics())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/certificate/verify")
def verify_cert(serial: str = Query(default=""),
                checksum: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        if not serial:
            return fail("缺少证书编号 serial")
        return ok(_S["exam"].verify_cert(serial, checksum))
    except Exception as e:  # noqa: BLE001
        return fail(f"验证失败: {e}")


# =========================================================================== #
# 4. 钓鱼演练（6 个端点，纯模拟）
# =========================================================================== #
@router.get("/phishing/templates")
def phish_templates(channel: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["phish"].list_templates(channel))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.post("/phishing/groups")
def create_group(req: GroupReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["phish"].create_group(req.name, req.members, req.department))
    except Exception as e:  # noqa: BLE001
        return fail(f"创建分组失败: {e}")


@router.get("/phishing/groups")
def list_groups():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["phish"].list_groups())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.post("/phishing/drill")
def run_drill(req: DrillReq):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task("phishing_drill")
        result = _S["phish"].run_drill(req.plan_name, req.tpl_ids,
                                       req.group_ids, req.channel)
        _finish(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:  # noqa: BLE001
        logger.exception("run_drill error")
        return fail(f"发起演练失败: {e}")


@router.get("/phishing/drills")
def list_drills():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["phish"].list_drills())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/phishing/drills/{drill_id}/report")
def drill_report(drill_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["phish"].drill_report(drill_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"报告生成失败: {e}")


# =========================================================================== #
# 5. 意识评估（5 个端点）
# =========================================================================== #
@router.get("/awareness/questionnaire")
def awareness_questionnaire():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["aware"].questionnaire())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.post("/awareness/assess")
def awareness_assess(req: AssessReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["aware"].assess(req.student, req.department, req.answers))
    except Exception as e:  # noqa: BLE001
        logger.exception("awareness_assess error")
        return fail(f"测评失败: {e}")


@router.get("/awareness/departments")
def awareness_departments():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["aware"].department_compare())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/awareness/trend")
def awareness_trend(months: int = Query(default=6, ge=1, le=24)):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["aware"].trend(months))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/awareness/compliance-report")
def awareness_compliance(framework: str = Query(default="等保2.0三级")):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["aware"].compliance_report(framework))
    except Exception as e:  # noqa: BLE001
        return fail(f"报告生成失败: {e}")


# =========================================================================== #
# 6. 培训运营（9 个端点）
# =========================================================================== #
@router.get("/ops/students")
def ops_students(department: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["ops"].list_students(department))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/ops/instructors")
def ops_instructors():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["ops"].list_instructors())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.post("/ops/classes")
def ops_create_class(req: ClassReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["ops"].create_class(req.name, req.instructor_id,
                                         req.student_ids, req.course_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"创建班级失败: {e}")


@router.get("/ops/classes")
def ops_classes():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["ops"].list_classes())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/ops/classes/{class_id}/evaluation")
def ops_evaluation(class_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["ops"].kirkpatrick_evaluation(class_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"评估失败: {e}")


@router.post("/ops/plans")
def ops_create_plan(req: PlanReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["ops"].create_plan(req.name, req.target, req.start,
                                        req.end, req.courses))
    except Exception as e:  # noqa: BLE001
        return fail(f"创建计划失败: {e}")


@router.get("/ops/plans")
def ops_plans():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["ops"].list_plans())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/ops/roi")
def ops_roi(cost: float = Query(default=0),
            avoided_loss: float = Query(default=0)):
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["ops"].roi_analysis(cost, avoided_loss))
    except Exception as e:  # noqa: BLE001
        return fail(f"ROI 计算失败: {e}")


@router.get("/ops/dashboard")
def ops_dashboard():
    try:
        g = _guard()
        if g:
            return g
        return ok(_S["ops"].dashboard())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


# =========================================================================== #
# 7. 综合培训工作流（3 个端点）
# =========================================================================== #
@router.post("/workflow/run")
def workflow_run(req: WorkflowReq):
    try:
        g = _guard()
        if g:
            return g
        tid = _new_task("training_workflow")
        result = _WF.run(req.student, req.role, req.department, req.demand_tags)
        _finish(tid, result)
        return ok({"task_id": tid, "result": result})
    except Exception as e:  # noqa: BLE001
        logger.exception("workflow_run error")
        return fail(f"工作流执行失败: {e}")


@router.get("/workflow/history")
def workflow_history():
    try:
        g = _guard()
        if g:
            return g
        return ok({"history": _WF.list_history()})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")


@router.get("/workflow/steps")
def workflow_steps():
    try:
        g = _guard()
        if g:
            return g
        return ok({"steps": TRAINING_WORKFLOW_STEPS})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}")
