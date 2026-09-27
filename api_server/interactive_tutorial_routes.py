# -*- coding: utf-8 -*-
"""
interactive_tutorial_routes.py — 交互式教程 REST API（36 个端点）。

路由前缀: /api/v1/interactive-tutorial
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

覆盖6大模块：
  教程内容 / 交互环境 / 学习路径 / 进度评估 / 场景实战 / 运营控制台
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

router = APIRouter(prefix="/api/v1/interactive-tutorial",
                   tags=["交互式教程"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from interactive_tutorial import tutorial_content as tc
    from interactive_tutorial import interactive_env as ie
    from interactive_tutorial import learning_path as lp
    from interactive_tutorial import progress_evaluation as pe
    from interactive_tutorial import scenario_practice as sp
    from interactive_tutorial import tutorial_dashboard as td
    _MOD_AVAILABLE = True
    logger.info("interactive_tutorial_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("interactive_tutorial_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    _TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in _TASKS:
        t = _TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应 + 清理控制字符
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符与无效Unicode代理对。"""
    if isinstance(obj, str):
        # 去掉不可见控制字符（保留换行/制表）
        obj = "".join(ch for ch in obj
                      if ch in ("\n", "\t", "\r") or ord(ch) >= 32)
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(item) for item in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("交互式教程模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class TutorialReq(BaseModel):
    title: str = ""
    description: str = ""
    category: str = "Web安全"
    difficulty: str = "入门"
    duration_min: int = 30
    goals: List[str] = Field(default_factory=list)
    prerequisites: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    cover: str = ""
    author: str = "author"


class ChapterReq(BaseModel):
    title: str = "新章节"
    order: int = 1
    summary: str = ""


class BlockReq(BaseModel):
    type: str = "markdown"
    title: str = ""
    content: str = ""
    language: str = ""
    interactive_config: Dict[str, Any] = Field(default_factory=dict)
    order: int = 1


class TemplateApplyReq(BaseModel):
    template_id: str
    variables: Dict[str, str] = Field(default_factory=dict)


class VersionReq(BaseModel):
    version: str
    changelog: str = ""
    author: str = "author"


class TerminalReq(BaseModel):
    command: str
    tab_id: Optional[str] = None


class CodeRunReq(BaseModel):
    language: str = "python"
    content: str = ""


class ApiSendReq(BaseModel):
    method: str = "GET"
    url: str = "https://api.demo.test/v1/ping"
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = ""
    auth: Dict[str, str] = Field(default_factory=dict)


class SqlReq(BaseModel):
    sql: str


class SandboxReq(BaseModel):
    name: str = "lab"
    config: Dict[str, Any] = Field(default_factory=dict)


class PathReq(BaseModel):
    name: str = ""
    goal: str = ""
    stages: List[Dict[str, Any]] = Field(default_factory=list)
    milestones: List[str] = Field(default_factory=list)
    certificate: str = ""
    recommended_for: List[str] = Field(default_factory=list)


class CourseReq(BaseModel):
    title: str = ""
    category: str = "Web安全"
    difficulty: str = "基础"
    duration_h: int = 8
    instructor: str = ""


class QuizReq(BaseModel):
    title: str = ""
    time_limit_min: int = 10
    questions: List[Dict[str, Any]] = Field(default_factory=list)


class GradeReq(BaseModel):
    answers: Dict[str, Any] = Field(default_factory=dict)


class TrackReq(BaseModel):
    user_id: str = "learner_demo"
    seconds: int = 0
    activity: Dict[str, Any] = Field(default_factory=dict)


class MasteryReq(BaseModel):
    user_id: str = "learner_demo"
    knowledge_id: str = ""
    score: float = 0.0


class ExamSubmitReq(BaseModel):
    answers: Dict[str, Any] = Field(default_factory=dict)
    focus_loss: int = 0


class CertificateReq(BaseModel):
    user_id: str = "learner_demo"
    template: str = "standard"
    course_id: str = ""
    score: float = 100.0


class ScenarioReq(BaseModel):
    type: str = "penetration"
    name: str = ""
    description: str = ""
    target_env: Dict[str, Any] = Field(default_factory=dict)
    network_topology: Dict[str, Any] = Field(default_factory=dict)
    vuln_settings: List[Dict[str, Any]] = Field(default_factory=list)
    data_settings: Dict[str, Any] = Field(default_factory=dict)
    time_limit_min: int = 60
    resource_limit: Dict[str, Any] = Field(default_factory=dict)
    criteria: List[Dict[str, Any]] = Field(default_factory=list)


class SessionStartReq(BaseModel):
    user_id: str = "learner_demo"
    mode: str = "guided"


class SessionActionReq(BaseModel):
    step: str = ""
    accepted: bool = True
    cost_seconds: int = 0


class SettingsReq(BaseModel):
    patch: Dict[str, Any] = Field(default_factory=dict)


class BulkReq(BaseModel):
    ids: List[str] = Field(default_factory=list)


# =========================================================================== #
# 1. 教程内容模块（10 个端点）
# =========================================================================== #
@router.get("/content/taxonomy")
def content_taxonomy():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(tc.taxonomy())
    except Exception as e:  # noqa: BLE001
        logger.exception("content_taxonomy error")
        return fail(f"获取分类失败: {e}", 500)


@router.post("/content/tutorials")
def content_create_tutorial(req: TutorialReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(tc.create_tutorial(req.model_dump()))
    except Exception as e:  # noqa: BLE001
        logger.exception("create_tutorial error")
        return fail(f"创建教程失败: {e}", 500)


@router.get("/content/tutorials")
def content_list_tutorials(category: Optional[str] = None,
                           difficulty: Optional[str] = None,
                           keyword: Optional[str] = None,
                           status: Optional[str] = None):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(tc.list_tutorials(category, difficulty, keyword, status))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询教程失败: {e}", 500)


@router.get("/content/tutorials/{tid}")
def content_get_tutorial(tid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        t = tc.get_tutorial(tid)
        if not t:
            return fail("教程不存在", 404)
        return ok(t)
    except Exception as e:  # noqa: BLE001
        return fail(f"查询失败: {e}", 500)


@router.put("/content/tutorials/{tid}")
def content_update_tutorial(tid: str, req: TutorialReq):
    try:
        g = _guard()
        if g is not None:
            return g
        t = tc.update_tutorial(tid, req.model_dump(exclude_unset=True))
        if not t:
            return fail("教程不存在", 404)
        return ok(t)
    except Exception as e:  # noqa: BLE001
        return fail(f"更新教程失败: {e}", 500)


@router.delete("/content/tutorials/{tid}")
def content_delete_tutorial(tid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        if not tc.delete_tutorial(tid):
            return fail("教程不存在", 404)
        return ok({"deleted": tid})
    except Exception as e:  # noqa: BLE001
        return fail(f"删除失败: {e}", 500)


@router.post("/content/tutorials/{tid}/chapters")
def content_add_chapter(tid: str, req: ChapterReq):
    try:
        g = _guard()
        if g is not None:
            return g
        ch = tc.add_chapter(tid, req.model_dump())
        if not ch:
            return fail("教程不存在", 404)
        return ok(ch)
    except Exception as e:  # noqa: BLE001
        return fail(f"添加章节失败: {e}", 500)


@router.get("/content/tutorials/{tid}/chapters")
def content_list_chapters(tid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(tc.list_chapters(tid))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询章节失败: {e}", 500)


@router.post("/content/chapters/{cid}/blocks")
def content_add_block(cid: str, req: BlockReq):
    try:
        g = _guard()
        if g is not None:
            return g
        b = tc.add_block(cid, req.model_dump())
        if not b:
            return fail("章节不存在", 404)
        return ok(b)
    except Exception as e:  # noqa: BLE001
        return fail(f"添加内容块失败: {e}", 500)


@router.get("/content/chapters/{cid}/blocks")
def content_list_blocks(cid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(tc.list_blocks(cid))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询内容块失败: {e}", 500)


# 模板 + 版本（4 个端点）
@router.get("/content/templates")
def content_list_templates(ttype: Optional[str] = None):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(tc.list_templates(ttype))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询模板失败: {e}", 500)


@router.post("/content/tutorials/{tid}/apply-template")
def content_apply_template(tid: str, req: TemplateApplyReq):
    try:
        g = _guard()
        if g is not None:
            return g
        r = tc.apply_template(tid, req.template_id, req.variables)
        if not r:
            return fail("教程或模板不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        return fail(f"应用模板失败: {e}", 500)


@router.post("/content/tutorials/{tid}/versions")
def content_new_version(tid: str, req: VersionReq):
    try:
        g = _guard()
        if g is not None:
            return g
        v = tc.new_version(tid, req.version, req.changelog, req.author)
        if not v:
            return fail("教程不存在", 404)
        return ok(v)
    except Exception as e:  # noqa: BLE001
        return fail(f"创建版本失败: {e}", 500)


@router.get("/content/tutorials/{tid}/versions")
def content_list_versions(tid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(tc.list_versions(tid))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询版本失败: {e}", 500)


@router.post("/content/tutorials/{tid}/publish")
def content_publish(tid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        t = tc.publish_tutorial(tid)
        if not t:
            return fail("教程不存在", 404)
        td.audit("publish_tutorial", "admin", tid)
        return ok(t)
    except Exception as e:  # noqa: BLE001
        return fail(f"发布失败: {e}", 500)


# =========================================================================== #
# 2. 交互环境模块（6 个端点）
# =========================================================================== #
@router.post("/env/terminal/exec")
def env_terminal_exec(req: TerminalReq):
    try:
        g = _guard()
        if g is not None:
            return g
        result = ie.TERMINAL.execute(req.command, req.tab_id)
        return ok(result)
    except Exception as e:  # noqa: BLE001
        return fail(f"终端执行失败: {e}", 500)


@router.get("/env/terminal/autocomplete")
def env_terminal_autocomplete(prefix: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"prefix": prefix, "candidates": ie.TERMINAL.autocomplete(prefix)})
    except Exception as e:  # noqa: BLE001
        return fail(f"自动补全失败: {e}", 500)


@router.post("/env/code/check")
def env_code_check(req: CodeRunReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ie.CodeEditor.run_check(req.language, req.content))
    except Exception as e:  # noqa: BLE001
        return fail(f"代码检查失败: {e}", 500)


@router.post("/env/browser/navigate")
def env_browser_navigate(url: str = Query(...)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ie.BROWSER.navigate(url))
    except Exception as e:  # noqa: BLE001
        return fail(f"浏览器导航失败: {e}", 500)


@router.get("/env/browser/audit")
def env_browser_audit(url: Optional[str] = None):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ie.BROWSER.security_audit(url))
    except Exception as e:  # noqa: BLE001
        return fail(f"安全审计失败: {e}", 500)


@router.post("/env/api/send")
def env_api_send(req: ApiSendReq):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("api_debug")
        result = ie.API_DEBUG.send(req.method, req.url, req.headers,
                                  req.body, req.auth)
        curl = ie.API_DEBUG.to_curl(req.method, req.url, req.headers, req.body)
        _finish_task(task_id, {"exchange": result, "curl": curl})
        return ok({"task_id": task_id, "exchange": result, "curl": curl})
    except Exception as e:  # noqa: BLE001
        return fail(f"API调试失败: {e}", 500)


@router.post("/env/db/query")
def env_db_query(req: SqlReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ie.DB.execute(req.sql))
    except Exception as e:  # noqa: BLE001
        return fail(f"SQL执行失败: {e}", 500)


@router.get("/env/db/schema")
def env_db_schema():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ie.DB.schema())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询表结构失败: {e}", 500)


@router.post("/env/sandbox/create")
def env_sandbox_create(req: SandboxReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ie.SANDBOX.create(req.name, req.config))
    except Exception as e:  # noqa: BLE001
        return fail(f"创建沙箱失败: {e}", 500)


@router.get("/env/sandbox/list")
def env_sandbox_list():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ie.SANDBOX.list())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询沙箱失败: {e}", 500)


# =========================================================================== #
# 3. 学习路径模块（6 个端点）
# =========================================================================== #
@router.post("/learning/paths")
def learning_create_path(req: PathReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(lp.create_path(req.model_dump()))
    except Exception as e:  # noqa: BLE001
        return fail(f"创建学习路径失败: {e}", 500)


@router.get("/learning/paths")
def learning_list_paths():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(lp.list_paths())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询路径失败: {e}", 500)


@router.post("/learning/courses")
def learning_create_course(req: CourseReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(lp.create_course(req.model_dump()))
    except Exception as e:  # noqa: BLE001
        return fail(f"创建课程失败: {e}", 500)


@router.get("/learning/courses")
def learning_list_courses(category: Optional[str] = None,
                          difficulty: Optional[str] = None):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(lp.list_courses(category, difficulty))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询课程失败: {e}", 500)


@router.post("/learning/courses/{cid}/enroll")
def learning_enroll(cid: str, user_id: str = Query("learner_demo")):
    try:
        g = _guard()
        if g is not None:
            return g
        e = lp.enroll(cid, user_id)
        if not e:
            return fail("课程不存在", 404)
        return ok(e)
    except Exception as e:  # noqa: BLE001
        return fail(f"报名失败: {e}", 500)


@router.post("/learning/quizzes")
def learning_create_quiz(req: QuizReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(lp.create_quiz(req.model_dump()))
    except Exception as e:  # noqa: BLE001
        return fail(f"创建测验失败: {e}", 500)


@router.post("/learning/quizzes/{qid}/grade")
def learning_grade_quiz(qid: str, req: GradeReq):
    try:
        g = _guard()
        if g is not None:
            return g
        r = lp.grade_quiz(qid, req.answers)
        if not r:
            return fail("测验不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        return fail(f"评分失败: {e}", 500)


# =========================================================================== #
# 4. 进度评估模块（7 个端点）
# =========================================================================== #
@router.post("/progress/track")
def progress_track(req: TrackReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(pe.track_study(req.user_id, req.seconds, req.activity))
    except Exception as e:  # noqa: BLE001
        return fail(f"记录进度失败: {e}", 500)


@router.get("/progress/{user_id}")
def progress_get(user_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(pe.get_progress(user_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询进度失败: {e}", 500)


@router.post("/progress/mastery")
def progress_mastery(req: MasteryReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(pe.update_mastery(req.user_id, req.knowledge_id, req.score))
    except Exception as e:  # noqa: BLE001
        return fail(f"更新掌握度失败: {e}", 500)


@router.get("/progress/{user_id}/radar")
def progress_radar(user_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(pe.radar(user_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"获取雷达图失败: {e}", 500)


@router.post("/progress/exams/{exam_id}/submit")
def progress_submit_exam(exam_id: str, req: ExamSubmitReq):
    try:
        g = _guard()
        if g is not None:
            return g
        r = pe.submit_exam(exam_id, req.answers, req.focus_loss)
        if not r:
            return fail("考试不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        return fail(f"交卷失败: {e}", 500)


@router.post("/progress/certificates")
def progress_issue_certificate(req: CertificateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(pe.issue_certificate(req.user_id, req.template,
                                       req.course_id, req.score))
    except Exception as e:  # noqa: BLE001
        return fail(f"签发证书失败: {e}", 500)


@router.get("/progress/certificates/verify/{code}")
def progress_verify_certificate(code: str):
    try:
        g = _guard()
        if g is not None:
            return g
        c = pe.verify_certificate(code)
        if not c:
            return fail("证书验证码无效", 404)
        return ok(c)
    except Exception as e:  # noqa: BLE001
        return fail(f"验证失败: {e}", 500)


@router.get("/progress/{user_id}/report")
def progress_report(user_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(pe.learning_report(user_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"生成报告失败: {e}", 500)


# =========================================================================== #
# 5. 场景实战模块（6 个端点）
# =========================================================================== #
@router.post("/scenarios")
def scenario_create(req: ScenarioReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(sp.create_scenario(req.model_dump()))
    except Exception as e:  # noqa: BLE001
        return fail(f"创建场景失败: {e}", 500)


@router.get("/scenarios")
def scenario_list(stype: Optional[str] = None):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(sp.list_scenarios(stype))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询场景失败: {e}", 500)


@router.post("/scenarios/{sid}/sessions")
def scenario_start_session(sid: str, req: SessionStartReq):
    try:
        g = _guard()
        if g is not None:
            return g
        s = sp.start_session(sid, req.user_id, req.mode)
        if not s:
            return fail("场景不存在", 404)
        return ok(s)
    except Exception as e:  # noqa: BLE001
        return fail(f"启动演练失败: {e}", 500)


@router.post("/scenarios/sessions/{sess_id}/actions")
def scenario_action(sess_id: str, req: SessionActionReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(sp.session_action(sess_id, req.model_dump()))
    except Exception as e:  # noqa: BLE001
        return fail(f"提交操作失败: {e}", 500)


@router.get("/scenarios/sessions/{sess_id}/hint")
def scenario_hint(sess_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(sp.get_hint(sess_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"获取提示失败: {e}", 500)


@router.post("/scenarios/sessions/{sess_id}/evaluate")
def scenario_evaluate(sess_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        r = sp.evaluate_session(sess_id)
        if not r:
            return fail("会话不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        return fail(f"评估失败: {e}", 500)


@router.get("/scenarios/evaluations")
def scenario_evaluations(scenario_id: Optional[str] = None):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(sp.list_evaluations(scenario_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询评估失败: {e}", 500)


# =========================================================================== #
# 6. 运营控制台模块（6 个端点）
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(td.overview())
    except Exception as e:  # noqa: BLE001
        return fail(f"获取总览失败: {e}", 500)


@router.post("/dashboard/tutorials/bulk-publish")
def dash_bulk_publish(req: BulkReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(td.bulk_publish(req.ids))
    except Exception as e:  # noqa: BLE001
        return fail(f"批量发布失败: {e}", 500)


@router.get("/dashboard/learners")
def dash_learners():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(td.learner_list())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询学员失败: {e}", 500)


@router.get("/dashboard/content-inventory")
def dash_content_inventory():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(td.content_inventory())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询内容库存失败: {e}", 500)


@router.get("/dashboard/assessment-stats")
def dash_assessment_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(td.assessment_stats())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询评估统计失败: {e}", 500)


@router.get("/dashboard/settings")
def dash_get_settings():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(td.get_settings())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询设置失败: {e}", 500)


@router.post("/dashboard/settings")
def dash_update_settings(req: SettingsReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(td.update_settings(req.patch))
    except Exception as e:  # noqa: BLE001
        return fail(f"更新设置失败: {e}", 500)


@router.get("/dashboard/audit-logs")
def dash_audit_logs(limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(td.list_audit_logs(limit))
    except Exception as e:  # noqa: BLE001
        return fail(f"查询审计日志失败: {e}", 500)


@router.get("/dashboard/env-snapshot")
def dash_env_snapshot():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(td.env_snapshot())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询环境快照失败: {e}", 500)
