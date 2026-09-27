# -*- coding: utf-8 -*-
"""
bug_bounty_routes.py — 漏洞赏金 / SRC 管理平台 REST API（40 个端点）。

路由前缀: /api/v1/bug-bounty
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

设计定位：合法 SRC 平台管理端，管理项目、接收白帽提交、评定奖励、跟踪修复。
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

router = APIRouter(prefix="/api/v1/bug-bounty", tags=["漏洞赏金/SRC管理"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from bug_bounty import program_manager as pm
    from bug_bounty import submission_workflow as sw
    from bug_bounty import hunter_community as hc
    from bug_bounty import bounty_finance as bf
    from bug_bounty import vulnerability_lifecycle as vl
    from bug_bounty import src_dashboard as dash
    pm.seed_demo(); sw.seed_demo(); hc.seed_demo()
    bf.seed_demo(); vl.seed_demo()
    _MOD_AVAILABLE = True
    logger.info("bug_bounty_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("bug_bounty_routes: load failed: %s", e)


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
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理数据中的控制字符与无效 Unicode，防止 JSON 序列化失败。"""
    if isinstance(obj, str):
        obj = obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(item) for item in obj]
    if isinstance(obj, tuple):
        return [_clean(item) for item in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("漏洞赏金/SRC 模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ProjectCreate(BaseModel):
    name: str = ""
    description: str = ""
    type: str = "public"
    industry: str = "互联网"
    logo: str = ""
    rules: str = ""
    reward_overview: str = ""
    start_date: str = ""
    end_date: str = ""
    owner: str = "platform"
    milestones: List[Dict[str, Any]] = Field(default_factory=list)


class ProjectPatch(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    type: Optional[str] = None
    industry: Optional[str] = None
    rules: Optional[str] = None
    reward_overview: Optional[str] = None
    end_date: Optional[str] = None


class ScopeIn(BaseModel):
    type: str = "domain"
    value: str = ""
    description: str = ""
    priority: str = "normal"
    is_excluded: bool = False
    sensitive_restrictions: List[str] = Field(default_factory=list)


class BountyRulesPatch(BaseModel):
    amounts: Optional[Dict[str, List[float]]] = None
    duplicate_policy: Optional[str] = None
    info_disclosure_policy: Optional[str] = None
    multiplier_by_level: Optional[Dict[str, float]] = None
    max_per_vuln: Optional[float] = None
    min_payout: Optional[float] = None


class AnnouncementIn(BaseModel):
    title: str = ""
    content: str = ""
    level: str = "info"


class SubmissionIn(BaseModel):
    project_id: str = ""
    reporter_id: str = "anon"
    title: str = ""
    vuln_type: str = "other"
    severity: str = "medium"
    target: str = ""
    repro_steps: str = ""
    impact: str = ""
    fix_suggestion: str = ""
    poc: str = ""
    screenshots: List[str] = Field(default_factory=list)
    video: str = ""
    references: List[str] = Field(default_factory=list)
    fingerprint: str = ""
    impact_scope: str = "dept"
    exploit_difficulty: str = "medium"
    report_quality: str = "good"
    attachments: List[Dict[str, Any]] = Field(default_factory=list)


class ReviewIn(BaseModel):
    step: str = "triage"
    status: str = "triage"
    reviewer: str = "admin"
    note: str = ""
    attachments: List[Dict[str, Any]] = Field(default_factory=list)
    override_score: Optional[float] = None


class DupLinkIn(BaseModel):
    original_id: str
    reward_note: str = ""


class CommentIn(BaseModel):
    author: str = "anon"
    body: str = ""
    kind: str = "comment"


class HunterIn(BaseModel):
    nickname: str = ""
    email: str = ""
    bio: str = ""
    skill_tags: List[str] = Field(default_factory=list)
    region: str = ""
    level: str = "newbie"


class WriteupIn(BaseModel):
    title: str = ""
    content: str = ""
    tags: List[str] = Field(default_factory=list)
    public: bool = True


class DisputeIn(BaseModel):
    vuln_id: str = ""
    reason: str = ""
    evidence: str = ""


class PaymentIn(BaseModel):
    vuln_id: str = ""
    project_id: str = ""
    hunter_id: str = ""
    method: str = "cash"
    amount: float = 0.0
    currency: str = "CNY"
    need_tax: bool = True
    note: str = ""


class BudgetIn(BaseModel):
    total: float = 0.0
    warning_pct: float = 0.8


class FixAssignIn(BaseModel):
    vuln_id: str = ""
    assignee: str = ""
    due_date: str = ""
    note: str = ""


class KbArticleIn(BaseModel):
    vuln_id: str = ""
    title: str = ""
    type: str = "writeup"
    content: str = ""
    analysis: str = ""
    fix_guidance: str = ""
    tags: List[str] = Field(default_factory=list)
    score: int = 0


class ExternalIn(BaseModel):
    platform: str = ""
    api_endpoint: str = ""
    api_key_ref: str = ""
    enabled: bool = True


class ExportIn(BaseModel):
    kind: str = "project_report"
    fmt: str = "json"
    payload: Dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# 1) 项目管理
# --------------------------------------------------------------------------- #
@router.get("/projects")
def list_projects(status: Optional[str] = None,
                  industry: Optional[str] = None):
    try:
        g = _guard()
        if g: return g
        return ok(pm.list_projects(status=status, industry=industry))
    except Exception as e:
        logger.exception("list_projects failed")
        return fail(str(e), 500)


@router.post("/projects")
def create_project(body: ProjectCreate):
    try:
        g = _guard()
        if g: return g
        return ok(pm.create_project(body.dict()))
    except Exception as e:
        logger.exception("create_project failed")
        return fail(str(e), 500)


@router.get("/projects/{pid}")
def get_project(pid: str):
    try:
        g = _guard()
        if g: return g
        p = pm.get_project(pid)
        if not p: return fail("项目不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(str(e), 500)


@router.patch("/projects/{pid}")
def update_project(pid: str, body: ProjectPatch):
    try:
        g = _guard()
        if g: return g
        p = pm.update_project(pid, {k: v for k, v in body.dict().items() if v is not None})
        if not p: return fail("项目不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/projects/{pid}/transition")
def transition_project(pid: str, new_status: str = Query(...),
                       note: str = ""):
    try:
        g = _guard()
        if g: return g
        return ok(pm.transition_status(pid, new_status, note))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/projects/{pid}/scopes")
def list_scopes(pid: str, only_in: bool = False):
    try:
        g = _guard()
        if g: return g
        return ok(pm.list_scopes(pid, only_in_scope=only_in))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/projects/{pid}/scopes")
def add_scope(pid: str, body: ScopeIn):
    try:
        g = _guard()
        if g: return g
        return ok(pm.add_scope(pid, body.dict()))
    except Exception as e:
        return fail(str(e), 500)


@router.delete("/projects/{pid}/scopes/{sid}")
def remove_scope(pid: str, sid: str):
    try:
        g = _guard()
        if g: return g
        return ok({"removed": pm.remove_scope(pid, sid)})
    except Exception as e:
        return fail(str(e), 500)


@router.get("/projects/{pid}/bounty-rules")
def get_rules(pid: str):
    try:
        g = _guard()
        if g: return g
        return ok(pm.get_bounty_rules(pid))
    except Exception as e:
        return fail(str(e), 500)


@router.put("/projects/{pid}/bounty-rules")
def update_rules(pid: str, body: BountyRulesPatch):
    try:
        g = _guard()
        if g: return g
        patch = {k: v for k, v in body.dict().items() if v is not None}
        return ok(pm.update_bounty_rules(pid, patch))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/projects/{pid}/announcements")
def publish_announcement(pid: str, body: AnnouncementIn):
    try:
        g = _guard()
        if g: return g
        return ok(pm.publish_announcement(pid, body.title, body.content, body.level))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/projects/{pid}/announcements")
def list_announcements(pid: str):
    try:
        g = _guard()
        if g: return g
        return ok(pm.list_announcements(pid))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/projects/{pid}/changelog")
def list_changelog(pid: str):
    try:
        g = _guard()
        if g: return g
        return ok(pm.list_changelog(pid))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/projects/{pid}/stats")
def project_stats(pid: str):
    try:
        g = _guard()
        if g: return g
        return ok(pm.project_stats(pid))
    except Exception as e:
        return fail(str(e), 500)


# --------------------------------------------------------------------------- #
# 2) 漏洞提交与审核
# --------------------------------------------------------------------------- #
@router.post("/submissions")
def submit_vuln(body: SubmissionIn):
    try:
        g = _guard()
        if g: return g
        return ok(sw.submit_vuln(body.dict()))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/submissions")
def list_submissions(project_id: Optional[str] = None,
                     status: Optional[str] = None,
                     hunter_id: Optional[str] = None):
    try:
        g = _guard()
        if g: return g
        return ok(sw.list_submissions(project_id=project_id,
                                      status=status, hunter_id=hunter_id))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/submissions/{vid}")
def get_submission(vid: str):
    try:
        g = _guard()
        if g: return g
        v = sw.get_submission(vid)
        if not v: return fail("漏洞不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/submissions/{vid}/review")
def review_step(vid: str, body: ReviewIn):
    try:
        g = _guard()
        if g: return g
        return ok(sw.review_step(vid, body.step, body.status, body.reviewer,
                                  body.note, body.attachments, body.override_score))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/submissions/{vid}/duplicate-link")
def link_dup(vid: str, body: DupLinkIn):
    try:
        g = _guard()
        if g: return g
        return ok(sw.link_duplicate(vid, body.original_id, body.reward_note))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/submissions/{vid}/comments")
def add_comment(vid: str, body: CommentIn):
    try:
        g = _guard()
        if g: return g
        return ok(sw.add_comment(vid, body.author, body.body, body.kind))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/submissions/{vid}/comments")
def list_comments(vid: str):
    try:
        g = _guard()
        if g: return g
        return ok(sw.list_comments(vid))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/submissions/{vid}/attachments")
def list_attachments(vid: str):
    try:
        g = _guard()
        if g: return g
        return ok(sw.list_attachments(vid))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/submissions/{vid}/history")
def status_history(vid: str):
    try:
        g = _guard()
        if g: return g
        return ok(sw.status_history(vid))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/scoring/suggest")
def score_suggest(severity: str = "medium",
                  impact_scope: str = "dept",
                  exploit_difficulty: str = "medium",
                  report_quality: str = "good"):
    try:
        g = _guard()
        if g: return g
        return ok(sw.suggest_score(severity, impact_scope,
                                   exploit_difficulty, report_quality))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/duplicate-check")
def dup_check(title: str = "", target: str = "",
              vuln_type: str = "", fingerprint: str = ""):
    try:
        g = _guard()
        if g: return g
        return ok(sw.detect_duplicate({
            "title": title, "target": target,
            "vuln_type": vuln_type, "fingerprint": fingerprint,
        }))
    except Exception as e:
        return fail(str(e), 500)


# --------------------------------------------------------------------------- #
# 3) 白帽社区
# --------------------------------------------------------------------------- #
@router.post("/hunters")
def register_hunter(body: HunterIn):
    try:
        g = _guard()
        if g: return g
        return ok(hc.register_hunter(body.dict()))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/hunters")
def list_hunters(status: Optional[str] = None,
                 skill: Optional[str] = None):
    try:
        g = _guard()
        if g: return g
        return ok(hc.list_hunters(status=status, skill=skill))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/hunters/{hid}")
def get_hunter(hid: str):
    try:
        g = _guard()
        if g: return g
        h = hc.get_hunter(hid)
        if not h: return fail("白帽不存在", 404)
        return ok(h)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/hunters/{hid}/rep")
def update_rep(hid: str, delta: int = 0, reason: str = ""):
    try:
        g = _guard()
        if g: return g
        return ok(hc.update_reputation(hid, delta, reason))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/leaderboard")
def board(metric: str = "points", period: str = "all",
          limit: int = 20):
    try:
        g = _guard()
        if g: return g
        return ok(hc.leaderboard(metric=metric, period=period, limit=limit))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/permissions/{level}")
def perms(level: str):
    try:
        g = _guard()
        if g: return g
        return ok(hc.get_permissions(level))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/writeups")
def post_writeup(body: WriteupIn,
                 hunter_id: str = Query("anon")):
    try:
        g = _guard()
        if g: return g
        return ok(hc.post_writeup(hunter_id, body.title, body.content,
                                   body.tags, body.public))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/writeups")
def list_writeups(public_only: bool = True):
    try:
        g = _guard()
        if g: return g
        return ok(hc.list_writeups(public_only=public_only))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/disputes")
def open_dispute(body: DisputeIn,
                 hunter_id: str = Query("anon")):
    try:
        g = _guard()
        if g: return g
        return ok(hc.open_dispute(hunter_id, body.vuln_id,
                                  body.reason, body.evidence))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/disputes")
def list_disputes(status: Optional[str] = None):
    try:
        g = _guard()
        if g: return g
        return ok(hc.list_disputes(status=status))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/disputes/{did}/resolve")
def resolve_dispute(did: str, result: str = "reject",
                    note: str = "", arbiter: str = "admin"):
    try:
        g = _guard()
        if g: return g
        return ok(hc.resolve_dispute(did, result, note, arbiter))
    except Exception as e:
        return fail(str(e), 500)


# --------------------------------------------------------------------------- #
# 4) 赏金财务
# --------------------------------------------------------------------------- #
@router.post("/bounty/estimate")
def estimate(severity: str = "medium",
             impact_scope: str = "dept",
             exploit_difficulty: str = "medium",
             report_quality: str = "good",
             level_multiplier: float = 1.0,
             cap: float = 200000.0, floor: float = 100.0):
    try:
        g = _guard()
        if g: return g
        return ok(bf.estimate_bounty(severity, impact_scope,
                                    exploit_difficulty, report_quality,
                                    level_multiplier, cap, floor))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/payments")
def issue_payment(body: PaymentIn):
    try:
        g = _guard()
        if g: return g
        return ok(bf.issue_payment(body.dict()))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/payments")
def list_payments(project_id: Optional[str] = None,
                  hunter_id: Optional[str] = None,
                  status: Optional[str] = None):
    try:
        g = _guard()
        if g: return g
        return ok(bf.list_payments(project_id=project_id,
                                  hunter_id=hunter_id, status=status))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/payments/{pid}/confirm")
def confirm_payment(pid: str, by: str = "finance"):
    try:
        g = _guard()
        if g: return g
        return ok(bf.confirm_payment(pid, by))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/finance/summary")
def finance_summary(project_id: Optional[str] = None):
    try:
        g = _guard()
        if g: return g
        return ok(bf.finance_summary(project_id=project_id))
    except Exception as e:
        return fail(str(e), 500)


@router.put("/budgets/{pid}")
def set_budget(pid: str, body: BudgetIn):
    try:
        g = _guard()
        if g: return g
        return ok(bf.set_budget(pid, body.total, body.warning_pct))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/budgets/{pid}")
def budget_status(pid: str):
    try:
        g = _guard()
        if g: return g
        return ok(bf.budget_status(pid))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/tax/{payment_id}")
def tax_info(payment_id: str):
    try:
        g = _guard()
        if g: return g
        info = bf.tax_info(payment_id)
        if not info: return fail("支付单不存在", 404)
        return ok(info)
    except Exception as e:
        return fail(str(e), 500)


# --------------------------------------------------------------------------- #
# 5) 漏洞生命周期
# --------------------------------------------------------------------------- #
@router.post("/fix/assign")
def assign_fix(body: FixAssignIn):
    try:
        g = _guard()
        if g: return g
        return ok(vl.assign_fix(body.vuln_id, body.assignee,
                                body.due_date, body.note))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/fix/tasks")
def list_fix(status: Optional[str] = None):
    try:
        g = _guard()
        if g: return g
        return ok(vl.list_fix_tasks(status=status))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/fix/tasks/{tid}/progress")
def progress(tid: str, progress: int = 0,
             commit_hash: str = "", commit_msg: str = ""):
    try:
        g = _guard()
        if g: return g
        commit = {"hash": commit_hash, "msg": commit_msg} if commit_hash else None
        return ok(vl.update_fix_progress(tid, progress, commit))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/fix/tasks/{tid}/verify")
def verify(tid: str, verifier: str = "qa",
           passed: bool = True, note: str = ""):
    try:
        g = _guard()
        if g: return g
        return ok(vl.verify_fix(tid, verifier, passed, note))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/sla/check")
def sla_check(severity: str = "high",
              submitted_at: str = "",
              responded_at: Optional[str] = None,
              fixed_at: Optional[str] = None):
    try:
        g = _guard()
        if g: return g
        return ok(vl.sla_check(severity, submitted_at or
                              time.strftime("%Y-%m-%d %H:%M:%S"),
                              responded_at, fixed_at))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/kb")
def add_kb(body: KbArticleIn):
    try:
        g = _guard()
        if g: return g
        return ok(vl.add_kb_article(body.dict()))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/kb/search")
def search_kb(q: str = "", tag: Optional[str] = None):
    try:
        g = _guard()
        if g: return g
        return ok(vl.search_kb(query=q, tag=tag))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/external/config")
def ext_cfg(body: ExternalIn):
    try:
        g = _guard()
        if g: return g
        return ok(vl.configure_external(body.platform, body.api_endpoint,
                                       body.api_key_ref, body.enabled))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/external/{platform}/sync")
def ext_sync(platform: str):
    try:
        g = _guard()
        if g: return g
        return ok(vl.sync_external(platform))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/export")
def export(body: ExportIn):
    try:
        g = _guard()
        if g: return g
        return ok(vl.export_report(body.kind, body.fmt, body.payload))
    except Exception as e:
        return fail(str(e), 500)


# --------------------------------------------------------------------------- #
# 6) 仪表盘
# --------------------------------------------------------------------------- #
@router.get("/dashboard/overview")
def dash_overview():
    try:
        g = _guard()
        if g: return g
        return ok(dash.overview())
    except Exception as e:
        return fail(str(e), 500)


@router.get("/dashboard/activity")
def dash_activity(limit: int = 20):
    try:
        g = _guard()
        if g: return g
        return ok(dash.recent_activity(limit=limit))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/dashboard/vuln-distribution")
def dash_vuln_dist():
    try:
        g = _guard()
        if g: return g
        return ok(dash.vuln_distribution())
    except Exception as e:
        return fail(str(e), 500)


@router.get("/dashboard/hunter-ecosystem")
def dash_hunter_eco():
    try:
        g = _guard()
        if g: return g
        return ok(dash.hunter_ecosystem())
    except Exception as e:
        return fail(str(e), 500)


@router.get("/dashboard/metrics")
def dash_metrics():
    try:
        g = _guard()
        if g: return g
        return ok(dash.operational_metrics())
    except Exception as e:
        return fail(str(e), 500)


@router.get("/dashboard/health")
def dash_health():
    try:
        g = _guard()
        if g: return g
        return ok(dash.project_health())
    except Exception as e:
        return fail(str(e), 500)


# --------------------------------------------------------------------------- #
# 任务查询（异步模拟）
# --------------------------------------------------------------------------- #
@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        t = _TASKS.get(task_id)
        if not t: return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e), 500)
