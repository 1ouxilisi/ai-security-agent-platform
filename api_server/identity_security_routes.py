# -*- coding: utf-8 -*-
"""
identity_security_routes.py — 身份安全与 IAM REST API（36 个端点）。

路由前缀: /api/v1/identity-security
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

设计定位：仅做授权范围内的身份治理/检测/审计视角分析，输出报告与建议。
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

router = APIRouter(prefix="/api/v1/identity-security", tags=["身份安全与IAM"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from identity_security.identity_governance import (
        IdentityGovernance, DIRECTORY_TYPES, LIFECYCLE_STAGES, ACCOUNT_STATES,
    )
    from identity_security.permission_audit import PermissionAuditor
    from identity_security.identity_threat_detection import IdentityThreatDetector
    from identity_security.privileged_access import PrivilegedAccessManager
    from identity_security.access_authentication import AccessAuthentication
    from identity_security.identity_dashboard import IdentityDashboard
    _MOD_AVAILABLE = True
    logger.info("identity_security_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("identity_security_routes: load failed: %s", e)


# 单例（内存态）
_GOV: Optional[Any] = None
_AUDIT: Optional[Any] = None
_THREAT: Optional[Any] = None
_PAM: Optional[Any] = None
_AUTH: Optional[Any] = None
_DASH: Optional[Any] = None


def _engines() -> None:
    global _GOV, _AUDIT, _THREAT, _PAM, _AUTH, _DASH
    if not _MOD_AVAILABLE:
        return
    if _GOV is None:
        _GOV = IdentityGovernance()
        _AUDIT = PermissionAuditor()
        _THREAT = IdentityThreatDetector()
        _PAM = PrivilegedAccessManager()
        _AUTH = AccessAuthentication()
        _DASH = IdentityDashboard()


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


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return _TASKS.get(task_id)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符与无效 Unicode 代理对。"""
    if isinstance(obj, str):
        obj = obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t"
                       or ord(ch) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(i) for i in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("身份安全模块不可用，请检查加载日志", 503)
    return None


def _task_view(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"task_id": t["task_id"], "status": t["status"], "kind": t["kind"],
            "created_at": t["created_at"], "finished_at": t["finished_at"]}


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class UserCreateRequest(BaseModel):
    username: str = ""
    name: str = ""
    email: str = ""
    dept: str = ""
    title: str = ""
    manager: str = ""
    roles: List[str] = Field(default_factory=list)
    mfa_enabled: bool = False


class UserUpdateRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    dept: Optional[str] = None
    title: Optional[str] = None
    state: Optional[str] = None
    lifecycle: Optional[str] = None
    manager: Optional[str] = None
    mfa_enabled: Optional[bool] = None
    roles: Optional[List[str]] = None


class ReviewActionRequest(BaseModel):
    action: str = "approve_all"
    comment: str = ""


class PrivRequestCreate(BaseModel):
    requester: str
    uid: str
    acct: str
    justification: str
    duration_min: int = 60


class PrivRequestDecision(BaseModel):
    approver: str
    decision: str = "approve"


class AccessRequestCreate(BaseModel):
    requester: str
    app: str
    entitlement: str
    justification: str
    duration_days: int = 30


class PolicyUpdate(BaseModel):
    patch: Dict[str, Any] = Field(default_factory=dict)


class AccessSimulate(BaseModel):
    user: str
    action: str
    resource: str
    ctx: Dict[str, Any] = Field(default_factory=dict)


# =========================================================================== #
# 1. 身份治理与目录（8 个端点）
# =========================================================================== #
@router.get("/governance/users")
def gov_list_users(dept: Optional[str] = Query(default=None),
                   state: Optional[str] = Query(default=None),
                   q: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_GOV.list_users(dept=dept, state=state, q=q))
    except Exception as e:
        logger.exception("gov_list_users")
        return fail(f"查询用户失败: {e}", 500)


@router.get("/governance/users/{uid}")
def gov_get_user(uid: str):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        u = _GOV.get_user(uid)
        if not u:
            return fail("用户不存在", 404)
        return ok(u)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/governance/users")
def gov_create_user(req: UserCreateRequest):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_GOV.create_user(req.model_dump()))
    except Exception as e:
        return fail(f"创建用户失败: {e}", 500)


@router.put("/governance/users/{uid}")
def gov_update_user(uid: str, req: UserUpdateRequest):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        patch = {k: v for k, v in req.model_dump().items() if v is not None}
        u = _GOV.update_user(uid, patch)
        if not u:
            return fail("用户不存在", 404)
        return ok(u)
    except Exception as e:
        return fail(f"更新用户失败: {e}", 500)


@router.delete("/governance/users/{uid}")
def gov_delete_user(uid: str):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        ok_del = _GOV.delete_user(uid)
        if not ok_del:
            return fail("用户不存在", 404)
        return ok({"deleted": uid})
    except Exception as e:
        return fail(f"删除用户失败: {e}", 500)


@router.get("/governance/directories")
def gov_directories():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_GOV.list_directories())
    except Exception as e:
        return fail(f"查询目录失败: {e}", 500)


@router.post("/governance/directories/{dir_id}/sync")
def gov_sync_directory(dir_id: str):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        r = _GOV.sync_directory(dir_id)
        if not r.get("ok"):
            return fail(r.get("reason", "同步失败"), 400)
        return ok(r)
    except Exception as e:
        return fail(f"同步目录失败: {e}", 500)


@router.get("/governance/graph")
def gov_graph():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_GOV.build_identity_graph())
    except Exception as e:
        return fail(f"生成身份图谱失败: {e}", 500)


@router.get("/governance/lifecycle")
def gov_lifecycle(uid: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_GOV.lifecycle_events(uid=uid))
    except Exception as e:
        return fail(f"查询生命周期失败: {e}", 500)


@router.get("/governance/data-quality")
def gov_data_quality():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        task_id = _new_task("data_quality")
        result = _GOV.data_quality()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"数据质量分析失败: {e}", 500)


# =========================================================================== #
# 2. 权限审计（7 个端点）
# =========================================================================== #
@router.get("/permission/matrix")
def perm_matrix():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUDIT.inventory())
    except Exception as e:
        return fail(f"权限盘点失败: {e}", 500)


@router.get("/permission/risk")
def perm_risk():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        task_id = _new_task("permission_risk")
        result = _AUDIT.risk_assessment()
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        return fail(f"权限风险评估失败: {e}", 500)


@router.get("/permission/reviews")
def perm_reviews():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUDIT.reviews())
    except Exception as e:
        return fail(f"查询复核工作流失败: {e}", 500)


@router.post("/permission/reviews/{review_id}/action")
def perm_review_action(review_id: str, req: ReviewActionRequest):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        r = _AUDIT.review_action(review_id, req.action, req.comment)
        if not r.get("ok"):
            return fail(r.get("reason", "操作失败"), 400)
        return ok(r)
    except Exception as e:
        return fail(f"复核操作失败: {e}", 500)


@router.get("/permission/least-privilege")
def perm_least_priv():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUDIT.least_privilege())
    except Exception as e:
        return fail(f"最小权限分析失败: {e}", 500)


@router.get("/permission/changes")
def perm_changes(limit: int = Query(default=50, ge=1, le=500)):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUDIT.changes(limit=limit))
    except Exception as e:
        return fail(f"查询权限变更失败: {e}", 500)


@router.get("/permission/task/{task_id}/results")
def perm_task_results(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        if t["status"] != "done":
            return fail(f"任务未完成: {t['status']}", 400)
        return ok(t["result"])
    except Exception as e:
        return fail(f"查询任务失败: {e}", 500)


# =========================================================================== #
# 3. 身份威胁检测（5 个端点）
# =========================================================================== #
@router.get("/threat/baselines")
def threat_baselines():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_THREAT.baselines())
    except Exception as e:
        return fail(f"查询基线失败: {e}", 500)


@router.get("/threat/anomalous-logins")
def threat_anomalies(event_type: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_THREAT.anomalous_logins(event_type=event_type))
    except Exception as e:
        return fail(f"查询异常登录失败: {e}", 500)


@router.get("/threat/credential-abuse")
def threat_abuse():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_THREAT.credential_abuse())
    except Exception as e:
        return fail(f"凭据滥用分析失败: {e}", 500)


@router.get("/threat/attack-chains")
def threat_chains():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_THREAT.attack_chains())
    except Exception as e:
        return fail(f"攻击链分析失败: {e}", 500)


@router.get("/threat/mfa-analysis")
def threat_mfa():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_THREAT.mfa_analysis())
    except Exception as e:
        return fail(f"MFA 分析失败: {e}", 500)


# =========================================================================== #
# 4. 特权账户 PAM（7 个端点）
# =========================================================================== #
@router.get("/pam/accounts")
def pam_accounts():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_PAM.inventory())
    except Exception as e:
        return fail(f"特权账户盘点失败: {e}", 500)


@router.get("/pam/risk")
def pam_risk():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_PAM.risk_assessment())
    except Exception as e:
        return fail(f"特权风险评估失败: {e}", 500)


@router.get("/pam/sessions")
def pam_sessions():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_PAM.sessions())
    except Exception as e:
        return fail(f"查询特权会话失败: {e}", 500)


@router.get("/pam/sessions/{sid}/replay")
def pam_replay(sid: str):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        r = _PAM.session_replay(sid)
        if not r:
            return fail("会话不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(f"会话回放失败: {e}", 500)


@router.get("/pam/requests")
def pam_requests():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_PAM.access_requests())
    except Exception as e:
        return fail(f"查询特权申请失败: {e}", 500)


@router.post("/pam/requests")
def pam_create_request(req: PrivRequestCreate):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_PAM.create_request(req.requester, req.uid, req.acct,
                                      req.justification, req.duration_min))
    except Exception as e:
        return fail(f"创建特权申请失败: {e}", 500)


@router.post("/pam/requests/{req_id}/decision")
def pam_decide(req_id: str, req: PrivRequestDecision):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        r = _PAM.approve_request(req_id, req.approver, req.decision)
        if not r.get("ok"):
            return fail(r.get("reason", "操作失败"), 400)
        return ok(r)
    except Exception as e:
        return fail(f"审批操作失败: {e}", 500)


@router.get("/pam/service-accounts")
def pam_services():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_PAM.service_accounts())
    except Exception as e:
        return fail(f"服务账户查询失败: {e}", 500)


# =========================================================================== #
# 5. 访问认证与 SSO（6 个端点）
# =========================================================================== #
@router.get("/auth/policies")
def auth_policies():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUTH.list_policies())
    except Exception as e:
        return fail(f"查询认证策略失败: {e}", 500)


@router.put("/auth/policies/{policy_id}")
def auth_update_policy(policy_id: str, req: PolicyUpdate):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        p = _AUTH.update_policy(policy_id, req.patch)
        if not p:
            return fail("策略不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(f"更新策略失败: {e}", 500)


@router.get("/auth/sso")
def auth_sso():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUTH.sso_inventory())
    except Exception as e:
        return fail(f"查询 SSO 失败: {e}", 500)


@router.get("/auth/access-models")
def auth_models():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUTH.access_control_models())
    except Exception as e:
        return fail(f"查询访问控制模型失败: {e}", 500)


@router.post("/auth/simulate")
def auth_simulate(req: AccessSimulate):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUTH.simulate_access(req.user, req.action, req.resource,
                                         req.ctx))
    except Exception as e:
        return fail(f"策略模拟失败: {e}", 500)


@router.get("/auth/access-requests")
def auth_requests():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUTH.access_requests())
    except Exception as e:
        return fail(f"查询访问申请失败: {e}", 500)


@router.post("/auth/access-requests")
def auth_create_request(req: AccessRequestCreate):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUTH.create_access_request(req.requester, req.app,
                                               req.entitlement,
                                               req.justification,
                                               req.duration_days))
    except Exception as e:
        return fail(f"创建访问申请失败: {e}", 500)


@router.get("/auth/logs")
def auth_logs(limit: int = Query(default=100, ge=1, le=1000)):
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_AUTH.auth_logs(limit=limit))
    except Exception as e:
        return fail(f"查询认证日志失败: {e}", 500)


# =========================================================================== #
# 6. 仪表盘（5 个端点）
# =========================================================================== #
@router.get("/dashboard/posture")
def dash_posture():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_DASH.posture)
    except Exception as e:
        return fail(f"查询态势失败: {e}", 500)


@router.get("/dashboard/alerts")
def dash_alerts():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_DASH.alerts())
    except Exception as e:
        return fail(f"查询告警失败: {e}", 500)


@router.get("/dashboard/heatmap")
def dash_heatmap():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_DASH.heatmap())
    except Exception as e:
        return fail(f"查询热力图失败: {e}", 500)


@router.get("/dashboard/compliance")
def dash_compliance():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_DASH.compliance())
    except Exception as e:
        return fail(f"查询合规失败: {e}", 500)


@router.get("/dashboard/metrics")
def dash_metrics():
    try:
        g = _guard()
        if g:
            return g
        _engines()
        return ok(_DASH.metrics())
    except Exception as e:
        return fail(f"查询度量失败: {e}", 500)


# --------------------------------------------------------------------------- #
# 健康检查
# --------------------------------------------------------------------------- #
@router.get("/health")
def health():
    return ok({"module": "identity_security",
               "available": _MOD_AVAILABLE,
               "endpoints": 40,
               "ts": time.strftime("%Y-%m-%d %H:%M:%S")})
