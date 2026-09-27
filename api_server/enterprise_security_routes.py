# -*- coding: utf-8 -*-
"""
enterprise_security_routes.py — 方向5：企业级安全与合规 REST API（27 端点）。

路由前缀: /api/v1/enterprise

认证/鉴权说明（演示）:
  - 通过请求头 X-User-Id 指定当前调用者（默认 U00001 管理员）。
  - 写操作 / 受限资源按 RBAC require() 校验功能权限，不足返回 403。
  - 所有关键操作写入审计日志（用户/时间/动作/对象/IP/结果）。
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/enterprise",
                   tags=["企业级安全与合规"])

# --------------------------------------------------------------------------- #
# 子系统实例（单例，内存）
# --------------------------------------------------------------------------- #
_MOD_OK = False
try:
    from enterprise_security.rbac import RBACManager, PermissionDenied, VALID_ROLES
    from enterprise_security.audit_log import AuditLogger
    from enterprise_security.data_encryption import DataEncryption
    from enterprise_security.security_baseline import SecurityBaseline
    from enterprise_security.compliance_report import ComplianceReportGenerator
    from enterprise_security.enterprise_dashboard import EnterpriseDashboard

    rbac = RBACManager()
    audit = AuditLogger()
    crypto = DataEncryption()
    baseline = SecurityBaseline()
    compliance = ComplianceReportGenerator()
    dashboard = EnterpriseDashboard(rbac, audit, crypto, baseline, compliance)

    # 预置几个演示凭据
    crypto.store_secret("scan_engine_token", "sk-scan-engine-demo-9f8e7d6c",
                        meta={"type": "api_key", "owner": "analyst_zhang"})
    crypto.store_secret("db_master_password", "P@ssw0rd!2026#secure",
                        meta={"type": "password", "owner": "admin"})
    _MOD_OK = True
    logger.info("enterprise_security_routes: all subsystems loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("enterprise_security_routes load failed: %s", e)
    rbac = audit = crypto = baseline = compliance = dashboard = None  # type: ignore


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c == "\n" or c == "\t" or ord(c) >= 32)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_OK:
        return fail("企业安全模块未加载", 503)
    return None


def _caller(request: Request) -> str:
    """从请求头解析当前用户，默认管理员。"""
    uid = request.headers.get("X-User-Id", "U00001")
    return uid


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "0.0.0.0"


def _authz(request: Request, permission: str) -> Any:
    """鉴权 + 审计钩子。返回 (user_info, error_response)。
    通过则 (user, None)；不通过则 (None, JSONResponse)。
    """
    uid = _caller(request)
    try:
        user = rbac.require(uid, permission)
    except PermissionDenied as e:
        audit.record(uid, f"denied:{permission}", "-",
                     ip=_client_ip(request), result="denied",
                     detail=str(e), status_code=403)
        return None, fail(str(e), 403)
    except KeyError as e:
        return None, fail(str(e), 404)
    return user, None


def _audit(request: Request, action: str, target: str,
           result: str = "success", detail: str = "",
           status_code: int = 200) -> None:
    audit.record(_caller(request), action, target,
                 ip=_client_ip(request), result=result,
                 detail=detail, status_code=status_code)


# =========================================================================== #
# 1. RBAC 权限体系（8 端点）
# =========================================================================== #
@router.get("/rbac/roles")
def rbac_roles():
    """角色 / 权限元数据。"""
    if _guard():
        return _guard()
    return ok(rbac.roles_meta())


@router.get("/rbac/users")
def rbac_list_users(request: Request):
    user, err = _authz(request, "user.manage")
    if err:
        return err
    users = rbac.list_users()
    _audit(request, "user.list", "rbac_users", detail=f"返回{len(users)}用户")
    return ok({"users": users, "count": len(users)})


@router.post("/rbac/users/create")
def rbac_create_user(request: Request,
                     display_name: str = Body(...),
                     role: str = Body(...),
                     email: str = Body(""),
                     username: str = Body("")):
    user, err = _authz(request, "user.manage")
    if err:
        return err
    try:
        nu = rbac.create_user(display_name, role, email=email, username=username)
    except PermissionDenied as e:
        _audit(request, "user.create", role, result="failed", detail=str(e), status_code=400)
        return fail(str(e), 400)
    _audit(request, "user.create", nu["user_id"],
           detail=f"创建 {display_name} 角色={role}")
    return ok(nu)


@router.get("/rbac/users/{user_id}")
def rbac_get_user(user_id: str, request: Request):
    user, err = _authz(request, "user.manage")
    if err:
        return err
    u = rbac.get_user(user_id)
    if not u:
        return fail("用户不存在", 404)
    return ok(u)


@router.put("/rbac/users/{user_id}/role")
def rbac_change_role(user_id: str, request: Request,
                     new_role: str = Body(..., embed=True)):
    user, err = _authz(request, "user.manage")
    if err:
        return err
    try:
        u = rbac.update_role(user_id, new_role)
    except (PermissionDenied, KeyError) as e:
        _audit(request, "user.role_change", user_id, result="failed", detail=str(e))
        return fail(str(e), 400)
    _audit(request, "user.role_change", user_id, detail=f"→{new_role}")
    return ok(u)


@router.put("/rbac/users/{user_id}/active")
def rbac_set_active(user_id: str, request: Request,
                    active: bool = Body(..., embed=True)):
    user, err = _authz(request, "user.manage")
    if err:
        return err
    try:
        u = rbac.set_active(user_id, active)
    except KeyError as e:
        return fail(str(e), 404)
    _audit(request, "user.set_active", user_id, detail=f"active={active}")
    return ok(u)


@router.delete("/rbac/users/{user_id}")
def rbac_delete_user(user_id: str, request: Request):
    user, err = _authz(request, "user.manage")
    if err:
        return err
    try:
        ok_del = rbac.delete_user(user_id)
    except PermissionDenied as e:
        _audit(request, "user.delete", user_id, result="failed", detail=str(e))
        return fail(str(e), 400)
    if not ok_del:
        return fail("用户不存在", 404)
    _audit(request, "user.delete", user_id, detail="已删除")
    return ok({"deleted": user_id})


@router.post("/rbac/check-permission")
def rbac_check(request: Request,
               user_id: str = Body(..., embed=True),
               permission: str = Body(..., embed=True)):
    """模拟指定用户调用某权限的结果。"""
    if _guard():
        return _guard()
    has = rbac.has_permission(user_id, permission)
    u = rbac.get_user(user_id)
    _audit(request, "perm.check", f"{user_id}:{permission}",
           detail=f"allowed={has}")
    return ok({
        "user_id": user_id,
        "user": u,
        "permission": permission,
        "allowed": has,
    })


# =========================================================================== #
# 2. 操作审计日志（4 端点）
# =========================================================================== #
@router.get("/audit/logs")
def audit_logs(request: Request,
               start_time: Optional[str] = Query(None),
               end_time: Optional[str] = Query(None),
               user_id: Optional[str] = Query(None),
               action: Optional[str] = Query(None),
               result: Optional[str] = Query(None),
               target: Optional[str] = Query(None),
               limit: int = Query(200),
               offset: int = Query(0)):
    user, err = _authz(request, "audit.view")
    if err:
        return err
    data = audit.query(start_time=start_time, end_time=end_time,
                       user_id=user_id, action=action, result=result,
                       target=target, limit=limit, offset=offset)
    return ok(data)


@router.get("/audit/stats")
def audit_stats(request: Request):
    user, err = _authz(request, "audit.view")
    if err:
        return err
    return ok(audit.stats())


@router.post("/audit/export")
def audit_export(request: Request,
                 fmt: str = Body("html"),
                 start_time: Optional[str] = Body(None),
                 end_time: Optional[str] = Body(None),
                 user_id: Optional[str] = Body(None),
                 action: Optional[str] = Body(None)):
    user, err = _authz(request, "audit.export")
    if err:
        return err
    report = audit.export(fmt=fmt, start_time=start_time, end_time=end_time,
                          user_id=user_id, action=action)
    _audit(request, "audit.export", report["report_id"],
           detail=f"格式={fmt} 共{report['count']}条")
    return ok(report)


@router.post("/audit/record")
def audit_record(request: Request,
                 action: str = Body(...),
                 target: str = Body(""),
                 result: str = Body("success"),
                 detail: str = Body("")):
    """手动追加一条审计事件（演示用）。"""
    if _guard():
        return _guard()
    entry = audit.record(_caller(request), action, target,
                         ip=_client_ip(request), result=result, detail=detail)
    return ok(entry)


# =========================================================================== #
# 3. 数据加密（5 端点）
# =========================================================================== #
@router.get("/crypto/self-test")
def crypto_selftest(request: Request):
    if _guard():
        return _guard()
    return ok(crypto.self_test())


@router.get("/crypto/secrets")
def crypto_list(request: Request):
    user, err = _authz(request, "secret.view")
    if err:
        return err
    return ok({"secrets": crypto.list_secrets()})


@router.post("/crypto/secrets/store")
def crypto_store(request: Request,
                 name: str = Body(...),
                 plaintext: str = Body(...),
                 meta: Optional[Dict[str, Any]] = Body(None)):
    user, err = _authz(request, "secret.view")
    if err:
        return err
    res = crypto.store_secret(name, plaintext, meta=meta)
    _audit(request, "crypto.store", name, detail="凭据已加密存储")
    return ok(res)


@router.get("/crypto/secrets/{name}/reveal")
def crypto_reveal(name: str, request: Request):
    user, err = _authz(request, "secret.view")
    if err:
        return err
    try:
        plain = crypto.reveal_secret(name)
    except KeyError as e:
        return fail(str(e), 404)
    _audit(request, "crypto.reveal", name, detail="敏感凭据被解密访问")
    return ok({"name": name, "plaintext": plain, "masked": crypto.mask(plain)})


@router.delete("/crypto/secrets/{name}")
def crypto_delete(name: str, request: Request):
    user, err = _authz(request, "secret.view")
    if err:
        return err
    deleted = crypto.delete_secret(name)
    if not deleted:
        return fail("凭据不存在", 404)
    _audit(request, "crypto.delete", name, detail="已删除")
    return ok({"deleted": name})


# =========================================================================== #
# 4. 安全基线检查（3 端点）
# =========================================================================== #
@router.post("/security-baseline/run")
def baseline_run(request: Request,
                 present_headers: Optional[Dict[str, str]] = Body(None)):
    user, err = _authz(request, "baseline.run")
    if err:
        return err
    report = baseline.run(present_headers=present_headers)
    _audit(request, "baseline.run", report["report_id"],
           detail=f"得分{report['summary']['score']}")
    return ok(report)


@router.get("/security-baseline/report")
def baseline_report(request: Request):
    user, err = _authz(request, "baseline.run")
    if err:
        return err
    if not baseline.last_report:
        # 自动跑一次
        baseline.run()
    return ok(baseline.last_report)


@router.get("/security-baseline/policy")
def baseline_policy():
    if _guard():
        return _guard()
    from enterprise_security.security_baseline import PASSWORD_POLICY, EXPECTED_HEADERS
    return ok({"password_policy": PASSWORD_POLICY,
               "expected_headers": EXPECTED_HEADERS})


# =========================================================================== #
# 5. 合规报告（5 端点）
# =========================================================================== #
@router.post("/compliance/generate")
def compliance_generate(request: Request,
                        framework: str = Body("mlps2", embed=True)):
    user, err = _authz(request, "compliance.generate")
    if err:
        return err
    try:
        report = compliance.generate(framework)
    except ValueError as e:
        return fail(str(e), 400)
    _audit(request, "compliance.generate", report["report_id"],
           detail=f"{report['framework_name']} 符合率{report['score']}%")
    return ok(report)


@router.get("/compliance/reports")
def compliance_list(request: Request):
    user, err = _authz(request, "data.view")
    if err:
        return err
    return ok({"reports": compliance.list_reports()})


@router.get("/compliance/reports/{report_id}")
def compliance_get(report_id: str, request: Request):
    user, err = _authz(request, "data.view")
    if err:
        return err
    r = compliance.get(report_id)
    if not r:
        return fail("报告不存在", 404)
    return ok(r)


@router.get("/compliance/reports/{report_id}/html",
            response_class=HTMLResponse)
def compliance_html(report_id: str, request: Request):
    user, err = _authz(request, "data.view")
    if err:
        return HTMLResponse("<h2>403 Forbidden</h2>", status_code=403)
    if not compliance.get(report_id):
        return HTMLResponse("<h2>报告不存在</h2>", status_code=404)
    return HTMLResponse(compliance.render_html(report_id))


@router.get("/compliance/reports/{report_id}/export")
def compliance_export(report_id: str, request: Request,
                      fmt: str = Query("html")):
    user, err = _authz(request, "report.export")
    if err:
        return err
    try:
        out = compliance.export(report_id, fmt=fmt)
    except KeyError as e:
        return fail(str(e), 404)
    _audit(request, "compliance.export", report_id, detail=f"格式={fmt}")
    return ok(out)


# =========================================================================== #
# 6. 企业安全控制台聚合（2 端点）
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview(request: Request):
    user, err = _authz(request, "data.view")
    if err:
        return err
    return ok(dashboard.overview())


@router.get("/dashboard/health")
def dash_health():
    if _guard():
        return _guard()
    return ok(dashboard.health())
