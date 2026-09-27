# -*- coding: utf-8 -*-
"""
license_system_routes.py — License 授权系统 REST API。

路由前缀: /api/v1/license-system
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

覆盖六大模块:
    1. License 生成/签发/验证/吊销/备份/审计
    2. 设备指纹/在线激活/离线激活/设备管理/诊断
    3. 功能模块/用户数/时间/API配额/数据量/高级功能
    4. 续费/升级/加购/扩容/订单/价格
    5. 防篡改/破解检测/水印/黑名单/法律合规
    6. 运营仪表盘
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

router = APIRouter(prefix="/api/v1/license-system", tags=["License授权系统"])

# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_OK = False
try:
    from license_system.license_generator import (
        get_issuer, get_key_manager, LICENSE_PLANS, ALL_MODULES, ADVANCED_FEATURES,
    )
    from license_system.device_binding import (
        get_activation_server, DeviceFingerprint, ACTIVATION_STORE,
    )
    from license_system.feature_control import get_feature_controller, MODULE_DEPS
    from license_system.billing_upgrade import get_billing_manager, PRICE_TABLE
    from license_system.anti_piracy import get_anti_piracy_guard, LEGAL_TERMS
    from license_system.license_dashboard import get_dashboard
    _MOD_OK = True
    logger.info("license_system_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("license_system_routes: load failed: %s", e)


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


def _finish_task(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in _TASKS:
        t = _TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应（递归清理控制字符）
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ord(ch) >= 32 or ch in "\n\t")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    if isinstance(obj, set):
        return sorted(_clean(x) for x in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_OK:
        return fail("License 系统模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class IssueRequest(BaseModel):
    plan: str = "standard"
    customer: str = "unknown"
    days: Optional[int] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class BatchIssueRequest(BaseModel):
    plan: str = "standard"
    customers: List[str] = Field(default_factory=list)
    days: Optional[int] = None


class VerifyRequest(BaseModel):
    license_id: str
    signature: Optional[str] = None
    device_fingerprint: Optional[str] = None
    mode: str = "local"


class VerifyCodeRequest(BaseModel):
    activation_code: str
    device_fingerprint: Optional[str] = None


class RevokeRequest(BaseModel):
    reason: str = "用户主动吊销"


class ExtendRequest(BaseModel):
    days: int = 365


class UpgradePlanRequest(BaseModel):
    new_plan: str = "professional"


class BackupRequest(BaseModel):
    blob: str = ""


class MigrateRequest(BaseModel):
    licenses: Dict[str, Any] = Field(default_factory=dict)


class ActivateRequest(BaseModel):
    license_id: str
    activation_code: str
    device_info: Dict[str, str] = Field(default_factory=dict)


class OfflineRequestReq(BaseModel):
    license_id: str


class OfflineIssueReq(BaseModel):
    offline_token: str


class OfflineVerifyReq(BaseModel):
    license_id: str
    offline_code: str
    fingerprint: Optional[str] = None


class MigrateDeviceReq(BaseModel):
    device_info: Dict[str, str] = Field(default_factory=dict)


class BlacklistReq(BaseModel):
    kind: str = "devices"
    value: str = ""


class ModuleCheckReq(BaseModel):
    license_id: str
    module: str = "ai_analysis"


class UsageUsersReq(BaseModel):
    license_id: str
    active: int = 0
    admins: int = 0
    concurrent: int = 0


class ApiQuotaReq(BaseModel):
    license_id: str
    cost: int = 1


class DataQuotaReq(BaseModel):
    license_id: str
    assets: int = 0
    scan_tasks: int = 0
    reports: int = 0
    storage_mb: int = 0


class RenewQuoteReq(BaseModel):
    license_id: str
    years: int = 1
    promo_code: Optional[str] = None


class UpgradeQuoteReq(BaseModel):
    license_id: str
    new_plan: str = "enterprise"


class ModuleQuoteReq(BaseModel):
    license_id: str
    modules: List[str] = Field(default_factory=list)


class ExpandQuoteReq(BaseModel):
    license_id: str
    extra_users: int = 10


class OrderCreateReq(BaseModel):
    license_id: str
    kind: str = "renew"
    amount: float = 0.0
    detail: Dict[str, Any] = Field(default_factory=dict)


class CrackDetectReq(BaseModel):
    license_id: Optional[str] = None
    strings: List[str] = Field(default_factory=list)
    loaded_libs: List[str] = Field(default_factory=list)
    memory_hash: str = ""
    raw_bytes: str = ""


class WatermarkReq(BaseModel):
    license_id: str
    document_id: str = "doc-1"
    wm_type: str = "user"


class ViolationReq(BaseModel):
    license_id: str
    description: str = "违规使用"


class IntegrityRecordReq(BaseModel):
    path: str = ""


class PriceUpdateReq(BaseModel):
    key: str = "plans"
    value: Any = None


# =========================================================================== #
# 1. License 签发 / 验证 / 吊销 / 备份（15 个端点）
# =========================================================================== #
@router.get("/plans")
def list_plans():
    try:
        g = _guard()
        if g:
            return g
        return ok({"plans": LICENSE_PLANS, "all_modules": ALL_MODULES,
                   "advanced_features": ADVANCED_FEATURES})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/licenses/issue")
def issue_license(req: IssueRequest):
    try:
        g = _guard()
        if g:
            return g
        iss = get_issuer()
        result = iss.issue(req.plan, req.customer, days=req.days, extra=req.extra)
        return ok(result)
    except Exception as e:
        return fail(f"签发失败: {e}", 500)


@router.post("/licenses/batch")
def batch_issue(req: BatchIssueRequest):
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("batch_issue")
        result = get_issuer().batch_issue(req.plan, req.customers, days=req.days)
        _finish_task(task_id, {"issued": len(result), "licenses": result})
        return ok({"task_id": task_id, "count": len(result), "licenses": result})
    except Exception as e:
        return fail(f"批量签发失败: {e}", 500)


@router.get("/licenses")
def list_licenses(q: Optional[str] = Query(default=None),
                  plan: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        items = get_issuer().list_all()
        if q:
            ql = q.lower()
            items = [x for x in items if ql in x["license_id"].lower()
                     or ql in x["customer"].lower()]
        if plan:
            items = [x for x in items if x["plan"] == plan]
        return ok({"total": len(items), "items": items})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/licenses/{license_id}")
def license_detail(license_id: str):
    try:
        g = _guard()
        if g:
            return g
        item = get_issuer().get(license_id)
        if not item:
            return fail("License 不存在", 404)
        return ok(item)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/licenses/verify")
def verify_license(req: VerifyRequest):
    try:
        g = _guard()
        if g:
            return g
        iss = get_issuer()
        sig = req.signature
        if not sig:
            rec = iss.licenses.get(req.license_id)
            sig = rec["signature"] if rec else ""
        result = iss.verify(req.license_id, sig,
                            device_fingerprint=req.device_fingerprint,
                            mode=req.mode)
        return ok(result)
    except Exception as e:
        return fail(f"验证失败: {e}", 500)


@router.post("/licenses/verify-by-code")
def verify_by_code(req: VerifyCodeRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_issuer().verify_by_code(req.activation_code,
                                              req.device_fingerprint))
    except Exception as e:
        return fail(f"验证失败: {e}", 500)


@router.post("/licenses/{license_id}/revoke")
def revoke_license(license_id: str, req: RevokeRequest):
    try:
        g = _guard()
        if g:
            return g
        okk = get_issuer().revoke(license_id, req.reason)
        if not okk:
            return fail("License 不存在", 404)
        return ok({"license_id": license_id, "revoked": True})
    except Exception as e:
        return fail(f"吊销失败: {e}", 500)


@router.post("/licenses/{license_id}/extend")
def extend_license(license_id: str, req: ExtendRequest):
    try:
        g = _guard()
        if g:
            return g
        okk = get_issuer().extend(license_id, req.days)
        return ok({"license_id": license_id, "extended_days": req.days, "ok": okk})
    except Exception as e:
        return fail(f"续费失败: {e}", 500)


@router.post("/licenses/{license_id}/upgrade")
def upgrade_license(license_id: str, req: UpgradePlanRequest):
    try:
        g = _guard()
        if g:
            return g
        okk = get_issuer().upgrade_plan(license_id, req.new_plan)
        return ok({"license_id": license_id, "new_plan": req.new_plan, "ok": okk})
    except Exception as e:
        return fail(f"升级失败: {e}", 500)


@router.get("/licenses/revoked/list")
def list_revoked():
    try:
        g = _guard()
        if g:
            return g
        return ok({"revoked": list(get_issuer().revoked.values())})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/licenses/audit/report")
def audit_report():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_issuer().audit_report())
    except Exception as e:
        return fail(f"审计失败: {e}", 500)


@router.post("/licenses/backup")
def backup_licenses():
    try:
        g = _guard()
        if g:
            return g
        blob = get_issuer().export_encrypted()
        return ok({"blob": blob, "size": len(blob),
                   "created_at": time.strftime("%Y-%m-%d %H:%M:%S")})
    except Exception as e:
        return fail(f"备份失败: {e}", 500)


@router.post("/licenses/restore")
def restore_licenses(req: BackupRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_issuer().restore(req.blob))
    except Exception as e:
        return fail(f"恢复失败: {e}", 500)


@router.post("/licenses/migrate")
def migrate_licenses(req: MigrateRequest):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_issuer().migrate(req.licenses))
    except Exception as e:
        return fail(f"迁移失败: {e}", 500)


# =========================================================================== #
# 2. 设备指纹 / 激活 / 离线 / 诊断（12 个端点）
# =========================================================================== #
@router.get("/device/fingerprint")
def device_fingerprint():
    try:
        g = _guard()
        if g:
            return g
        fp = DeviceFingerprint.fingerprint()
        return ok({"fingerprint": fp, "detail": DeviceFingerprint.collect()})
    except Exception as e:
        return fail(f"指纹采集失败: {e}", 500)


@router.post("/activation/activate")
def activate_device(req: ActivateRequest):
    try:
        g = _guard()
        if g:
            return g
        result = get_activation_server().activate(
            req.license_id, req.activation_code, req.device_info)
        return ok(result)
    except Exception as e:
        return fail(f"激活失败: {e}", 500)


@router.get("/activations")
def list_activations(license_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        return ok({"items": get_activation_server().list_devices(license_id)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/devices")
def list_devices(license_id: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        return ok({"items": get_activation_server().list_devices(license_id)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/devices/{activation_id}/unbind")
def unbind_device(activation_id: str):
    try:
        g = _guard()
        if g:
            return g
        okk = get_activation_server().unbind_device(activation_id)
        return ok({"activation_id": activation_id, "unbound": okk})
    except Exception as e:
        return fail(f"解绑失败: {e}", 500)


@router.post("/devices/{activation_id}/migrate")
def migrate_device(activation_id: str, req: MigrateDeviceReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_activation_server().migrate_device(activation_id, req.device_info))
    except Exception as e:
        return fail(f"迁移失败: {e}", 500)


@router.post("/devices/blacklist")
def blacklist_device(req: BlacklistReq):
    try:
        g = _guard()
        if g:
            return g
        if req.kind == "devices":
            get_activation_server().blacklist_device(req.value)
        else:
            get_anti_piracy_guard().add_blacklist(req.kind, req.value)
        return ok({"kind": req.kind, "value": req.value, "added": True})
    except Exception as e:
        return fail(f"加黑失败: {e}", 500)


@router.delete("/devices/blacklist")
def unblacklist_device(kind: str = "devices", value: str = ""):
    try:
        g = _guard()
        if g:
            return g
        if kind == "devices":
            get_activation_server().unblacklist_device(value)
        else:
            get_anti_piracy_guard().remove_blacklist(kind, value)
        return ok({"kind": kind, "value": value, "removed": True})
    except Exception as e:
        return fail(f"移除失败: {e}", 500)


@router.post("/offline/request")
def offline_request(req: OfflineRequestReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_activation_server().create_offline_request(req.license_id))
    except Exception as e:
        return fail(f"生成离线请求失败: {e}", 500)


@router.post("/offline/issue")
def offline_issue(req: OfflineIssueReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_activation_server().issue_offline_code(req.offline_token))
    except Exception as e:
        return fail(f"签发离线码失败: {e}", 500)


@router.post("/offline/verify")
def offline_verify(req: OfflineVerifyReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_activation_server().verify_offline_code(
            req.license_id, req.offline_code, req.fingerprint))
    except Exception as e:
        return fail(f"离线验证失败: {e}", 500)


@router.get("/activation/diagnose")
def activation_diagnose(license_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_activation_server().diagnose(license_id))
    except Exception as e:
        return fail(f"诊断失败: {e}", 500)


# =========================================================================== #
# 3. 功能权限 / 配额 / 限制（7 个端点）
# =========================================================================== #
@router.get("/features/modules/{license_id}")
def feature_modules(license_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_feature_controller().module_status(license_id))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/features/check-module")
def check_module(req: ModuleCheckReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_feature_controller().require_module(req.license_id, req.module))
    except Exception as e:
        return fail(f"校验失败: {e}", 500)


@router.post("/features/users")
def check_users(req: UsageUsersReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_feature_controller().usage_users(
            req.license_id, req.active, req.admins, req.concurrent))
    except Exception as e:
        return fail(f"校验失败: {e}", 500)


@router.get("/features/time/{license_id}")
def feature_time(license_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_feature_controller().time_status(license_id))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/features/api-quota")
def check_api_quota(req: ApiQuotaReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_feature_controller().api_quota_check(req.license_id, req.cost))
    except Exception as e:
        return fail(f"配额校验失败: {e}", 500)


@router.post("/features/data-quota")
def check_data_quota(req: DataQuotaReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_feature_controller().data_quota_check(
            req.license_id, req.assets, req.scan_tasks,
            req.reports, req.storage_mb))
    except Exception as e:
        return fail(f"数据量校验失败: {e}", 500)


@router.get("/features/advanced/{license_id}")
def advanced_features(license_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_feature_controller().unlockable_features(license_id))
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 4. 续费 / 升级 / 订单 / 价格（12 个端点）
# =========================================================================== #
@router.post("/billing/quote/renew")
def quote_renew(req: RenewQuoteReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_billing_manager().quote_renewal(
            req.license_id, req.years, req.promo_code))
    except Exception as e:
        return fail(f"报价失败: {e}", 500)


@router.post("/billing/quote/upgrade")
def quote_upgrade(req: UpgradeQuoteReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_billing_manager().quote_upgrade(req.license_id, req.new_plan))
    except Exception as e:
        return fail(f"报价失败: {e}", 500)


@router.post("/billing/quote/module")
def quote_module(req: ModuleQuoteReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_billing_manager().quote_module_addon(req.license_id, req.modules))
    except Exception as e:
        return fail(f"报价失败: {e}", 500)


@router.post("/billing/quote/expand")
def quote_expand(req: ExpandQuoteReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_billing_manager().quote_expand_users(req.license_id, req.extra_users))
    except Exception as e:
        return fail(f"报价失败: {e}", 500)


@router.post("/billing/orders")
def create_order(req: OrderCreateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_billing_manager().create_order(
            req.license_id, req.kind, req.amount, req.detail))
    except Exception as e:
        return fail(f"下单失败: {e}", 500)


@router.post("/billing/orders/{order_id}/pay")
def pay_order(order_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_billing_manager().pay_order(order_id))
    except Exception as e:
        return fail(f"支付失败: {e}", 500)


@router.post("/billing/orders/{order_id}/refund")
def refund_order(order_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_billing_manager().refund_order(order_id))
    except Exception as e:
        return fail(f"退款失败: {e}", 500)


@router.get("/billing/orders")
def list_orders(license_id: Optional[str] = Query(default=None),
                status: Optional[str] = Query(default=None)):
    try:
        g = _guard()
        if g:
            return g
        return ok({"items": get_billing_manager().list_orders(license_id, status)})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/billing/revenue")
def revenue_summary():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_billing_manager().revenue_summary())
    except Exception as e:
        return fail(f"统计失败: {e}", 500)


@router.get("/billing/renew-reminders")
def renew_reminders():
    try:
        g = _guard()
        if g:
            return g
        return ok({"items": get_billing_manager().renewal_reminders()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/billing/prices")
def list_prices():
    try:
        g = _guard()
        if g:
            return g
        return ok(PRICE_TABLE)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.put("/billing/prices")
def update_price(req: PriceUpdateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_billing_manager().update_price(req.key, req.value))
    except Exception as e:
        return fail(f"更新失败: {e}", 500)


# =========================================================================== #
# 5. 防盗版 / 安全 / 合规（11 个端点）
# =========================================================================== #
@router.post("/security/integrity/record")
def integrity_record(req: IntegrityRecordReq):
    try:
        g = _guard()
        if g:
            return g
        okk = get_anti_piracy_guard().record_integrity(req.path)
        return ok({"path": req.path, "recorded": okk})
    except Exception as e:
        return fail(f"记录失败: {e}", 500)


@router.post("/security/integrity/check")
def integrity_check(req: IntegrityRecordReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_anti_piracy_guard().check_integrity(req.path))
    except Exception as e:
        return fail(f"校验失败: {e}", 500)


@router.get("/security/runtime")
def runtime_protection():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_anti_piracy_guard().runtime_protection())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/security/hardening")
def hardening_profile():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_anti_piracy_guard().hardening_profile())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/security/detect-crack")
def detect_crack(req: CrackDetectReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_anti_piracy_guard().detect_crack(req.model_dump()))
    except Exception as e:
        return fail(f"检测失败: {e}", 500)


@router.post("/security/watermark/embed")
def embed_watermark(req: WatermarkReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_anti_piracy_guard().embed_watermark(
            req.license_id, req.document_id, req.wm_type))
    except Exception as e:
        return fail(f"嵌入失败: {e}", 500)


@router.get("/security/watermark/trace")
def trace_watermark(w: str = Query(...)):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_anti_piracy_guard().trace_watermark(w))
    except Exception as e:
        return fail(f"溯源失败: {e}", 500)


@router.get("/security/blacklist")
def blacklist_summary():
    try:
        g = _guard()
        if g:
            return g
        return ok({"counts": get_anti_piracy_guard().blacklist_summary()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/security/alerts")
def security_alerts():
    try:
        g = _guard()
        if g:
            return g
        return ok({"items": get_anti_piracy_guard().recent_alerts()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.post("/security/violation")
def violation_report(req: ViolationReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_anti_piracy_guard().violation_report(
            req.license_id, req.description))
    except Exception as e:
        return fail(f"上报失败: {e}", 500)


@router.get("/legal/docs")
def legal_docs():
    try:
        g = _guard()
        if g:
            return g
        return ok(LEGAL_TERMS)
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


# =========================================================================== #
# 6. 运营仪表盘（4 个端点）
# =========================================================================== #
@router.get("/dashboard/overview")
def dashboard_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().overview())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/full")
def dashboard_full():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().full_dashboard())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/alerts")
def dashboard_alerts():
    try:
        g = _guard()
        if g:
            return g
        return ok({"items": get_dashboard().alerts()})
    except Exception as e:
        return fail(f"查询失败: {e}", 500)


@router.get("/dashboard/settings")
def dashboard_settings():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard().system_settings())
    except Exception as e:
        return fail(f"查询失败: {e}", 500)
