# -*- coding: utf-8 -*-
"""
data_security_deep_routes.py — 数据安全与隐私保护深度平台 REST API（第24轮升级方向3）。

路由前缀：/api/v1/data-security-deep
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500 错误。
任务/会话用内存字典模拟异步。
本模块仅用于授权的数据安全治理场景。
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:  # 模块导入失败也不影响 app 启动
    from data_security_deep.data_classification import (
        get_classification_engine, CLASSIFICATION_LEVELS_DEEP,
        SENSITIVE_PATTERNS, BUSINESS_DOMAINS,
    )
    from data_security_deep.dlp_engine import (
        get_dlp_engine, DLP_PROFILES, PROTECTION_ACTIONS,
    )
    from data_security_deep.privacy_compute import (
        get_privacy_compute_engine, ENCRYPTION_ALGORITHMS,
        PRIVACY_COMPUTE_TECHS, ANONYMIZATION_METHODS,
    )
    from data_security_deep.access_audit import (
        get_access_audit_engine, ACCESS_CONTROL_MODES, ANOMALY_RULES,
    )
    from data_security_deep.privacy_compliance import (
        get_privacy_compliance_manager, COMPLIANCE_FRAMEWORKS_DEEP,
        DATA_SUBJECT_RIGHTS, CONSENT_CHANNELS,
    )
    from data_security_deep.data_security_dashboard import (
        get_dashboard, DASHBOARD_METRICS, SYSTEM_SETTINGS,
    )
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger("data_security_deep_routes").warning("模块导入失败: %s", _e)
    get_classification_engine = None  # type: ignore
    get_dlp_engine = None  # type: ignore
    get_privacy_compute_engine = None  # type: ignore
    get_access_audit_engine = None  # type: ignore
    get_privacy_compliance_manager = None  # type: ignore
    get_dashboard = None  # type: ignore
    CLASSIFICATION_LEVELS_DEEP = {}
    SENSITIVE_PATTERNS = {}
    BUSINESS_DOMAINS = {}
    DLP_PROFILES = {}
    PROTECTION_ACTIONS = {}
    ENCRYPTION_ALGORITHMS = {}
    PRIVACY_COMPUTE_TECHS = {}
    ANONYMIZATION_METHODS = {}
    ACCESS_CONTROL_MODES = {}
    ANOMALY_RULES = {}
    COMPLIANCE_FRAMEWORKS_DEEP = {}
    DATA_SUBJECT_RIGHTS = {}
    CONSENT_CHANNELS = {}
    DASHBOARD_METRICS = {}
    SYSTEM_SETTINGS = {}
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/data-security-deep", tags=["数据安全深度平台"])


# ==================== 响应工具 ====================

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理无效控制字符，避免 JSON 序列化异常"""
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": str(err)})


def _check_modules() -> Optional[JSONResponse]:
    if not _MODULES_OK:
        return _fail("data_security_deep 模块未正确加载")
    return None


# ==================== 内存任务存储 ====================

TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    return tid


# ==================== 请求模型 ====================

class DiscoverReq(BaseModel):
    source_types: List[str] = Field(default_factory=list)
    scan_depth: str = "full"


class ClassifyReq(BaseModel):
    asset_id: str
    text_sample: str = ""


class BatchClassifyReq(BaseModel):
    samples: Dict[str, str] = Field(default_factory=dict)


class GradeReq(BaseModel):
    grade: str
    reviewer: str = ""


class ScanTextReq(BaseModel):
    text: str


class AssetUpdateReq(BaseModel):
    updates: Dict[str, Any] = Field(default_factory=dict)


class TagReq(BaseModel):
    tag: str


class TransferMonitorReq(BaseModel):
    channel: str
    content: str
    user: str = ""
    destination: str = ""


class UsageMonitorReq(BaseModel):
    usage_type: str
    user: str
    resource: str
    operation: str = "read"
    data_volume: int = 0


class PolicyCreateReq(BaseModel):
    name: str
    scope: str
    trigger: str
    action: str
    priority: int = 50


class PolicyUpdateReq(BaseModel):
    updates: Dict[str, Any] = Field(default_factory=dict)


class EventHandleReq(BaseModel):
    action: str
    handler: str = ""
    note: str = ""


class EncryptReq(BaseModel):
    plaintext: str
    algorithm: str = "aes-256-gcm"
    key_id: Optional[str] = None


class DecryptReq(BaseModel):
    ciphertext: str
    key_id: str = ""


class MaskReq(BaseModel):
    data: str
    method: str = "mask"
    field_type: str = "auto"


class BatchMaskReq(BaseModel):
    records: List[Dict[str, str]] = Field(default_factory=list)
    sensitive_fields: List[str] = Field(default_factory=list)


class PrivacyComputeReq(BaseModel):
    tech: str
    data_size: int = 10000


class AnonymizeReq(BaseModel):
    data: List[Dict[str, Any]] = Field(default_factory=list)
    method: str = "k_anonymity"
    quasi_identifiers: List[str] = Field(default_factory=list)
    sensitive_attr: str = ""


class WatermarkReq(BaseModel):
    content: str
    watermark_text: str = ""
    wm_type: str = "invisible"
    user_id: str = "system"


class KeyGenReq(BaseModel):
    algorithm: str = "AES-256"
    owner: str = ""
    rotation_days: int = 90


class AccessCheckReq(BaseModel):
    user_id: str
    resource: str
    action: str = "read"


class AccessRequestReq(BaseModel):
    user_id: str
    resource: str
    reason: str = ""
    duration_hours: int = 4
    approver: str = "manager"


class ApproveReq(BaseModel):
    approver: str
    approved: bool = True
    comment: str = ""


class AbuseCheckReq(BaseModel):
    user_id: str
    operation: str
    data_volume: int = 0


class ReportReq(BaseModel):
    report_type: str = "access"


class RopaCreateReq(BaseModel):
    activity_name: str
    purposes: List[str] = Field(default_factory=list)
    data_categories: List[str] = Field(default_factory=list)
    data_subjects: List[str] = Field(default_factory=list)
    lawful_basis: str = "consent"
    cross_border: bool = False


class DpiaReq(BaseModel):
    processing_name: str
    high_risk_data: bool = False
    systematic_monitoring: bool = False


class CrossBorderReq(BaseModel):
    destination_country: str
    data_volume: str = "small"


class DsrSubmitReq(BaseModel):
    right_type: str
    subject_name: str
    subject_contact: str = ""
    details: str = ""


class DsrProcessReq(BaseModel):
    action: str
    handler: str = ""
    result: str = ""


class ConsentRecordReq(BaseModel):
    subject_id: str
    purpose: str
    channel: str = "web_form"
    consent_text: str = ""
    version: str = "v1.0"


class ConsentWithdrawReq(BaseModel):
    reason: str = ""


class PolicyGenReq(BaseModel):
    company_name: str
    services: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)


class TrainingCreateReq(BaseModel):
    title: str
    audience: str
    duration_min: int = 60


class EnrollReq(BaseModel):
    user_name: str


class CompleteTrainingReq(BaseModel):
    user_name: str
    score: int = 90


class SettingUpdateReq(BaseModel):
    key: str
    value: Any


class AlertResolveReq(BaseModel):
    resolution: str = "已处理"


# ======================================================================
# 健康检查 & 总览
# ======================================================================
@router.get("/health")
def health():
    """模块健康检查与能力总览"""
    try:
        return _ok({
            "module": "data_security_deep",
            "modules_loaded": _MODULES_OK,
            "version": "24.3.0",
            "capabilities": [
                "数据分类分级深度引擎", "DLP数据防泄漏",
                "隐私计算与数据加密", "数据访问控制与审计",
                "隐私合规管理", "数据安全控制台",
            ],
        })
    except Exception as e:
        return _fail(str(e))


@router.get("/overview")
def overview():
    """数据安全总览"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().get_overview())
    except Exception as e:
        return _fail(str(e))


@router.get("/trend")
def trend(days: int = 14):
    """安全趋势"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().get_security_trend(days))
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 一、数据分类分级（12 端点）
# ======================================================================
@router.post("/classification/discover")
def classification_discover(req: DiscoverReq):
    """数据资产发现：自动扫描数据源"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().discover_assets(req.source_types, req.scan_depth))
    except Exception as e:
        return _fail(str(e))


@router.post("/classification/asset/{asset_id}/classify")
def classification_classify_asset(asset_id: str, req: ClassifyReq):
    """对单个资产进行分类"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().classify_asset(asset_id, req.text_sample))
    except Exception as e:
        return _fail(str(e))


@router.post("/classification/batch-classify")
def classification_batch_classify(req: BatchClassifyReq):
    """批量分类"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().classify_batch(req.samples))
    except Exception as e:
        return _fail(str(e))


@router.post("/classification/asset/{asset_id}/auto-grade")
def classification_auto_grade(asset_id: str):
    """自动分级"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().auto_grade(asset_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/classification/asset/{asset_id}/manual-grade")
def classification_manual_grade(asset_id: str, req: GradeReq):
    """人工调整分级"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().manual_grade(asset_id, req.grade, req.reviewer))
    except Exception as e:
        return _fail(str(e))


@router.post("/classification/scan-text")
def classification_scan_text(req: ScanTextReq):
    """敏感数据文本扫描"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().scan_text(req.text))
    except Exception as e:
        return _fail(str(e))


@router.get("/classification/grading-rules")
def classification_grading_rules():
    """获取分级规则"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"rules": get_classification_engine().list_grading_rules(),
                    "standards": CLASSIFICATION_LEVELS_DEEP})
    except Exception as e:
        return _fail(str(e))


@router.get("/classification/templates")
def classification_templates():
    """获取分类模板"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().get_templates())
    except Exception as e:
        return _fail(str(e))


@router.get("/classification/suggestions")
def classification_suggestions(asset_name: str = ""):
    """分类建议"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().get_classification_suggestions(asset_name))
    except Exception as e:
        return _fail(str(e))


@router.get("/classification/data-map")
def classification_data_map():
    """数据地图"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().get_data_map())
    except Exception as e:
        return _fail(str(e))


@router.get("/classification/data-lineage")
def classification_data_lineage():
    """数据血缘图"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().get_data_lineage())
    except Exception as e:
        return _fail(str(e))


@router.get("/classification/data-flow")
def classification_data_flow():
    """数据流向图"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().get_data_flow())
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 二、数据资产目录（6 端点）
# ======================================================================
@router.get("/assets")
def list_assets(keyword: Optional[str] = None, domain: Optional[str] = None,
                grade: Optional[str] = None, source_type: Optional[str] = None,
                page: int = 1, page_size: int = 20):
    """资产列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().list_assets(
            keyword, domain, grade, source_type, page, page_size))
    except Exception as e:
        return _fail(str(e))


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str):
    """资产详情"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().get_asset_detail(asset_id))
    except Exception as e:
        return _fail(str(e))


@router.put("/assets/{asset_id}")
def update_asset(asset_id: str, req: AssetUpdateReq):
    """更新资产"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().update_asset(asset_id, req.updates))
    except Exception as e:
        return _fail(str(e))


@router.post("/assets/{asset_id}/tags")
def add_asset_tag(asset_id: str, req: TagReq):
    """添加资产标签"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().add_tag(asset_id, req.tag))
    except Exception as e:
        return _fail(str(e))


@router.get("/assets/{asset_id}/score")
def asset_score(asset_id: str):
    """资产评分"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_classification_engine().get_asset_score(asset_id))
    except Exception as e:
        return _fail(str(e))


@router.get("/assets/catalog/summary")
def asset_catalog_summary():
    """资产目录摘要"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"stats": get_classification_engine().stats(),
                    "domains": BUSINESS_DOMAINS,
                    "patterns": list(SENSITIVE_PATTERNS.keys())})
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 三、DLP 数据防泄漏（12 端点）
# ======================================================================
@router.post("/dlp/monitor-transfer")
def dlp_monitor_transfer(req: TransferMonitorReq):
    """监控数据传输"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().monitor_transfer(
            req.channel, req.content, req.user, req.destination))
    except Exception as e:
        return _fail(str(e))


@router.post("/dlp/monitor-usage")
def dlp_monitor_usage(req: UsageMonitorReq):
    """监控数据使用"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().monitor_usage(
            req.usage_type, req.user, req.resource, req.operation, req.data_volume))
    except Exception as e:
        return _fail(str(e))


@router.get("/dlp/policies")
def dlp_list_policies():
    """DLP策略列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"policies": get_dlp_engine().list_policies(),
                    "profiles": DLP_PROFILES,
                    "actions": PROTECTION_ACTIONS})
    except Exception as e:
        return _fail(str(e))


@router.post("/dlp/policies")
def dlp_create_policy(req: PolicyCreateReq):
    """创建DLP策略"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().create_policy(req.name, req.scope, req.trigger, req.action, req.priority))
    except Exception as e:
        return _fail(str(e))


@router.put("/dlp/policies/{policy_id}")
def dlp_update_policy(policy_id: str, req: PolicyUpdateReq):
    """更新DLP策略"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().update_policy(policy_id, req.updates))
    except Exception as e:
        return _fail(str(e))


@router.post("/dlp/policies/{policy_id}/toggle")
def dlp_toggle_policy(policy_id: str):
    """启用/禁用策略"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().toggle_policy(policy_id))
    except Exception as e:
        return _fail(str(e))


@router.get("/dlp/events")
def dlp_list_events(status: Optional[str] = None, severity: Optional[str] = None,
                    channel: Optional[str] = None):
    """泄漏事件列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().list_events(status, severity, channel))
    except Exception as e:
        return _fail(str(e))


@router.get("/dlp/events/{event_id}")
def dlp_event_detail(event_id: str):
    """事件详情"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().get_event_detail(event_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/dlp/events/{event_id}/handle")
def dlp_handle_event(event_id: str, req: EventHandleReq):
    """处置事件"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().handle_event(event_id, req.action, req.handler, req.note))
    except Exception as e:
        return _fail(str(e))


@router.get("/dlp/statistics")
def dlp_statistics():
    """事件统计"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().event_statistics())
    except Exception as e:
        return _fail(str(e))


@router.get("/dlp/trend")
def dlp_trend(days: int = 7):
    """事件趋势"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().event_trend(days))
    except Exception as e:
        return _fail(str(e))


@router.get("/dlp/channels")
def dlp_channels():
    """监控通道"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dlp_engine().get_channels())
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 四、隐私计算与加密（12 端点）
# ======================================================================
@router.post("/crypto/encrypt")
def crypto_encrypt(req: EncryptReq):
    """加密数据"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().encrypt_data(req.plaintext, req.algorithm, req.key_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/crypto/decrypt")
def crypto_decrypt(req: DecryptReq):
    """解密数据"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().decrypt_data(req.ciphertext, req.key_id))
    except Exception as e:
        return _fail(str(e))


@router.get("/crypto/status")
def crypto_status():
    """加密状态"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"status": get_privacy_compute_engine().get_encryption_status(),
                    "algorithms": ENCRYPTION_ALGORITHMS})
    except Exception as e:
        return _fail(str(e))


@router.get("/crypto/keys")
def crypto_list_keys():
    """密钥列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().list_keys())
    except Exception as e:
        return _fail(str(e))


@router.post("/crypto/keys")
def crypto_generate_key(req: KeyGenReq):
    """生成密钥"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().generate_key(req.algorithm, req.owner, req.rotation_days))
    except Exception as e:
        return _fail(str(e))


@router.post("/crypto/keys/{key_id}/rotate")
def crypto_rotate_key(key_id: str):
    """轮换密钥"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().rotate_key(key_id))
    except Exception as e:
        return _fail(str(e))


@router.delete("/crypto/keys/{key_id}")
def crypto_destroy_key(key_id: str):
    """销毁密钥"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().destroy_key(key_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/crypto/mask")
def crypto_mask(req: MaskReq):
    """数据脱敏"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().mask_data(req.data, req.method, req.field_type))
    except Exception as e:
        return _fail(str(e))


@router.post("/crypto/batch-mask")
def crypto_batch_mask(req: BatchMaskReq):
    """批量脱敏"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().batch_mask(req.records, req.sensitive_fields))
    except Exception as e:
        return _fail(str(e))


@router.post("/privacy-compute/run")
def privacy_compute_run(req: PrivacyComputeReq):
    """隐私计算执行"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().privacy_compute_demo(req.tech, req.data_size))
    except Exception as e:
        return _fail(str(e))


@router.post("/anonymize")
def anonymize(req: AnonymizeReq):
    """数据匿名化"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().anonymize(
            req.data, req.method, req.quasi_identifiers, req.sensitive_attr))
    except Exception as e:
        return _fail(str(e))


@router.post("/watermark/add")
def watermark_add(req: WatermarkReq):
    """添加水印"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().add_watermark(
            req.content, req.watermark_text, req.wm_type, req.user_id))
    except Exception as e:
        return _fail(str(e))


@router.post("/watermark/detect")
def watermark_detect(content: str = Query(...)):
    """检测水印"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compute_engine().detect_watermark(content))
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 五、访问控制与审计（10 端点）
# ======================================================================
@router.post("/access/check")
def access_check(req: AccessCheckReq):
    """检查访问权限"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_access_audit_engine().check_access(req.user_id, req.resource, req.action))
    except Exception as e:
        return _fail(str(e))


@router.get("/access/roles")
def access_roles():
    """角色列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({"roles": get_access_audit_engine().list_roles(),
                    "modes": ACCESS_CONTROL_MODES})
    except Exception as e:
        return _fail(str(e))


@router.get("/access/users")
def access_users():
    """用户列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_access_audit_engine().list_users())
    except Exception as e:
        return _fail(str(e))


@router.post("/access/requests")
def access_request(req: AccessRequestReq):
    """申请敏感数据访问"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_access_audit_engine().request_access(
            req.user_id, req.resource, req.reason, req.duration_hours, req.approver))
    except Exception as e:
        return _fail(str(e))


@router.post("/access/requests/{request_id}/approve")
def access_approve(request_id: str, req: ApproveReq):
    """审批访问申请"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_access_audit_engine().approve_request(
            request_id, req.approver, req.approved, req.comment))
    except Exception as e:
        return _fail(str(e))


@router.get("/access/requests")
def access_list_requests(status: Optional[str] = None):
    """访问申请列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_access_audit_engine().list_requests(status))
    except Exception as e:
        return _fail(str(e))


@router.get("/access/grants")
def access_grants():
    """临时授权列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_access_audit_engine().list_temp_grants())
    except Exception as e:
        return _fail(str(e))


@router.get("/audit/logs")
def audit_logs(user_id: Optional[str] = None, action: Optional[str] = None,
               resource: Optional[str] = None, start: int = 0, limit: int = 100):
    """审计日志"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_access_audit_engine().get_audit_logs(user_id, action, resource, start, limit))
    except Exception as e:
        return _fail(str(e))


@router.get("/audit/anomalies")
def audit_anomalies(hours: int = 24):
    """异常访问检测"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_access_audit_engine().detect_anomalies(hours))
    except Exception as e:
        return _fail(str(e))


@router.post("/audit/check-abuse")
def audit_check_abuse(req: AbuseCheckReq):
    """防滥用检查"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_access_audit_engine().check_abuse(req.user_id, req.operation, req.data_volume))
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 六、隐私合规（12 端点）
# ======================================================================
@router.get("/compliance/frameworks")
def compliance_frameworks():
    """合规框架列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(COMPLIANCE_FRAMEWORKS_DEEP)
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/frameworks/{fid}")
def compliance_framework_detail(fid: str):
    """框架详情"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(COMPLIANCE_FRAMEWORKS_DEEP.get(fid, {"error": "不存在"}))
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/ropa")
def compliance_create_ropa(req: RopaCreateReq):
    """创建ROPA记录"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().create_ropa(
            req.activity_name, req.purposes, req.data_categories,
            req.data_subjects, req.lawful_basis, req.cross_border))
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/ropa")
def compliance_list_ropa():
    """ROPA列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().list_ropa())
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/dpia")
def compliance_dpia(req: DpiaReq):
    """DPIA评估"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().conduct_dpia(
            req.processing_name, req.high_risk_data, req.systematic_monitoring))
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/cross-border")
def compliance_cross_border(req: CrossBorderReq):
    """跨境传输评估"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().cross_border_assessment(
            req.destination_country, req.data_volume))
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/rights")
def compliance_rights():
    """数据主体权利"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(DATA_SUBJECT_RIGHTS)
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/dsr")
def compliance_submit_dsr(req: DsrSubmitReq):
    """提交DSR请求"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().submit_dsr(
            req.right_type, req.subject_name, req.subject_contact, req.details))
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/dsr")
def compliance_list_dsr(status: Optional[str] = None):
    """DSR列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().list_dsr(status))
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/dsr/{request_id}/process")
def compliance_process_dsr(request_id: str, req: DsrProcessReq):
    """处理DSR"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().process_dsr(
            request_id, req.action, req.handler, req.result))
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/consent")
def compliance_record_consent(req: ConsentRecordReq):
    """记录同意"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().record_consent(
            req.subject_id, req.purpose, req.channel, req.consent_text, req.version))
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/consent/{consent_id}/withdraw")
def compliance_withdraw_consent(consent_id: str, req: ConsentWithdrawReq):
    """撤回同意"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().withdraw_consent(consent_id, req.reason))
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/consent/audit")
def compliance_consent_audit():
    """同意审计"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().consent_audit())
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/policy/generate")
def compliance_gen_policy(req: PolicyGenReq):
    """生成隐私政策"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().generate_privacy_policy(
            req.company_name, req.services, req.frameworks))
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/policies")
def compliance_list_policies():
    """隐私政策列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().list_policies())
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/policy/{policy_id}/check")
def compliance_check_policy(policy_id: str, framework: str = "pipl"):
    """政策合规检查"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().check_policy_compliance(policy_id, framework))
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/training")
def compliance_create_training(req: TrainingCreateReq):
    """创建培训"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().create_training(
            req.title, req.audience, req.duration_min))
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/trainings")
def compliance_list_trainings():
    """培训列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_privacy_compliance_manager().list_trainings())
    except Exception as e:
        return _fail(str(e))


# ======================================================================
# 七、控制台 & 系统设置（8 端点）
# ======================================================================
@router.get("/dashboard")
def dashboard():
    """控制台总览"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({
            "overview": get_dashboard().get_overview(),
            "asset_view": get_dashboard().get_asset_view(),
            "protection_view": get_dashboard().get_protection_view(),
            "compliance_view": get_dashboard().get_compliance_view(),
            "monitoring_view": get_dashboard().get_monitoring_view(),
        })
    except Exception as e:
        return _fail(str(e))


@router.get("/alerts")
def list_alerts(level: Optional[str] = None, status: Optional[str] = None):
    """告警列表"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().list_alerts(level, status))
    except Exception as e:
        return _fail(str(e))


@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: str, req: AlertResolveReq):
    """处理告警"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().resolve_alert(alert_id, req.resolution))
    except Exception as e:
        return _fail(str(e))


@router.get("/settings")
def get_settings():
    """系统设置"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().get_settings())
    except Exception as e:
        return _fail(str(e))


@router.put("/settings")
def update_setting(req: SettingUpdateReq):
    """更新设置"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_dashboard().update_setting(req.key, req.value))
    except Exception as e:
        return _fail(str(e))


@router.get("/settings/schema")
def settings_schema():
    """设置项定义"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(SYSTEM_SETTINGS)
    except Exception as e:
        return _fail(str(e))


@router.post("/report/generate")
def generate_report(req: ReportReq):
    """生成合规报告"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(get_access_audit_engine().generate_compliance_report(req.report_type))
    except Exception as e:
        return _fail(str(e))


@router.get("/metrics/library")
def metrics_library():
    """指标库"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok(DASHBOARD_METRICS)
    except Exception as e:
        return _fail(str(e))


@router.get("/stats")
def all_stats():
    """全部统计"""
    try:
        err = _check_modules()
        if err:
            return err
        return _ok({
            "classification": get_classification_engine().stats(),
            "dlp": get_dlp_engine().stats(),
            "privacy_compute": get_privacy_compute_engine().stats(),
            "access_audit": get_access_audit_engine().stats(),
            "compliance": get_privacy_compliance_manager().stats(),
            "dashboard": get_dashboard().stats(),
        })
    except Exception as e:
        return _fail(str(e))
