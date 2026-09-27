# -*- coding: utf-8 -*-
"""
api_server/api_security_lifecycle_routes.py — 第29轮升级方向3：API 安全全生命周期 REST API。

路由前缀: /api/v1/api-security-lifecycle
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。

覆盖 7 大模块 60+ 端点：
    总览/设置 · API资产 · 设计安全 · 开发安全 · 运行时安全 · 滥用与业务逻辑 · 治理合规
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

router = APIRouter(prefix="/api/v1/api-security-lifecycle", tags=["API安全全生命周期"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from api_security_lifecycle.api_assets import get_api_assets
    from api_security_lifecycle.design_security import get_design_security
    from api_security_lifecycle.dev_security import get_dev_security
    from api_security_lifecycle.runtime_security import get_runtime_security
    from api_security_lifecycle.abuse_logic import get_abuse_logic
    from api_security_lifecycle.governance_compliance import get_governance_compliance
    from api_security_lifecycle.api_security_dashboard import (
        get_api_security_dashboard, SYSTEM_SETTINGS,
    )
    _MOD_AVAILABLE = True
    logger.info("api_security_lifecycle_routes: modules loaded OK")
except Exception as e:
    logger.exception("api_security_lifecycle_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from api_security_lifecycle.api_assets import get_api_assets  # noqa
        from api_security_lifecycle.design_security import get_design_security  # noqa
        from api_security_lifecycle.dev_security import get_dev_security  # noqa
        from api_security_lifecycle.runtime_security import get_runtime_security  # noqa
        from api_security_lifecycle.abuse_logic import get_abuse_logic  # noqa
        from api_security_lifecycle.governance_compliance import get_governance_compliance  # noqa
        from api_security_lifecycle.api_security_dashboard import (  # noqa
            get_api_security_dashboard, SYSTEM_SETTINGS,
        )
        _MOD_AVAILABLE = True
        logger.info("api_security_lifecycle_routes: fallback import OK")
    except Exception as e2:
        logger.exception("api_security_lifecycle_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
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


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("API安全全生命周期模块不可用，请检查加载日志", 503)
    return None


# =========================================================================== #
# 请求模型
# =========================================================================== #
class AssetRegisterReq(BaseModel):
    name: str
    method: str = "GET"
    path: str
    description: str = ""
    category: str = "other"
    owner: str = "unknown"


class AssetUpdateReq(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    lifecycle: Optional[str] = None
    category: Optional[str] = None
    visibility: Optional[str] = None
    owner: Optional[str] = None
    team: Optional[str] = None
    auth_type: Optional[str] = None
    rate_limit: Optional[int] = None


class GatewayDiscoverReq(BaseModel):
    routes: List[Dict[str, Any]] = Field(default_factory=list)


class TrafficDiscoverReq(BaseModel):
    log_lines: List[str] = Field(default_factory=list)


class OpenAPIDiscoverReq(BaseModel):
    spec: Dict[str, Any] = Field(default_factory=dict)


class DependencyReq(BaseModel):
    dep_id: str
    dep_type: str = "upstream"
    reason: str = ""


class HealthRecordReq(BaseModel):
    latency_ms: float = 0
    error_rate_pct: float = 0
    throughput_rpm: float = 0
    status: str = "healthy"


class AuthConfigReq(BaseModel):
    api_id: str
    method: str
    config: Dict[str, Any] = Field(default_factory=dict)


class SchemaRegisterReq(BaseModel):
    name: str
    json_schema: Dict[str, Any] = Field(default_factory=dict, alias="schema")


class ValidateReq(BaseModel):
    data: Any = None
    schema_name: str = ""


class OutputCheckReq(BaseModel):
    data: str = ""
    output_type: str = "json"


class ReviewReq(BaseModel):
    api_name: str
    method: str = "GET"
    path: str = "/"
    has_auth: bool = True
    has_rate_limit: bool = True
    has_input_validation: bool = True
    has_tls: bool = True
    error_messages_generic: bool = True
    uses_minimal_privilege: bool = True


class SecretDetectReq(BaseModel):
    code: str = ""
    filename: str = "snippet"


class CodingCheckReq(BaseModel):
    code: str = ""
    lang: str = "python"


class FuzzReq(BaseModel):
    endpoint: str = "/"
    method: str = "GET"
    params: List[str] = Field(default_factory=list)


class KeyGenerateReq(BaseModel):
    name: str
    owner: str = "unknown"
    scopes: List[str] = Field(default_factory=lambda: ["read"])


class VersionCreateReq(BaseModel):
    api_id: str
    version: str
    deprecated: bool = False


class GateEvaluateReq(BaseModel):
    findings: Dict[str, int] = Field(default_factory=dict)


class DocCreateReq(BaseModel):
    title: str
    doc_type: str = "design"
    content: str = ""
    author: str = "dev-team"


class RouteAddReq(BaseModel):
    path: str
    service: str
    upstream_url: str
    methods: List[str] = Field(default_factory=lambda: ["GET"])
    auth_required: bool = True


class ABACEvalReq(BaseModel):
    user_attrs: Dict[str, Any] = Field(default_factory=dict)
    resource_attrs: Dict[str, Any] = Field(default_factory=dict)
    action: str = "read"


class RateLimitRuleReq(BaseModel):
    name: str
    rpm: int = 600
    burst: int = 10
    key_by: str = "ip"


class RateLimitCheckReq(BaseModel):
    rule_id: str
    client_key: str


class ThreatDetectReq(BaseModel):
    input_data: str = ""
    context: str = "query"


class MaskReq(BaseModel):
    data: Dict[str, Any] = Field(default_factory=dict)
    sensitive_fields: List[str] = Field(default_factory=list)


class MetricRecordReq(BaseModel):
    api_id: str
    latency_ms: float = 0
    error: bool = False


class AbuseLogReq(BaseModel):
    client_key: str
    endpoint: str = "/"
    user_agent: str = ""


class BotDetectReq(BaseModel):
    user_agent: str = ""
    request_count: int = 0
    mouse_events: int = 0
    scroll_events: int = 0


class FlawDetectReq(BaseModel):
    api_endpoint: str = "/"
    method: str = "GET"
    user_role: str = "user"
    target_user_id: str = ""
    authenticated_user_id: str = ""
    params: Dict[str, Any] = Field(default_factory=dict)
    is_admin_endpoint: bool = False


class ReplayVerifyReq(BaseModel):
    nonce: str = ""
    timestamp: int = 0
    signature: str = ""
    secret: str = ""
    body: str = ""


class QuotaCheckReq(BaseModel):
    client_id: str = ""
    tier_id: str = "tier-free"
    current_usage: int = 0


class BillReq(BaseModel):
    client_id: str = ""
    tier_id: str = "tier-free"
    usage_calls: int = 0
    period: str = "2026-09"


class SecurityEventReq(BaseModel):
    title: str
    event_type: str = "abuse"
    severity: str = "medium"
    description: str = ""


class EventStatusReq(BaseModel):
    status: str
    note: str = ""


class PolicyCreateReq(BaseModel):
    name: str
    ptype: str = "access"
    description: str = ""
    enforcement: str = "advisory"


class PolicyEvaluateReq(BaseModel):
    resource_attrs: Dict[str, Any] = Field(default_factory=dict)


class ComplianceAssessReq(BaseModel):
    framework_id: str
    implementation_status: Dict[str, bool] = Field(default_factory=dict)


class MetricRecordReq2(BaseModel):
    metric_name: str
    value: float
    tags: Dict[str, str] = Field(default_factory=dict)


class AuditLogReq(BaseModel):
    action: str
    actor: str
    resource: str
    detail: str = ""
    ip: str = ""


class ReportGenerateReq(BaseModel):
    report_type: str = "overview"
    period: str = "2026-09"


class MaturityAssessReq(BaseModel):
    governance: int = 1
    design: int = 1
    development: int = 1
    runtime: int = 1
    monitoring: int = 1


class SettingsUpdateReq(BaseModel):
    fields: Dict[str, Any] = Field(default_factory=dict)


# =========================================================================== #
# 一、总览 / 系统设置
# =========================================================================== #
@router.get("/overview")
def overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_security_dashboard().overview())
    except Exception as e:
        logger.exception("overview error")
        return fail(str(e))


@router.get("/summary")
def summary():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_security_dashboard().summary_by_module())
    except Exception as e:
        return fail(str(e))


@router.get("/settings")
def get_settings():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_security_dashboard().get_settings())
    except Exception as e:
        return fail(str(e))


@router.put("/settings")
def update_settings(req: SettingsUpdateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_security_dashboard().update_settings(req.fields))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 二、API 资产管理
# =========================================================================== #
@router.get("/assets/apis")
def list_apis(status: Optional[str] = None, category: Optional[str] = None,
              visibility: Optional[str] = None,
              discovery_source: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().list_apis(status, category, visibility, discovery_source))
    except Exception as e:
        return fail(str(e))


@router.post("/assets/apis")
def register_api(req: AssetRegisterReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().manual_register(req.name, req.method, req.path,
                                                    req.description, req.category, req.owner))
    except Exception as e:
        return fail(str(e))


@router.get("/assets/apis/{api_id}")
def get_api(api_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_api_assets().get_api(api_id)
        if not result:
            return fail("API not found", 404)
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.put("/assets/apis/{api_id}")
def update_api(api_id: str, req: AssetUpdateReq):
    try:
        g = _guard()
        if g:
            return g
        result = get_api_assets().update_api(api_id, req.model_dump(exclude_none=True))
        if not result:
            return fail("API not found", 404)
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.delete("/assets/apis/{api_id}")
def delete_api(api_id: str):
    try:
        g = _guard()
        if g:
            return g
        if get_api_assets().delete_api(api_id):
            return ok({"deleted": api_id})
        return fail("API not found", 404)
    except Exception as e:
        return fail(str(e))


@router.get("/assets/search")
def search_apis(keyword: str = Query(...)):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().search_apis(keyword))
    except Exception as e:
        return fail(str(e))


@router.get("/assets/catalog")
def api_catalog():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().api_catalog())
    except Exception as e:
        return fail(str(e))


@router.post("/assets/discover/gateway")
def discover_gateway(req: GatewayDiscoverReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().discover_from_gateway(req.routes))
    except Exception as e:
        return fail(str(e))


@router.post("/assets/discover/traffic")
def discover_traffic(req: TrafficDiscoverReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().discover_from_traffic(req.log_lines))
    except Exception as e:
        return fail(str(e))


@router.post("/assets/discover/openapi")
def discover_openapi(req: OpenAPIDiscoverReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().discover_from_openapi(req.spec))
    except Exception as e:
        return fail(str(e))


@router.get("/assets/{api_id}/dependencies")
def get_dependencies(api_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().get_dependencies(api_id))
    except Exception as e:
        return fail(str(e))


@router.post("/assets/{api_id}/dependencies")
def add_dependency(api_id: str, req: DependencyReq):
    try:
        g = _guard()
        if g:
            return g
        if get_api_assets().add_dependency(api_id, req.dep_id, req.dep_type, req.reason):
            return ok({"added": True})
        return fail("API or dependency not found", 404)
    except Exception as e:
        return fail(str(e))


@router.get("/assets/service-map")
def service_map():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().build_service_map())
    except Exception as e:
        return fail(str(e))


@router.get("/assets/circular-deps")
def circular_deps():
    try:
        g = _guard()
        if g:
            return g
        return ok({"cycles": get_api_assets().detect_circular_deps()})
    except Exception as e:
        return fail(str(e))


@router.get("/assets/single-point-deps")
def single_point_deps():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().single_point_dependencies())
    except Exception as e:
        return fail(str(e))


@router.get("/assets/health")
def health_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().health_overview())
    except Exception as e:
        return fail(str(e))


@router.post("/assets/health/{api_id}/record")
def record_health(api_id: str, req: HealthRecordReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().record_health(api_id, req.latency_ms,
                                                   req.error_rate_pct, req.throughput_rpm, req.status))
    except Exception as e:
        return fail(str(e))


@router.get("/assets/health/{api_id}/score")
def health_score(api_id: str):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().compute_health_score(api_id))
    except Exception as e:
        return fail(str(e))


@router.get("/assets/inventory")
def asset_inventory():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_assets().asset_inventory())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 三、API 设计安全
# =========================================================================== #
@router.get("/design/principles")
def design_principles():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().list_principles())
    except Exception as e:
        return fail(str(e))


@router.get("/design/specs")
def list_specs(category: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().list_specs(category))
    except Exception as e:
        return fail(str(e))


@router.post("/design/specs")
def create_spec(req: dict):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().create_spec(
            req.get("name", "unnamed"), req.get("category", "generic"),
            req.get("rules", [])))
    except Exception as e:
        return fail(str(e))


@router.post("/design/specs/{spec_id}/rules")
def add_spec_rule(spec_id: str, req: dict):
    try:
        g = _guard()
        if g:
            return g
        if get_design_security().add_spec_rule(spec_id, req):
            return ok({"added": True})
        return fail("Spec not found", 404)
    except Exception as e:
        return fail(str(e))


@router.get("/design/auth-methods")
def auth_methods():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().list_auth_methods())
    except Exception as e:
        return fail(str(e))


@router.post("/design/auth-config")
def configure_auth(req: AuthConfigReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().configure_auth(req.api_id, req.method, req.config))
    except Exception as e:
        return fail(str(e))


@router.get("/design/auth-configs")
def list_auth_configs():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().list_auth_configs())
    except Exception as e:
        return fail(str(e))


@router.post("/design/schemas")
def register_schema(req: SchemaRegisterReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().register_schema(req.name, req.json_schema))
    except Exception as e:
        return fail(str(e))


@router.post("/design/validate")
def validate_input(req: ValidateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().validate_input(req.data, req.schema_name))
    except Exception as e:
        return fail(str(e))


@router.post("/design/output-check")
def output_check(req: OutputCheckReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().output_encode_check(req.data, req.output_type))
    except Exception as e:
        return fail(str(e))


@router.get("/design/error-codes")
def list_error_codes(category: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().list_error_codes(category))
    except Exception as e:
        return fail(str(e))


@router.post("/design/review")
def review_design(req: ReviewReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().review_design(
            req.api_name, req.method, req.path,
            req.has_auth, req.has_rate_limit,
            req.has_input_validation, req.has_tls,
            req.error_messages_generic, req.uses_minimal_privilege))
    except Exception as e:
        return fail(str(e))


@router.get("/design/reviews")
def list_reviews():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_design_security().list_reviews())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 四、API 开发安全
# =========================================================================== #
@router.post("/dev/detect-secrets")
def detect_secrets(req: SecretDetectReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().detect_secrets(req.code, req.filename))
    except Exception as e:
        return fail(str(e))


@router.post("/dev/coding-check")
def coding_check(req: CodingCheckReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().coding_standards_check(req.code, req.lang))
    except Exception as e:
        return fail(str(e))


@router.post("/dev/fuzz")
def run_fuzz(req: FuzzReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().run_fuzz_test(req.endpoint, req.method, req.params))
    except Exception as e:
        return fail(str(e))


@router.get("/dev/test-runs")
def list_test_runs():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().list_test_runs())
    except Exception as e:
        return fail(str(e))


@router.post("/dev/keys")
def generate_key(req: KeyGenerateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().generate_key(req.name, req.owner, req.scopes))
    except Exception as e:
        return fail(str(e))


@router.get("/dev/keys")
def list_keys(status: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().list_keys(status))
    except Exception as e:
        return fail(str(e))


@router.post("/dev/keys/{key_id}/revoke")
def revoke_key(key_id: str):
    try:
        g = _guard()
        if g:
            return g
        if get_dev_security().revoke_key(key_id):
            return ok({"revoked": key_id})
        return fail("Key not found", 404)
    except Exception as e:
        return fail(str(e))


@router.post("/dev/keys/{key_id}/rotate")
def rotate_key(key_id: str):
    try:
        g = _guard()
        if g:
            return g
        result = get_dev_security().rotate_key(key_id)
        if not result:
            return fail("Key not found or revoked", 404)
        return ok(result)
    except Exception as e:
        return fail(str(e))


@router.get("/dev/keys/audit")
def key_audit():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().key_audit())
    except Exception as e:
        return fail(str(e))


@router.get("/dev/versions")
def list_versions(api_id: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().list_versions(api_id))
    except Exception as e:
        return fail(str(e))


@router.post("/dev/versions")
def create_version(req: VersionCreateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().create_version(req.api_id, req.version, req.deprecated))
    except Exception as e:
        return fail(str(e))


@router.post("/dev/versions/{version_id}/deprecate")
def deprecate_version(version_id: str, days: int = 90):
    try:
        g = _guard()
        if g:
            return g
        if get_dev_security().deprecate_version(version_id, days):
            return ok({"deprecated": version_id})
        return fail("Version not found", 404)
    except Exception as e:
        return fail(str(e))


@router.get("/dev/versions/stats")
def version_stats():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().version_stats())
    except Exception as e:
        return fail(str(e))


@router.post("/dev/gate/evaluate")
def evaluate_gate(req: GateEvaluateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().evaluate_gate(req.findings))
    except Exception as e:
        return fail(str(e))


@router.get("/dev/pipelines")
def list_pipelines():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().list_pipelines())
    except Exception as e:
        return fail(str(e))


@router.post("/dev/docs")
def create_doc(req: DocCreateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dev_security().create_doc(req.title, req.doc_type, req.content, req.author))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 五、API 运行时安全
# =========================================================================== #
@router.get("/runtime/routes")
def list_routes():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().list_routes())
    except Exception as e:
        return fail(str(e))


@router.post("/runtime/routes")
def add_route(req: RouteAddReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().add_route(req.path, req.service,
                                                     req.upstream_url, req.methods, req.auth_required))
    except Exception as e:
        return fail(str(e))


@router.get("/runtime/roles")
def list_roles():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().list_roles())
    except Exception as e:
        return fail(str(e))


@router.post("/runtime/abac-evaluate")
def evaluate_abac(req: ABACEvalReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().evaluate_abac(req.user_attrs, req.resource_attrs, req.action))
    except Exception as e:
        return fail(str(e))


@router.get("/runtime/rate-limit-rules")
def list_rl_rules():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().list_rate_limit_rules())
    except Exception as e:
        return fail(str(e))


@router.post("/runtime/rate-limit-rules")
def add_rl_rule(req: RateLimitRuleReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().add_rate_limit_rule(req.name, req.rpm, req.burst, req.key_by))
    except Exception as e:
        return fail(str(e))


@router.post("/runtime/rate-limit-check")
def rate_limit_check(req: RateLimitCheckReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().rate_limit_check(req.rule_id, req.client_key))
    except Exception as e:
        return fail(str(e))


@router.post("/runtime/detect-threat")
def detect_threat(req: ThreatDetectReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().detect_threat(req.input_data, req.context))
    except Exception as e:
        return fail(str(e))


@router.get("/runtime/threat-events")
def list_threat_events(category: Optional[str] = None, limit: int = 50):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().list_threat_events(category, limit))
    except Exception as e:
        return fail(str(e))


@router.get("/runtime/threat-overview")
def threat_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().threat_overview())
    except Exception as e:
        return fail(str(e))


@router.post("/runtime/mask")
def mask_data(req: MaskReq):
    try:
        g = _guard()
        if g:
            return g
        return ok({"masked": get_runtime_security().mask_data(req.data, req.sensitive_fields)})
    except Exception as e:
        return fail(str(e))


@router.get("/runtime/data-protection")
def list_data_protection():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().list_data_protection())
    except Exception as e:
        return fail(str(e))


@router.get("/runtime/metrics")
def get_metrics(api_id: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().metric_summary(api_id))
    except Exception as e:
        return fail(str(e))


@router.post("/runtime/metrics/record")
def record_metric(req: MetricRecordReq):
    try:
        g = _guard()
        if g:
            return g
        get_runtime_security().record_metric(req.api_id, req.latency_ms, req.error)
        return ok({"recorded": True})
    except Exception as e:
        return fail(str(e))


@router.get("/runtime/alert-rules")
def list_alert_rules():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_runtime_security().list_alert_rules())
    except Exception as e:
        return fail(str(e))


@router.get("/runtime/alerts")
def evaluate_alerts():
    try:
        g = _guard()
        if g:
            return g
        return ok({"triggered": get_runtime_security().evaluate_alerts()})
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 六、API 滥用与业务逻辑安全
# =========================================================================== #
@router.post("/abuse/log-request")
def log_request(req: AbuseLogReq):
    try:
        g = _guard()
        if g:
            return g
        get_abuse_logic().log_request(req.client_key, req.endpoint, req.user_agent)
        return ok({"logged": True})
    except Exception as e:
        return fail(str(e))


@router.post("/abuse/detect")
def detect_abuse(client_key: str = Query(...)):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().detect_abuse(client_key))
    except Exception as e:
        return fail(str(e))


@router.get("/abuse/alerts")
def list_abuse_alerts(status: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().list_abuse_alerts(status))
    except Exception as e:
        return fail(str(e))


@router.post("/abuse/detect-bot")
def detect_bot(req: BotDetectReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().detect_bot(req.user_agent, req.request_count,
                                                req.mouse_events, req.scroll_events))
    except Exception as e:
        return fail(str(e))


@router.get("/abuse/bot-records")
def list_bot_records():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().list_bot_records())
    except Exception as e:
        return fail(str(e))


@router.get("/abuse/bot-overview")
def bot_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().bot_overview())
    except Exception as e:
        return fail(str(e))


@router.post("/abuse/detect-flaw")
def detect_flaw(req: FlawDetectReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().detect_logic_flaw(
            req.api_endpoint, req.method, req.user_role,
            req.target_user_id, req.authenticated_user_id,
            req.params, req.is_admin_endpoint))
    except Exception as e:
        return fail(str(e))


@router.get("/abuse/flaws")
def list_flaws(severity: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().list_logic_flaws(severity))
    except Exception as e:
        return fail(str(e))


@router.get("/abuse/flaw-overview")
def flaw_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().flaw_overview())
    except Exception as e:
        return fail(str(e))


@router.post("/abuse/nonce")
def generate_nonce():
    try:
        g = _guard()
        if g:
            return g
        return ok({"nonce": get_abuse_logic().generate_nonce()})
    except Exception as e:
        return fail(str(e))


@router.post("/abuse/verify-replay")
def verify_replay(req: ReplayVerifyReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().verify_replay(
            req.nonce, req.timestamp, req.signature, req.secret, req.body))
    except Exception as e:
        return fail(str(e))


@router.get("/abuse/tiers")
def list_tiers():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().list_tiers())
    except Exception as e:
        return fail(str(e))


@router.post("/abuse/check-quota")
def check_quota(req: QuotaCheckReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().check_quota(req.client_id, req.tier_id, req.current_usage))
    except Exception as e:
        return fail(str(e))


@router.post("/abuse/bill")
def generate_bill(req: BillReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().generate_bill(req.client_id, req.tier_id,
                                                    req.usage_calls, req.period))
    except Exception as e:
        return fail(str(e))


@router.get("/abuse/bills")
def list_bills(client_id: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().list_bills(client_id))
    except Exception as e:
        return fail(str(e))


@router.post("/abuse/events")
def create_event(req: SecurityEventReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().create_security_event(
            req.title, req.event_type, req.severity, req.description))
    except Exception as e:
        return fail(str(e))


@router.get("/abuse/events")
def list_events(status: Optional[str] = None, severity: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_abuse_logic().list_security_events(status, severity))
    except Exception as e:
        return fail(str(e))


@router.put("/abuse/events/{event_id}/status")
def update_event(event_id: str, req: EventStatusReq):
    try:
        g = _guard()
        if g:
            return g
        result = get_abuse_logic().update_event_status(event_id, req.status, req.note)
        if not result:
            return fail("Event not found", 404)
        return ok(result)
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 七、API 安全治理与合规
# =========================================================================== #
@router.get("/gov/policies")
def list_policies(ptype: Optional[str] = None):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().list_policies(ptype))
    except Exception as e:
        return fail(str(e))


@router.post("/gov/policies")
def create_policy(req: PolicyCreateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().create_policy(
            req.name, req.ptype, req.description, req.enforcement))
    except Exception as e:
        return fail(str(e))


@router.post("/gov/policies/{policy_id}/evaluate")
def evaluate_policy(policy_id: str, req: PolicyEvaluateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().evaluate_policy(policy_id, req.resource_attrs))
    except Exception as e:
        return fail(str(e))


@router.get("/gov/frameworks")
def list_frameworks():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().list_frameworks())
    except Exception as e:
        return fail(str(e))


@router.post("/gov/assess")
def assess_compliance(req: ComplianceAssessReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().assess_compliance(
            req.framework_id, req.implementation_status))
    except Exception as e:
        return fail(str(e))


@router.get("/gov/assessments")
def list_assessments():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().list_assessments())
    except Exception as e:
        return fail(str(e))


@router.get("/gov/compliance-overview")
def compliance_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().compliance_overview())
    except Exception as e:
        return fail(str(e))


@router.post("/gov/metrics")
def record_metric(req: MetricRecordReq2):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().record_metric(req.metric_name, req.value, req.tags))
    except Exception as e:
        return fail(str(e))


@router.get("/gov/metrics")
def get_metrics():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().security_metrics())
    except Exception as e:
        return fail(str(e))


@router.post("/gov/audit-log")
def log_audit(req: AuditLogReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().log_audit(
            req.action, req.actor, req.resource, req.detail, req.ip))
    except Exception as e:
        return fail(str(e))


@router.get("/gov/audit-logs")
def list_audit_logs(actor: Optional[str] = None, action: Optional[str] = None,
                     limit: int = 100):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().list_audit_logs(actor, action, limit))
    except Exception as e:
        return fail(str(e))


@router.get("/gov/audit-summary")
def audit_summary():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().audit_summary())
    except Exception as e:
        return fail(str(e))


@router.post("/gov/reports")
def generate_report(req: ReportGenerateReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().generate_report(req.report_type, req.period))
    except Exception as e:
        return fail(str(e))


@router.get("/gov/reports")
def list_reports():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().list_reports())
    except Exception as e:
        return fail(str(e))


@router.post("/gov/maturity")
def assess_maturity(req: MaturityAssessReq):
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().assess_maturity(req.model_dump()))
    except Exception as e:
        return fail(str(e))


@router.get("/gov/maturity")
def get_maturity():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_governance_compliance().get_maturity())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 八、异步任务查询
# =========================================================================== #
@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        g = _guard()
        if g:
            return g
        if task_id in TASKS:
            return ok(TASKS[task_id])
        return fail("Task not found", 404)
    except Exception as e:
        return fail(str(e))
