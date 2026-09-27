# -*- coding: utf-8 -*-
"""developer_portal_routes.py — 开放 API 平台与开发者中心 REST API。

路由前缀: /api/v1/developer-portal
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。
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

router = APIRouter(prefix="/api/v1/developer-portal", tags=["开放API平台"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from developer_portal.api_docs import get_docs_center
    from developer_portal.sdk_tools import get_sdk_manager
    from developer_portal.sandbox_manager import get_sandbox_manager
    from developer_portal.app_key_manager import get_app_key_manager
    from developer_portal.usage_billing import get_usage_billing
    from developer_portal.community_support import get_community
    from developer_portal.portal_workflow import get_portal_workflow
    _MOD_AVAILABLE = True
    logger.info("developer_portal_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("developer_portal_routes: load failed: %s", e)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in TASKS:
        t = TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符 / 非法 Unicode。"""
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ch >= " " or ch in "\n\t")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(v) for v in obj)
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("开发者中心模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class CreateAppRequest(BaseModel):
    name: str = ""
    owner: str = "anonymous"
    description: str = ""
    scopes: List[str] = Field(default_factory=lambda: ["scanner:read"])


class ReviewAppRequest(BaseModel):
    approved: bool = True
    note: str = ""


class UpdateAppRequest(BaseModel):
    ip_whitelist: Optional[List[str]] = None
    callback_url: Optional[str] = None
    scopes: Optional[List[str]] = None
    description: Optional[str] = None


class CreateKeyRequest(BaseModel):
    name: str = "default"
    expires_days: int = 365


class RevokeKeyRequest(BaseModel):
    reason: str = ""


class MockRequestRequest(BaseModel):
    endpoint: str = "/api/v1/ping"
    method: str = "GET"
    payload: Dict[str, Any] = Field(default_factory=dict)


class CreateSandboxRequest(BaseModel):
    owner: str = "anonymous"
    name: str = ""


class SetDatasetRequest(BaseModel):
    dataset: str = "vuln_reports"


class RecordCallRequest(BaseModel):
    app_id: str = ""
    meter: str = "scanner.start"
    cost_units: int = 1


class SubscribeRequest(BaseModel):
    app_id: str = ""
    plan_id: str = "free"


class RateLimitRequest(BaseModel):
    app_id: str = ""
    calls_in_window: int = 0


class GenerateBillRequest(BaseModel):
    app_id: str = ""
    period: str = "2026-09"


class PayBillRequest(BaseModel):
    method: str = "alipay"


class CreatePostRequest(BaseModel):
    author: str = "anonymous"
    title: str = ""
    body: str = ""
    tags: List[str] = Field(default_factory=list)


class ReplyPostRequest(BaseModel):
    author: str = "anonymous"
    body: str = ""


class AskRequest(BaseModel):
    author: str = "anonymous"
    title: str = ""
    body: str = ""
    tags: List[str] = Field(default_factory=list)


class AnswerRequest(BaseModel):
    author: str = "anonymous"
    body: str = ""
    accepted: bool = False


class FeedbackRequest(BaseModel):
    author: str = "anonymous"
    kind: str = "bug"
    body: str = ""


class OnboardRequest(BaseModel):
    developer: str = "anonymous"
    app_name: str = "my-app"
    scopes: List[str] = Field(default_factory=lambda: ["scanner:read"])


class AdvanceRequest(BaseModel):
    developer: str = "anonymous"
    step_key: str = "sandbox_test"


# =========================================================================== #
# 1. API 文档中心（7 个端点）
# =========================================================================== #
@router.get("/docs/categories")
def docs_categories():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_docs_center().categories())
    except Exception as e:
        logger.exception("docs_categories error")
        return fail(f"获取分类失败: {e}", 500)


@router.get("/docs/endpoints")
def docs_endpoints(category: str = Query("全部"), keyword: str = Query("")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_docs_center().list_endpoints(category, keyword))
    except Exception as e:
        logger.exception("docs_endpoints error")
        return fail(f"获取接口列表失败: {e}", 500)


@router.get("/docs/endpoints/{ep_id}")
def docs_endpoint_detail(ep_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ep = get_docs_center().get_endpoint(ep_id)
        if not ep:
            return fail("接口不存在", 404)
        return ok(ep)
    except Exception as e:
        logger.exception("docs_endpoint_detail error")
        return fail(f"获取接口详情失败: {e}", 500)


@router.get("/docs/openapi")
def docs_openapi(version: str = Query("v1")):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("openapi_export")
        spec = get_docs_center().to_openapi(version)
        _finish_task(task_id, spec)
        return ok({"task_id": task_id, "openapi": spec})
    except Exception as e:
        logger.exception("docs_openapi error")
        return fail(f"生成 OpenAPI 失败: {e}", 500)


@router.get("/docs/example-code")
def docs_example_code(ep_id: str = Query(...), language: str = Query("python")):
    try:
        g = _guard()
        if g is not None:
            return g
        code = get_docs_center().example_code(ep_id, language)
        return ok({"ep_id": ep_id, "language": language, "code": code})
    except Exception as e:
        logger.exception("docs_example_code error")
        return fail(f"生成示例代码失败: {e}", 500)


@router.get("/docs/changelog")
def docs_changelog(version: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_docs_center().list_changelog(version))
    except Exception as e:
        logger.exception("docs_changelog error")
        return fail(f"获取变更日志失败: {e}", 500)


@router.get("/docs/error-codes")
def docs_error_codes():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_docs_center().list_error_codes())
    except Exception as e:
        logger.exception("docs_error_codes error")
        return fail(f"获取错误码失败: {e}", 500)


# =========================================================================== #
# 2. SDK 与工具库（7 个端点）
# =========================================================================== #
@router.get("/sdk/list")
def sdk_list():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_sdk_manager().list_sdks())
    except Exception as e:
        logger.exception("sdk_list error")
        return fail(f"获取 SDK 列表失败: {e}", 500)


@router.get("/sdk/{lang}")
def sdk_detail(lang: str):
    try:
        g = _guard()
        if g is not None:
            return g
        sdk = get_sdk_manager().get_sdk(lang)
        if not sdk:
            return fail("SDK 不存在", 404)
        return ok(sdk)
    except Exception as e:
        logger.exception("sdk_detail error")
        return fail(f"获取 SDK 详情失败: {e}", 500)


@router.post("/sdk/{lang}/download")
def sdk_download(lang: str):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("sdk_download")
        result = get_sdk_manager().download(lang)
        if not result:
            _finish_task(task_id, None, "lang not supported")
            return fail("不支持的语言", 404)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, **result})
    except Exception as e:
        logger.exception("sdk_download error")
        return fail(f"下载 SDK 失败: {e}", 500)


@router.get("/sdk/postman")
def sdk_postman():
    try:
        g = _guard()
        if g is not None:
            return ok(get_sdk_manager().generate_postman_collection())
        return g
    except Exception as e:
        logger.exception("sdk_postman error")
        return fail(f"生成 Postman 集合失败: {e}", 500)


@router.get("/sdk/insomnia")
def sdk_insomnia():
    try:
        g = _guard()
        if g is not None:
            return ok(get_sdk_manager().generate_insomnia_collection())
        return g
    except Exception as e:
        logger.exception("sdk_insomnia error")
        return fail(f"生成 Insomnia 集合失败: {e}", 500)


@router.get("/sdk/curl-examples")
def sdk_curl_examples():
    try:
        g = _guard()
        if g is not None:
            return ok(get_sdk_manager().list_curl_examples())
        return g
    except Exception as e:
        logger.exception("sdk_curl_examples error")
        return fail(f"获取 cURL 示例失败: {e}", 500)


@router.get("/sdk/cli")
def sdk_cli():
    try:
        g = _guard()
        if g is not None:
            return ok(get_sdk_manager().cli_integration())
        return g
    except Exception as e:
        logger.exception("sdk_cli error")
        return fail(f"获取 CLI 集成失败: {e}", 500)


# =========================================================================== #
# 3. 开发者沙箱（10 个端点）
# =========================================================================== #
@router.post("/sandbox/create")
def sandbox_create(req: CreateSandboxRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        sb = get_sandbox_manager().create(req.owner, req.name)
        return ok(sb)
    except Exception as e:
        logger.exception("sandbox_create error")
        return fail(f"创建沙箱失败: {e}", 500)


@router.get("/sandbox/list")
def sandbox_list(owner: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_sandbox_manager().list(owner))
    except Exception as e:
        logger.exception("sandbox_list error")
        return fail(f"获取沙箱列表失败: {e}", 500)


@router.get("/sandbox/datasets")
def sandbox_datasets():
    try:
        g = _guard()
        if g is not None:
            return ok(get_sandbox_manager().list_datasets())
        return g
    except Exception as e:
        logger.exception("sandbox_datasets error")
        return fail(f"获取数据集失败: {e}", 500)


@router.get("/sandbox/{sb_id}")
def sandbox_detail(sb_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        sb = get_sandbox_manager().get(sb_id)
        if not sb:
            return fail("沙箱不存在", 404)
        return ok(sb)
    except Exception as e:
        logger.exception("sandbox_detail error")
        return fail(f"获取沙箱详情失败: {e}", 500)


@router.post("/sandbox/{sb_id}/reset")
def sandbox_reset(sb_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        sb = get_sandbox_manager().reset(sb_id)
        if not sb:
            return fail("沙箱不存在", 404)
        return ok(sb)
    except Exception as e:
        logger.exception("sandbox_reset error")
        return fail(f"重置沙箱失败: {e}", 500)


@router.delete("/sandbox/{sb_id}")
def sandbox_destroy(sb_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        ok_ = get_sandbox_manager().destroy(sb_id)
        return ok({"destroyed": ok_})
    except Exception as e:
        logger.exception("sandbox_destroy error")
        return fail(f"销毁沙箱失败: {e}", 500)


@router.get("/sandbox/{sb_id}/health")
def sandbox_health(sb_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_sandbox_manager().health(sb_id))
    except Exception as e:
        logger.exception("sandbox_health error")
        return fail(f"健康检查失败: {e}", 500)


@router.post("/sandbox/{sb_id}/mock-request")
def sandbox_mock_request(sb_id: str, req: MockRequestRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("sandbox_mock_request")
        result = get_sandbox_manager().mock_request(
            sb_id, req.endpoint, req.method, req.payload)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, **result})
    except Exception as e:
        logger.exception("sandbox_mock_request error")
        return fail(f"模拟请求失败: {e}", 500)


@router.get("/sandbox/{sb_id}/logs")
def sandbox_logs(sb_id: str, limit: int = Query(50, ge=1, le=500)):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_sandbox_manager().debug_logs(sb_id, limit))
    except Exception as e:
        logger.exception("sandbox_logs error")
        return fail(f"获取调试日志失败: {e}", 500)


@router.post("/sandbox/{sb_id}/replay")
def sandbox_replay(sb_id: str, req: Dict[str, str]):
    try:
        g = _guard()
        if g is not None:
            return g
        req_id = req.get("req_id", "")
        return ok(get_sandbox_manager().replay(sb_id, req_id))
    except Exception as e:
        logger.exception("sandbox_replay error")
        return fail(f"请求回放失败: {e}", 500)


@router.post("/sandbox/{sb_id}/dataset")
def sandbox_set_dataset(sb_id: str, req: SetDatasetRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_sandbox_manager().set_dataset(sb_id, req.dataset)
        if not result:
            return fail("沙箱不存在", 404)
        return ok(result)
    except Exception as e:
        logger.exception("sandbox_set_dataset error")
        return fail(f"切换数据集失败: {e}", 500)


# =========================================================================== #
# 4. 应用与 API Key（10 个端点）
# =========================================================================== #
@router.post("/apps/register")
def app_register(req: CreateAppRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        app = get_app_key_manager().register_app(
            req.name, req.owner, req.description, req.scopes)
        return ok(app)
    except Exception as e:
        logger.exception("app_register error")
        return fail(f"注册应用失败: {e}", 500)


@router.get("/apps/list")
def app_list(owner: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g is not None:
            return ok(get_app_key_manager().list_apps(owner))
        return g
    except Exception as e:
        logger.exception("app_list error")
        return fail(f"获取应用列表失败: {e}", 500)


@router.get("/apps/{app_id}")
def app_detail(app_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        app = get_app_key_manager().get_app(app_id)
        if not app:
            return fail("应用不存在", 404)
        return ok(app)
    except Exception as e:
        logger.exception("app_detail error")
        return fail(f"获取应用详情失败: {e}", 500)


@router.post("/apps/{app_id}/review")
def app_review(app_id: str, req: ReviewAppRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        app = get_app_key_manager().review_app(app_id, req.approved, req.note)
        if not app:
            return fail("应用不存在", 404)
        return ok(app)
    except Exception as e:
        logger.exception("app_review error")
        return fail(f"审核应用失败: {e}", 500)


@router.patch("/apps/{app_id}")
def app_update(app_id: str, req: UpdateAppRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        fields = req.model_dump(exclude_none=True)
        app = get_app_key_manager().update_app(app_id, **fields)
        if not app:
            return fail("应用不存在", 404)
        return ok(app)
    except Exception as e:
        logger.exception("app_update error")
        return fail(f"更新应用失败: {e}", 500)


@router.get("/apps/{app_id}/stats")
def app_stats(app_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        stats = get_app_key_manager().app_stats(app_id)
        if not stats:
            return fail("应用不存在", 404)
        return ok(stats)
    except Exception as e:
        logger.exception("app_stats error")
        return fail(f"获取应用统计失败: {e}", 500)


@router.get("/scopes")
def scopes_catalog():
    try:
        g = _guard()
        if g is not None:
            return ok(get_app_key_manager().scopes_catalog())
        return g
    except Exception as e:
        logger.exception("scopes_catalog error")
        return fail(f"获取权限范围失败: {e}", 500)


@router.post("/apps/{app_id}/keys")
def key_create(app_id: str, req: CreateKeyRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("key_create")
        rec = get_app_key_manager().create_key(app_id, req.name, req.expires_days)
        if not rec:
            _finish_task(task_id, None, "app not found")
            return fail("应用不存在", 404)
        _finish_task(task_id, rec)
        return ok({"task_id": task_id, **rec})
    except Exception as e:
        logger.exception("key_create error")
        return fail(f"生成密钥失败: {e}", 500)


@router.post("/keys/{key_id}/rotate")
def key_rotate(key_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        rec = get_app_key_manager().rotate_key(key_id)
        if not rec:
            return fail("密钥不存在", 404)
        return ok(rec)
    except Exception as e:
        logger.exception("key_rotate error")
        return fail(f"轮换密钥失败: {e}", 500)


@router.post("/keys/{key_id}/revoke")
def key_revoke(key_id: str, req: RevokeKeyRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        rec = get_app_key_manager().revoke_key(key_id, req.reason)
        if not rec:
            return fail("密钥不存在", 404)
        return ok(rec)
    except Exception as e:
        logger.exception("key_revoke error")
        return fail(f"撤销密钥失败: {e}", 500)


@router.get("/keys/list")
def key_list(app_id: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g is not None:
            return ok(get_app_key_manager().list_keys(app_id))
        return g
    except Exception as e:
        logger.exception("key_list error")
        return fail(f"获取密钥列表失败: {e}", 500)


# =========================================================================== #
# 5. 用量与计费（10 个端点）
# =========================================================================== #
@router.post("/usage/record")
def usage_record(req: RecordCallRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_usage_billing().record_call(req.app_id, req.meter, req.cost_units))
    except Exception as e:
        logger.exception("usage_record error")
        return fail(f"记录用量失败: {e}", 500)


@router.get("/usage/{app_id}")
def usage_get(app_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_usage_billing().get_usage(app_id))
    except Exception as e:
        logger.exception("usage_get error")
        return fail(f"获取用量失败: {e}", 500)


@router.post("/usage/{app_id}/reset")
def usage_reset(app_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        u = get_usage_billing().quota_reset(app_id)
        if not u:
            return fail("无用量记录", 404)
        return ok(u)
    except Exception as e:
        logger.exception("usage_reset error")
        return fail(f"重置配额失败: {e}", 500)


@router.get("/plans")
def plans_list():
    try:
        g = _guard()
        if g is not None:
            return ok(get_usage_billing().list_plans())
        return g
    except Exception as e:
        logger.exception("plans_list error")
        return fail(f"获取套餐失败: {e}", 500)


@router.post("/subscribe")
def subscribe(req: SubscribeRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_usage_billing().subscribe(req.app_id, req.plan_id)
        if not result.get("success", False):
            return fail(result.get("error", "订阅失败"), 400)
        return ok(result)
    except Exception as e:
        logger.exception("subscribe error")
        return fail(f"订阅失败: {e}", 500)


@router.post("/rate-limit-check")
def rate_limit_check(req: RateLimitRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_usage_billing().rate_limit_check(req.app_id, req.calls_in_window))
    except Exception as e:
        logger.exception("rate_limit_check error")
        return fail(f"限流检查失败: {e}", 500)


@router.post("/bills/generate")
def bill_generate(req: GenerateBillRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("bill_generate")
        bill = get_usage_billing().generate_bill(req.app_id, req.period)
        _finish_task(task_id, bill)
        return ok({"task_id": task_id, **bill})
    except Exception as e:
        logger.exception("bill_generate error")
        return fail(f"生成账单失败: {e}", 500)


@router.get("/bills")
def bill_list(app_id: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g is not None:
            return ok(get_usage_billing().list_bills(app_id))
        return g
    except Exception as e:
        logger.exception("bill_list error")
        return fail(f"获取账单失败: {e}", 500)


@router.post("/bills/{bill_id}/pay")
def bill_pay(bill_id: str, req: PayBillRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_usage_billing().pay_bill(bill_id, req.method)
        if not result.get("success", False):
            return fail(result.get("error", "支付失败"), 404)
        return ok(result)
    except Exception as e:
        logger.exception("bill_pay error")
        return fail(f"支付失败: {e}", 500)


@router.get("/free-quota")
def free_quota():
    try:
        g = _guard()
        if g is not None:
            return ok(get_usage_billing().free_quota())
        return g
    except Exception as e:
        logger.exception("free_quota error")
        return fail(f"获取免费额度失败: {e}", 500)


@router.get("/alarms")
def alarms_list(app_id: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g is not None:
            return ok(get_usage_billing().list_alarms(app_id))
        return g
    except Exception as e:
        logger.exception("alarms_list error")
        return fail(f"获取告警失败: {e}", 500)


# =========================================================================== #
# 6. 开发者社区与支持（12 个端点）
# =========================================================================== #
@router.post("/community/posts")
def community_create_post(req: CreatePostRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_community().create_post(req.author, req.title, req.body, req.tags))
    except Exception as e:
        logger.exception("community_create_post error")
        return fail(f"发帖失败: {e}", 500)


@router.get("/community/posts")
def community_list_posts(tag: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g is not None:
            return ok(get_community().list_posts(tag))
        return g
    except Exception as e:
        logger.exception("community_list_posts error")
        return fail(f"获取帖子失败: {e}", 500)


@router.post("/community/posts/{post_id}/reply")
def community_reply_post(post_id: str, req: ReplyPostRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        r = get_community().reply_post(post_id, req.author, req.body)
        if not r:
            return fail("帖子不存在", 404)
        return ok(r)
    except Exception as e:
        logger.exception("community_reply_post error")
        return fail(f"回复帖子失败: {e}", 500)


@router.post("/community/questions")
def community_ask(req: AskRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_community().ask(req.author, req.title, req.body, req.tags))
    except Exception as e:
        logger.exception("community_ask error")
        return fail(f"提问失败: {e}", 500)


@router.get("/community/questions")
def community_list_questions():
    try:
        g = _guard()
        if g is not None:
            return ok(get_community().list_questions())
        return g
    except Exception as e:
        logger.exception("community_list_questions error")
        return fail(f"获取问题失败: {e}", 500)


@router.post("/community/questions/{qid}/answer")
def community_answer(qid: str, req: AnswerRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        a = get_community().answer(qid, req.author, req.body, req.accepted)
        if not a:
            return fail("问题不存在", 404)
        return ok(a)
    except Exception as e:
        logger.exception("community_answer error")
        return fail(f"回答失败: {e}", 500)


@router.get("/community/tutorials")
def community_tutorials():
    try:
        g = _guard()
        if g is not None:
            return ok(get_community().list_tutorials())
        return g
    except Exception as e:
        logger.exception("community_tutorials error")
        return fail(f"获取教程失败: {e}", 500)


@router.get("/community/faq")
def community_faq():
    try:
        g = _guard()
        if g is not None:
            return ok(get_community().list_faq())
        return g
    except Exception as e:
        logger.exception("community_faq error")
        return fail(f"获取 FAQ 失败: {e}", 500)


@router.get("/community/announcements")
def community_announcements():
    try:
        g = _guard()
        if g is not None:
            return ok(get_community().list_announcements())
        return g
    except Exception as e:
        logger.exception("community_announcements error")
        return fail(f"获取公告失败: {e}", 500)


@router.get("/community/status")
def community_status():
    try:
        g = _guard()
        if g is not None:
            return ok(get_community().get_status_page())
        return g
    except Exception as e:
        logger.exception("community_status error")
        return fail(f"获取状态页失败: {e}", 500)


@router.post("/community/feedback")
def community_submit_feedback(req: FeedbackRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_community().submit_feedback(req.author, req.kind, req.body))
    except Exception as e:
        logger.exception("community_submit_feedback error")
        return fail(f"提交反馈失败: {e}", 500)


@router.get("/community/feedback")
def community_list_feedback(status: Optional[str] = Query(None)):
    try:
        g = _guard()
        if g is not None:
            return ok(get_community().list_feedback(status))
        return g
    except Exception as e:
        logger.exception("community_list_feedback error")
        return fail(f"获取反馈失败: {e}", 500)


@router.get("/community/tiers")
def community_tiers():
    try:
        g = _guard()
        if g is not None:
            return ok(get_community().list_tiers())
        return g
    except Exception as e:
        logger.exception("community_tiers error")
        return fail(f"获取开发者等级失败: {e}", 500)


@router.get("/community/contributors")
def community_contributors():
    try:
        g = _guard()
        if g is not None:
            return ok(get_community().contributors())
        return g
    except Exception as e:
        logger.exception("community_contributors error")
        return fail(f"获取贡献者失败: {e}", 500)


# =========================================================================== #
# 7. 综合工作流（5 个端点）
# =========================================================================== #
@router.get("/workflow/steps")
def workflow_steps():
    try:
        g = _guard()
        if g is not None:
            return ok(get_portal_workflow().steps())
        return g
    except Exception as e:
        logger.exception("workflow_steps error")
        return fail(f"获取工作流步骤失败: {e}", 500)


@router.post("/workflow/onboard")
def workflow_onboard(req: OnboardRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        task_id = _new_task("onboard")
        result = get_portal_workflow().onboard(req.developer, req.app_name, req.scopes)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, **result})
    except Exception as e:
        logger.exception("workflow_onboard error")
        return fail(f"一键入驻失败: {e}", 500)


@router.post("/workflow/advance")
def workflow_advance(req: AdvanceRequest):
    try:
        g = _guard()
        if g is not None:
            return g
        result = get_portal_workflow().advance(req.developer, req.step_key)
        if not result.get("success", False):
            return fail(result.get("error", "推进失败"), 400)
        return ok(result)
    except Exception as e:
        logger.exception("workflow_advance error")
        return fail(f"推进工作流失败: {e}", 500)


@router.get("/workflow/progress")
def workflow_progress(developer: str = Query("anonymous")):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_portal_workflow().get_progress(developer))
    except Exception as e:
        logger.exception("workflow_progress error")
        return fail(f"获取进度失败: {e}", 500)


@router.get("/workflow/overview")
def workflow_overview():
    try:
        g = _guard()
        if g is not None:
            return ok(get_portal_workflow().overview())
        return g
    except Exception as e:
        logger.exception("workflow_overview error")
        return fail(f"获取平台总览失败: {e}", 500)
