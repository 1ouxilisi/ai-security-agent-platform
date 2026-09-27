# -*- coding: utf-8 -*-
"""
ux_docs_deep_routes.py — 第28轮升级方向4：文档完善与用户体验优化 REST API。

路由前缀: /api/v1/ux-docs-deep
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。
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

router = APIRouter(prefix="/api/v1/ux-docs-deep", tags=["UX Docs Deep 文档与UX优化"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from ux_docs_deep.user_manual import get_user_manual_manager, MANUAL_SECTIONS
    from ux_docs_deep.deployment_docs import (
        get_deployment_docs_manager, DEPLOYMENT_PLATFORMS,
        HARDWARE_REQUIREMENTS, CONFIG_CATEGORIES,
    )
    from ux_docs_deep.api_docs import (
        get_api_docs_manager, AUTH_METHODS, ERROR_CODE_TABLE, SDK_REGISTRY,
    )
    from ux_docs_deep.frontend_ux import (
        get_frontend_ux_manager, DESIGN_TOKENS, ACCESSIBILITY_RULES, I18N_LANGUAGES,
    )
    from ux_docs_deep.onboarding_tutorials import (
        get_onboarding_manager, GUIDE_FLOWS, VIDEO_CATEGORIES,
        LAB_ENVIRONMENTS, LEARNING_PATHS,
    )
    from ux_docs_deep.docs_management import get_docs_manager, DOC_CATEGORIES, ROLES
    from ux_docs_deep.ux_docs_dashboard import (
        get_ux_docs_dashboard, SYSTEM_SETTINGS,
    )
    _MOD_AVAILABLE = True
    logger.info("ux_docs_deep_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("ux_docs_deep_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from ux_docs_deep.user_manual import get_user_manual_manager, MANUAL_SECTIONS  # noqa
        from ux_docs_deep.deployment_docs import (  # noqa
            get_deployment_docs_manager, DEPLOYMENT_PLATFORMS,
            HARDWARE_REQUIREMENTS, CONFIG_CATEGORIES,
        )
        from ux_docs_deep.api_docs import (  # noqa
            get_api_docs_manager, AUTH_METHODS, ERROR_CODE_TABLE, SDK_REGISTRY,
        )
        from ux_docs_deep.frontend_ux import (  # noqa
            get_frontend_ux_manager, DESIGN_TOKENS, ACCESSIBILITY_RULES, I18N_LANGUAGES,
        )
        from ux_docs_deep.onboarding_tutorials import (  # noqa
            get_onboarding_manager, GUIDE_FLOWS, VIDEO_CATEGORIES,
            LAB_ENVIRONMENTS, LEARNING_PATHS,
        )
        from ux_docs_deep.docs_management import get_docs_manager, DOC_CATEGORIES, ROLES  # noqa
        from ux_docs_deep.ux_docs_dashboard import (  # noqa
            get_ux_docs_dashboard, SYSTEM_SETTINGS,
        )
        _MOD_AVAILABLE = True
        logger.info("ux_docs_deep_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("ux_docs_deep_routes: fallback load failed: %s", e2)


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
        return fail("UX Docs Deep 模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ManualArticleReq(BaseModel):
    section: str
    chapter: str = ""
    title: str
    content: str = ""
    author: str = "doc-bot"
    tags: List[str] = Field(default_factory=list)


class ManualArticleUpdateReq(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    author: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None


class DeploymentDocReq(BaseModel):
    category: str
    title: str
    content: str = ""
    platform: str = "all"
    owner: str = "devops"


class DeploymentRecordReq(BaseModel):
    env: str
    platform: str
    version: str
    operator: str
    result: str = "success"
    notes: str = ""


class ApiEndpointReq(BaseModel):
    method: str
    path: str
    summary: str
    category: str
    description: str = ""
    params: List[Dict[str, Any]] = Field(default_factory=list)
    response: Dict[str, Any] = Field(default_factory=dict)
    auth_required: bool = True


class TokenReq(BaseModel):
    client: str
    scope: str = "read"
    ttl_hours: int = 24


class ChangeReq(BaseModel):
    version: str
    change_type: str
    endpoint: str
    description: str


class UXImprovementReq(BaseModel):
    area: str
    title: str
    description: str = ""
    priority: str = "P2"
    owner: str = "ux-team"


class UXImprovementUpdateReq(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    owner: Optional[str] = None
    status: Optional[str] = None


class PerfRecordReq(BaseModel):
    page: str
    fcp: float = 0.0
    lcp: float = 0.0
    fid: float = 0.0
    cls: float = 0.0
    ttfb: float = 0.0
    js_kb: int = 0
    css_kb: int = 0
    image_kb: int = 0
    cache_hit: float = 0.0


class TutorialReq(BaseModel):
    title: str
    category: str
    description: str = ""
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    difficulty: str = "入门"
    estimated_min: int = 10


class VideoReq(BaseModel):
    title: str
    category: str
    duration_sec: int = 60
    description: str = ""


class TicketReq(BaseModel):
    user_id: str
    subject: str
    message: str
    priority: str = "P3"


class DocReq(BaseModel):
    title: str
    category: str
    author: str
    content: str = ""
    tags: List[str] = Field(default_factory=list)


class DocUpdateReq(BaseModel):
    content: str
    author: str
    note: str = ""


class CommentReq(BaseModel):
    user: str
    content: str


class RatingReq(BaseModel):
    score: int


class PermissionsReq(BaseModel):
    visibility: Optional[str] = None
    allow_roles: Optional[List[str]] = None
    allow_users: Optional[List[str]] = None


class SettingsReq(BaseModel):
    docs_locale: Optional[str] = None
    docs_theme: Optional[str] = None
    search_enabled: Optional[bool] = None
    feedback_enabled: Optional[bool] = None
    rating_enabled: Optional[bool] = None
    comment_enabled: Optional[bool] = None


# =========================================================================== #
# 1. 仪表盘 / 总览
# =========================================================================== #
@router.get("/health")
def health():
    """健康检查。"""
    try:
        return ok({"status": "ok", "module": "ux_docs_deep",
                   "version": "v28.4.0", "ts": time.strftime("%Y-%m-%d %H:%M:%S")})
    except Exception as e:  # pragma: no cover
        return fail(str(e), 500)


@router.get("/overview")
def overview():
    """文档与UX总览数据。"""
    g = _guard()
    if g:
        return g
    try:
        dash = get_ux_docs_dashboard()
        return ok(dash.overview())
    except Exception as e:  # pragma: no cover
        logger.exception("overview error")
        return fail(str(e), 500)


@router.get("/settings")
def get_settings():
    """获取系统设置。"""
    g = _guard()
    if g:
        return g
    try:
        dash = get_ux_docs_dashboard()
        return ok(dash.settings_view())
    except Exception as e:
        return fail(str(e), 500)


@router.put("/settings")
def update_settings(req: SettingsReq):
    """更新系统设置。"""
    g = _guard()
    if g:
        return g
    try:
        data = req.model_dump(exclude_none=True)
        SYSTEM_SETTINGS.update(data)
        return ok({"updated": True, "settings": SYSTEM_SETTINGS})
    except Exception as e:
        return fail(str(e), 500)


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    """查询异步任务状态。"""
    try:
        t = TASKS.get(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e), 500)


# =========================================================================== #
# 2. 用户手册
# =========================================================================== #
@router.get("/manual/sections")
def manual_sections():
    """手册分册列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_user_manual_manager()
        return ok(mgr.list_sections())
    except Exception as e:
        return fail(str(e), 500)


@router.get("/manual/sections/{section}/chapters")
def manual_chapters(section: str):
    """分册章节。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_user_manual_manager()
        return ok(mgr.get_chapters(section))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/manual/articles")
def manual_list_articles(section: Optional[str] = None,
                         chapter: Optional[str] = None,
                         status: Optional[str] = None,
                         keyword: Optional[str] = None):
    """文章列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_user_manual_manager()
        return ok(mgr.list_articles(section, chapter, status, keyword))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/manual/articles")
def manual_create_article(req: ManualArticleReq):
    """创建文章。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_user_manual_manager()
        art = mgr.create_article(req.section, req.chapter, req.title,
                                  req.content, req.author, req.tags)
        return ok(art)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/manual/articles/{article_id}")
def manual_get_article(article_id: str):
    """文章详情。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_user_manual_manager()
        art = mgr.get_article(article_id)
        if not art:
            return fail("文章不存在", 404)
        return ok(art)
    except Exception as e:
        return fail(str(e), 500)


@router.put("/manual/articles/{article_id}")
def manual_update_article(article_id: str, req: ManualArticleUpdateReq):
    """更新文章。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_user_manual_manager()
        art = mgr.update_article(article_id, **req.model_dump(exclude_none=True))
        if not art:
            return fail("文章不存在", 404)
        return ok(art)
    except Exception as e:
        return fail(str(e), 500)


@router.delete("/manual/articles/{article_id}")
def manual_delete_article(article_id: str):
    """删除文章。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_user_manual_manager()
        ok_del = mgr.delete_article(article_id)
        if not ok_del:
            return fail("文章不存在", 404)
        return ok({"deleted": True})
    except Exception as e:
        return fail(str(e), 500)


@router.post("/manual/articles/{article_id}/like")
def manual_like(article_id: str):
    """点赞文章。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_user_manual_manager()
        art = mgr.like_article(article_id)
        if not art:
            return fail("文章不存在", 404)
        return ok(art)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/manual/stats")
def manual_stats():
    """手册统计。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_user_manual_manager()
        return ok(mgr.stats())
    except Exception as e:
        return fail(str(e), 500)


# =========================================================================== #
# 3. 部署文档
# =========================================================================== #
@router.get("/deployment/docs")
def deploy_list_docs(category: Optional[str] = None,
                     platform: Optional[str] = None,
                     keyword: Optional[str] = None):
    """部署文档列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_deployment_docs_manager()
        return ok(mgr.list_docs(category, platform, keyword))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/deployment/docs")
def deploy_create_doc(req: DeploymentDocReq):
    """创建部署文档。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_deployment_docs_manager()
        return ok(mgr.create_doc(req.category, req.title, req.content,
                                 req.platform, req.owner))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/deployment/docs/{doc_id}")
def deploy_get_doc(doc_id: str):
    """部署文档详情。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_deployment_docs_manager()
        d = mgr.get_doc(doc_id)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.put("/deployment/docs/{doc_id}")
def deploy_update_doc(doc_id: str, req: DeploymentDocReq):
    """更新部署文档。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_deployment_docs_manager()
        d = mgr.update_doc(doc_id, **req.model_dump())
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.delete("/deployment/docs/{doc_id}")
def deploy_delete_doc(doc_id: str):
    """删除部署文档。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_deployment_docs_manager()
        if not mgr.delete_doc(doc_id):
            return fail("文档不存在", 404)
        return ok({"deleted": True})
    except Exception as e:
        return fail(str(e), 500)


@router.get("/deployment/platforms")
def deploy_platforms():
    """支持的部署平台。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(DEPLOYMENT_PLATFORMS)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/deployment/hardware")
def deploy_hardware():
    """硬件要求矩阵。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(HARDWARE_REQUIREMENTS)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/deployment/config-categories")
def deploy_config_cats():
    """配置项分类。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(CONFIG_CATEGORIES)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/deployment/records")
def deploy_record(req: DeploymentRecordReq):
    """记录一次部署。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_deployment_docs_manager()
        return ok(mgr.record_deploy(req.env, req.platform, req.version,
                                    req.operator, req.result, req.notes))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/deployment/records")
def deploy_records():
    """部署历史。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_deployment_docs_manager()
        return ok(mgr.list_deploy_records())
    except Exception as e:
        return fail(str(e), 500)


@router.get("/deployment/stats")
def deploy_stats():
    """部署文档统计。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_deployment_docs_manager()
        return ok(mgr.stats())
    except Exception as e:
        return fail(str(e), 500)


# =========================================================================== #
# 4. API 文档
# =========================================================================== #
@router.get("/api/overview")
def api_overview():
    """API 概览。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        return ok(mgr.overview())
    except Exception as e:
        return fail(str(e), 500)


@router.get("/api/endpoints")
def api_list_endpoints(category: Optional[str] = None,
                       method: Optional[str] = None,
                       include_deprecated: bool = False):
    """端点列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        return ok(mgr.list_endpoints(category, method, include_deprecated))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/api/endpoints")
def api_create_endpoint(req: ApiEndpointReq):
    """创建端点文档。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        return ok(mgr.create_endpoint(req.method, req.path, req.summary,
                                      req.category, req.description,
                                      req.params, req.response, req.auth_required))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/api/endpoints/{ep_id}")
def api_get_endpoint(ep_id: str):
    """端点详情。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        ep = mgr.get_endpoint(ep_id)
        if not ep:
            return fail("端点不存在", 404)
        return ok(ep)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/api/endpoints/{ep_id}/deprecate")
def api_deprecate_endpoint(ep_id: str, sunset_version: str = Query(...)):
    """废弃端点。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        ep = mgr.deprecate_endpoint(ep_id, sunset_version)
        if not ep:
            return fail("端点不存在", 404)
        return ok(ep)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/api/tokens")
def api_issue_token(req: TokenReq):
    """签发 Token。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        return ok(mgr.issue_token(req.client, req.scope, req.ttl_hours))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/api/tokens")
def api_list_tokens():
    """Token 列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        return ok(mgr.list_tokens())
    except Exception as e:
        return fail(str(e), 500)


@router.delete("/api/tokens/{token_id}")
def api_revoke_token(token_id: str):
    """吊销 Token。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        if not mgr.revoke_token(token_id):
            return fail("Token 不存在", 404)
        return ok({"revoked": True})
    except Exception as e:
        return fail(str(e), 500)


@router.get("/api/changes")
def api_list_changes(version: Optional[str] = None):
    """变更日志。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        return ok(mgr.list_changes(version))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/api/changes")
def api_add_change(req: ChangeReq):
    """新增变更记录。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        return ok(mgr.add_change(req.version, req.change_type,
                                 req.endpoint, req.description))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/api/stats")
def api_stats():
    """API 文档统计。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_api_docs_manager()
        return ok(mgr.stats())
    except Exception as e:
        return fail(str(e), 500)


# =========================================================================== #
# 5. 前端 UX
# =========================================================================== #
@router.get("/ux/improvements")
def ux_list_improvements(area: Optional[str] = None,
                         status: Optional[str] = None,
                         priority: Optional[str] = None):
    """UX 改进项列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_frontend_ux_manager()
        return ok(mgr.list_improvements(area, status, priority))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/ux/improvements")
def ux_create_improvement(req: UXImprovementReq):
    """创建 UX 改进项。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_frontend_ux_manager()
        return ok(mgr.create_improvement(req.area, req.title, req.description,
                                          req.priority, req.owner))
    except Exception as e:
        return fail(str(e), 500)


@router.put("/ux/improvements/{imp_id}")
def ux_update_improvement(imp_id: str, req: UXImprovementUpdateReq):
    """更新 UX 改进项。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_frontend_ux_manager()
        imp = mgr.update_improvement(imp_id, **req.model_dump(exclude_none=True))
        if not imp:
            return fail("改进项不存在", 404)
        return ok(imp)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/ux/perf")
def ux_list_perf(page: Optional[str] = None):
    """性能快照列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_frontend_ux_manager()
        return ok(mgr.list_perf(page))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/ux/perf")
def ux_record_perf(req: PerfRecordReq):
    """记录性能快照。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_frontend_ux_manager()
        return ok(mgr.record_perf(req.page, req.fcp, req.lcp, req.fid,
                                   req.cls, req.ttfb, req.js_kb,
                                   req.css_kb, req.image_kb, req.cache_hit))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/ux/design-tokens")
def ux_design_tokens():
    """设计令牌。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(DESIGN_TOKENS)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/ux/a11y-rules")
def ux_a11y_rules():
    """无障碍规则。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(ACCESSIBILITY_RULES)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/ux/languages")
def ux_languages():
    """支持的语言。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(I18N_LANGUAGES)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/ux/stats")
def ux_stats():
    """UX 统计。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_frontend_ux_manager()
        return ok(mgr.stats())
    except Exception as e:
        return fail(str(e), 500)


# =========================================================================== #
# 6. 新手引导
# =========================================================================== #
@router.get("/onboarding/flows")
def onboarding_flows():
    """引导流程定义。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(GUIDE_FLOWS)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/onboarding/tutorials")
def onboarding_list_tutorials(category: Optional[str] = None,
                              difficulty: Optional[str] = None):
    """教程列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        return ok(mgr.list_tutorials(category, difficulty))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/onboarding/tutorials")
def onboarding_create_tutorial(req: TutorialReq):
    """创建教程。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        return ok(mgr.create_tutorial(req.title, req.category, req.description,
                                       req.steps, req.difficulty,
                                       req.estimated_min))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/onboarding/tutorials/{tid}/play")
def onboarding_play_tutorial(tid: str):
    """播放教程。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        t = mgr.play_tutorial(tid)
        if not t:
            return fail("教程不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/onboarding/tutorials/{tid}/complete")
def onboarding_complete_tutorial(tid: str):
    """完成教程。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        t = mgr.complete_tutorial(tid)
        if not t:
            return fail("教程不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/onboarding/videos")
def onboarding_list_videos(category: Optional[str] = None,
                          keyword: Optional[str] = None):
    """视频列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        return ok(mgr.list_videos(category, keyword))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/onboarding/videos")
def onboarding_create_video(req: VideoReq):
    """创建视频。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        return ok(mgr.create_video(req.title, req.category,
                                   req.duration_sec, req.description))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/onboarding/videos/{vid}/play")
def onboarding_play_video(vid: str):
    """播放视频。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        v = mgr.play_video(vid)
        if not v:
            return fail("视频不存在", 404)
        return ok(v)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/onboarding/labs")
def onboarding_labs():
    """实验环境。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(LAB_ENVIRONMENTS)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/onboarding/paths")
def onboarding_paths():
    """学习路径。"""
    g = _guard()
    if g:
        return g
    try:
        return ok(LEARNING_PATHS)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/onboarding/users/{user_id}/progress")
def onboarding_user_progress(user_id: str):
    """用户学习进度。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        return ok(mgr.get_user_progress(user_id))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/onboarding/tickets")
def onboarding_create_ticket(req: TicketReq):
    """创建工单。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        return ok(mgr.create_ticket(req.user_id, req.subject,
                                    req.message, req.priority))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/onboarding/tickets")
def onboarding_list_tickets(status: Optional[str] = None):
    """工单列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        return ok(mgr.list_tickets(status))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/onboarding/stats")
def onboarding_stats():
    """新手引导统计。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_onboarding_manager()
        return ok(mgr.stats())
    except Exception as e:
        return fail(str(e), 500)


# =========================================================================== #
# 7. 文档管理系统
# =========================================================================== #
@router.get("/docs/list")
def docs_list(category: Optional[str] = None,
              status: Optional[str] = None,
              tag: Optional[str] = None,
              keyword: Optional[str] = None,
              sort: str = "updated_desc"):
    """文档列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        return ok(mgr.list_docs(category, status, tag, keyword, sort))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/docs/create")
def docs_create(req: DocReq):
    """创建文档。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        return ok(mgr.create_doc(req.title, req.category, req.author,
                                 req.content, req.tags))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/docs/{doc_id}")
def docs_get(doc_id: str):
    """文档详情。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.get_doc(doc_id)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.put("/docs/{doc_id}")
def docs_update(doc_id: str, req: DocUpdateReq):
    """更新文档（新版本）。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.update_doc(doc_id, req.content, req.author, req.note)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.delete("/docs/{doc_id}")
def docs_delete(doc_id: str):
    """删除文档。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        if not mgr.delete_doc(doc_id):
            return fail("文档不存在", 404)
        return ok({"deleted": True})
    except Exception as e:
        return fail(str(e), 500)


@router.post("/docs/{doc_id}/submit")
def docs_submit(doc_id: str):
    """提交审核。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.submit_for_review(doc_id)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/docs/{doc_id}/publish")
def docs_publish(doc_id: str):
    """发布文档。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.publish_doc(doc_id)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/docs/{doc_id}/archive")
def docs_archive(doc_id: str):
    """归档文档。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.archive_doc(doc_id)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/docs/{doc_id}/versions")
def docs_versions(doc_id: str):
    """版本列表。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        return ok(mgr.list_versions(doc_id))
    except Exception as e:
        return fail(str(e), 500)


@router.post("/docs/{doc_id}/rollback")
def docs_rollback(doc_id: str, version: str = Query(...)):
    """回滚版本。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.rollback_version(doc_id, version)
        if not d:
            return fail("版本不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/docs/{doc_id}/like")
def docs_like(doc_id: str):
    """点赞。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.like_doc(doc_id)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/docs/{doc_id}/favorite")
def docs_favorite(doc_id: str):
    """收藏。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.favorite_doc(doc_id)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/docs/{doc_id}/rate")
def docs_rate(doc_id: str, req: RatingReq):
    """评分。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.rate_doc(doc_id, req.score)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.post("/docs/{doc_id}/comment")
def docs_comment(doc_id: str, req: CommentReq):
    """评论。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.comment_doc(doc_id, req.user, req.content)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.put("/docs/{doc_id}/permissions")
def docs_permissions(doc_id: str, req: PermissionsReq):
    """设置权限。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        d = mgr.set_permissions(doc_id, req.visibility,
                                req.allow_roles, req.allow_users)
        if not d:
            return fail("文档不存在", 404)
        return ok(d)
    except Exception as e:
        return fail(str(e), 500)


@router.get("/docs/search")
def docs_search(q: str = Query(...)):
    """全文搜索。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        return ok(mgr.search(q))
    except Exception as e:
        return fail(str(e), 500)


@router.get("/docs/analytics")
def docs_analytics():
    """文档分析。"""
    g = _guard()
    if g:
        return g
    try:
        mgr = get_docs_manager()
        return ok(mgr.analytics())
    except Exception as e:
        return fail(str(e), 500)
