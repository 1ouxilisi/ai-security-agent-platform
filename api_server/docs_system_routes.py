# -*- coding: utf-8 -*-
"""
docs_system_routes.py — 文档体系 REST API（35 个端点）。

路由前缀: /api/v1/docs-center
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。

覆盖6大模块：
    1. 架构文档体系 (architecture)
    2. API文档中心 (api-docs)
    3. 用户手册与指南 (user-guides)
    4. 部署运维文档 (deployment)
    5. 知识库与最佳实践 (knowledge)
    6. 文档管理与运营 (management)
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/docs-center", tags=["文档体系"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from docs_system.architecture_docs import (
        get_system_overview, get_module_architecture, get_api_architecture,
        get_data_architecture, get_deployment_architecture,
    )
    from docs_system.api_docs_center import (
        get_auto_api_docs, get_interactive_debug_info, get_api_categories,
        get_api_changelog, get_api_best_practices, get_openapi_spec,
    )
    from docs_system.user_guides import (
        get_quickstart, get_feature_manuals, get_scenario_tutorials,
        get_admin_guide, get_developer_guide,
    )
    from docs_system.deployment_ops_docs import (
        get_install_guide, get_config_reference, get_ops_manual,
        get_monitoring_alerting, get_troubleshooting,
    )
    from docs_system.knowledge_base import (
        get_security_knowledge_base, get_best_practices, get_case_library,
        get_faq, get_glossary,
    )
    from docs_system.docs_management import (
        list_doc_versions, get_doc_version_detail, compare_versions,
        rollback_version, run_quality_check, search_documents,
        get_contribution_guide, get_dashboard, export_documents,
        get_export_status, list_export_formats,
    )
    _MOD_AVAILABLE = True
    logger.info("docs_system_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("docs_system_routes: load failed: %s", e)


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
# 统一响应 & 清理
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理数据中的控制字符和无效Unicode。"""
    if isinstance(obj, str):
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
    return JSONResponse(
        {"success": False, "data": None, "error": _clean(message)},
        status_code=code,
    )


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("文档体系模块不可用，请检查加载日志", 503)
    return None


# =========================================================================== #
# 模块1: 架构文档体系（6个端点）
# =========================================================================== #

@router.get("/architecture/overview")
def arch_overview():
    """系统架构总览"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_system_overview())
    except Exception as e:
        logger.exception("arch_overview error: %s", e)
        return fail(f"获取架构总览失败: {e}")


@router.get("/architecture/modules")
def arch_modules(module: Optional[str] = Query(None, description="模块名")):
    """模块架构文档列表/详情"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_module_architecture(module))
    except Exception as e:
        logger.exception("arch_modules error: %s", e)
        return fail(f"获取模块架构失败: {e}")


@router.get("/architecture/api")
def arch_api():
    """API架构设计规范"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_architecture())
    except Exception as e:
        logger.exception("arch_api error: %s", e)
        return fail(f"获取API架构失败: {e}")


@router.get("/architecture/data")
def arch_data():
    """数据架构设计"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_data_architecture())
    except Exception as e:
        logger.exception("arch_data error: %s", e)
        return fail(f"获取数据架构失败: {e}")


@router.get("/architecture/deployment")
def arch_deployment():
    """部署架构设计"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_deployment_architecture())
    except Exception as e:
        logger.exception("arch_deployment error: %s", e)
        return fail(f"获取部署架构失败: {e}")


@router.post("/architecture/scan")
def arch_scan():
    """触发项目结构扫描（异步任务）"""
    try:
        g = _guard()
        if g:
            return g
        task_id = _new_task("architecture_scan")
        # 立即执行扫描（模拟异步）
        try:
            result = get_module_architecture()
            _finish_task(task_id, result)
        except Exception as scan_err:
            _finish_task(task_id, None, str(scan_err))
        return ok({"task_id": task_id, "status": "done", "message": "架构扫描完成"})
    except Exception as e:
        logger.exception("arch_scan error: %s", e)
        return fail(f"触发架构扫描失败: {e}")


# =========================================================================== #
# 模块2: API文档中心（6个端点）
# =========================================================================== #

@router.get("/api-docs/auto")
def api_docs_auto():
    """自动API文档（扫描项目路由）"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_auto_api_docs())
    except Exception as e:
        logger.exception("api_docs_auto error: %s", e)
        return fail(f"获取自动API文档失败: {e}")


@router.get("/api-docs/openapi")
def api_docs_openapi():
    """OpenAPI 3.0规范"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_openapi_spec())
    except Exception as e:
        logger.exception("api_docs_openapi error: %s", e)
        return fail(f"获取OpenAPI规范失败: {e}")


@router.get("/api-docs/debug")
def api_docs_debug():
    """交互式API调试信息"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_interactive_debug_info())
    except Exception as e:
        logger.exception("api_docs_debug error: %s", e)
        return fail(f"获取调试信息失败: {e}")


@router.get("/api-docs/categories")
def api_docs_categories():
    """API分类与搜索"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_categories())
    except Exception as e:
        logger.exception("api_docs_categories error: %s", e)
        return fail(f"获取API分类失败: {e}")


@router.get("/api-docs/changelog")
def api_docs_changelog():
    """API变更日志"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_changelog())
    except Exception as e:
        logger.exception("api_docs_changelog error: %s", e)
        return fail(f"获取变更日志失败: {e}")


@router.get("/api-docs/best-practices")
def api_docs_best_practices():
    """API最佳实践"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_api_best_practices())
    except Exception as e:
        logger.exception("api_docs_best_practices error: %s", e)
        return fail(f"获取API最佳实践失败: {e}")


# =========================================================================== #
# 模块3: 用户手册与指南（5个端点）
# =========================================================================== #

@router.get("/user-guides/quickstart")
def guides_quickstart():
    """快速上手指南"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_quickstart())
    except Exception as e:
        logger.exception("guides_quickstart error: %s", e)
        return fail(f"获取快速上手指南失败: {e}")


@router.get("/user-guides/features")
def guides_features():
    """功能使用手册（32大安全方向）"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_feature_manuals())
    except Exception as e:
        logger.exception("guides_features error: %s", e)
        return fail(f"获取功能手册失败: {e}")


@router.get("/user-guides/scenarios")
def guides_scenarios():
    """场景化教程"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_scenario_tutorials())
    except Exception as e:
        logger.exception("guides_scenarios error: %s", e)
        return fail(f"获取场景教程失败: {e}")


@router.get("/user-guides/admin")
def guides_admin():
    """管理员指南"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_admin_guide())
    except Exception as e:
        logger.exception("guides_admin error: %s", e)
        return fail(f"获取管理员指南失败: {e}")


@router.get("/user-guides/developer")
def guides_developer():
    """开发者指南"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_developer_guide())
    except Exception as e:
        logger.exception("guides_developer error: %s", e)
        return fail(f"获取开发者指南失败: {e}")


# =========================================================================== #
# 模块4: 部署与运维文档（5个端点）
# =========================================================================== #

@router.get("/deployment/install")
def deploy_install():
    """安装部署文档"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_install_guide())
    except Exception as e:
        logger.exception("deploy_install error: %s", e)
        return fail(f"获取安装文档失败: {e}")


@router.get("/deployment/config")
def deploy_config():
    """配置参考"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_config_reference())
    except Exception as e:
        logger.exception("deploy_config error: %s", e)
        return fail(f"获取配置参考失败: {e}")


@router.get("/deployment/ops")
def deploy_ops():
    """运维操作手册"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_ops_manual())
    except Exception as e:
        logger.exception("deploy_ops error: %s", e)
        return fail(f"获取运维手册失败: {e}")


@router.get("/deployment/monitoring")
def deploy_monitoring():
    """监控与告警"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_monitoring_alerting())
    except Exception as e:
        logger.exception("deploy_monitoring error: %s", e)
        return fail(f"获取监控告警失败: {e}")


@router.get("/deployment/troubleshooting")
def deploy_troubleshooting():
    """故障排查指南"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_troubleshooting())
    except Exception as e:
        logger.exception("deploy_troubleshooting error: %s", e)
        return fail(f"获取故障排查指南失败: {e}")


# =========================================================================== #
# 模块5: 知识库与最佳实践（5个端点）
# =========================================================================== #

@router.get("/knowledge/security-base")
def kb_security_base():
    """安全知识库"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_security_knowledge_base())
    except Exception as e:
        logger.exception("kb_security_base error: %s", e)
        return fail(f"获取安全知识库失败: {e}")


@router.get("/knowledge/best-practices")
def kb_best_practices():
    """最佳实践库"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_best_practices())
    except Exception as e:
        logger.exception("kb_best_practices error: %s", e)
        return fail(f"获取最佳实践失败: {e}")


@router.get("/knowledge/cases")
def kb_cases():
    """案例库"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_case_library())
    except Exception as e:
        logger.exception("kb_cases error: %s", e)
        return fail(f"获取案例库失败: {e}")


@router.get("/knowledge/faq")
def kb_faq():
    """FAQ常见问题"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_faq())
    except Exception as e:
        logger.exception("kb_faq error: %s", e)
        return fail(f"获取FAQ失败: {e}")


@router.get("/knowledge/glossary")
def kb_glossary():
    """安全术语表"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_glossary())
    except Exception as e:
        logger.exception("kb_glossary error: %s", e)
        return fail(f"获取术语表失败: {e}")


# =========================================================================== #
# 模块6: 文档管理与运营（8个端点）
# =========================================================================== #

@router.get("/management/versions")
def mgmt_versions():
    """文档版本列表"""
    try:
        g = _guard()
        if g:
            return g
        return ok(list_doc_versions())
    except Exception as e:
        logger.exception("mgmt_versions error: %s", e)
        return fail(f"获取文档版本失败: {e}")


@router.get("/management/versions/{doc_id}")
def mgmt_version_detail(doc_id: str):
    """文档版本详情"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_doc_version_detail(doc_id))
    except Exception as e:
        logger.exception("mgmt_version_detail error: %s", e)
        return fail(f"获取文档版本详情失败: {e}")


@router.get("/management/compare")
def mgmt_compare(
    doc_id: str = Query(...),
    v1: str = Query(...),
    v2: str = Query(...),
):
    """版本对比"""
    try:
        g = _guard()
        if g:
            return g
        return ok(compare_versions(doc_id, v1, v2))
    except Exception as e:
        logger.exception("mgmt_compare error: %s", e)
        return fail(f"版本对比失败: {e}")


@router.post("/management/rollback")
def mgmt_rollback(
    doc_id: str = Query(...),
    version: str = Query(...),
):
    """文档回滚"""
    try:
        g = _guard()
        if g:
            return g
        result = rollback_version(doc_id, version)
        if result.get("success"):
            return ok(result)
        return fail(result.get("error", "回滚失败"))
    except Exception as e:
        logger.exception("mgmt_rollback error: %s", e)
        return fail(f"文档回滚失败: {e}")


@router.get("/management/quality")
def mgmt_quality(doc_id: Optional[str] = Query(None)):
    """文档质量检查"""
    try:
        g = _guard()
        if g:
            return g
        return ok(run_quality_check(doc_id))
    except Exception as e:
        logger.exception("mgmt_quality error: %s", e)
        return fail(f"质量检查失败: {e}")


@router.get("/management/search")
def mgmt_search(
    q: str = Query("", description="搜索关键词"),
    category: Optional[str] = Query(None),
):
    """文档搜索"""
    try:
        g = _guard()
        if g:
            return g
        return ok(search_documents(q, category))
    except Exception as e:
        logger.exception("mgmt_search error: %s", e)
        return fail(f"文档搜索失败: {e}")


@router.get("/management/contribute")
def mgmt_contribute():
    """文档贡献指南"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_contribution_guide())
    except Exception as e:
        logger.exception("mgmt_contribute error: %s", e)
        return fail(f"获取贡献指南失败: {e}")


@router.get("/management/dashboard")
def mgmt_dashboard():
    """文档仪表盘"""
    try:
        g = _guard()
        if g:
            return g
        return ok(get_dashboard())
    except Exception as e:
        logger.exception("mgmt_dashboard error: %s", e)
        return fail(f"获取文档仪表盘失败: {e}")


# =========================================================================== #
# 文档导出（3个端点）
# =========================================================================== #

@router.post("/management/export")
def mgmt_export(
    fmt: str = Query("markdown", description="导出格式"),
):
    """导出文档"""
    try:
        g = _guard()
        if g:
            return g
        result = export_documents(fmt)
        if result.get("success"):
            return ok(result)
        return fail(result.get("error", "导出失败"))
    except Exception as e:
        logger.exception("mgmt_export error: %s", e)
        return fail(f"文档导出失败: {e}")


@router.get("/management/export/{task_id}")
def mgmt_export_status(task_id: str):
    """查询导出任务状态"""
    try:
        g = _guard()
        if g:
            return g
        result = get_export_status(task_id)
        if result.get("success"):
            return ok(result["data"])
        return fail(result.get("error", "查询失败"))
    except Exception as e:
        logger.exception("mgmt_export_status error: %s", e)
        return fail(f"查询导出状态失败: {e}")


@router.get("/management/export-formats")
def mgmt_export_formats():
    """支持的导出格式"""
    try:
        g = _guard()
        if g:
            return g
        return ok(list_export_formats())
    except Exception as e:
        logger.exception("mgmt_export_formats error: %s", e)
        return fail(f"获取导出格式失败: {e}")


# =========================================================================== #
# 汇总统计端点（1个）
# =========================================================================== #

@router.get("/summary")
def docs_summary():
    """文档体系总览统计"""
    try:
        g = _guard()
        if g:
            return g
        return ok({
            "title": "文档体系总览",
            "modules": [
                {"name": "架构文档体系", "endpoints": 6, "path": "/architecture"},
                {"name": "API文档中心", "endpoints": 6, "path": "/api-docs"},
                {"name": "用户手册与指南", "endpoints": 5, "path": "/user-guides"},
                {"name": "部署与运维", "endpoints": 5, "path": "/deployment"},
                {"name": "知识库与最佳实践", "endpoints": 5, "path": "/knowledge"},
                {"name": "文档管理与运营", "endpoints": 11, "path": "/management"},
            ],
            "total_endpoints": 38,
            "version": "1.0.0",
        })
    except Exception as e:
        logger.exception("docs_summary error: %s", e)
        return fail(f"获取文档总览失败: {e}")
