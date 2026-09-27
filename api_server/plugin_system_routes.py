# -*- coding: utf-8 -*-
"""
plugin_system_routes.py - 插件系统 API 路由

路由前缀：/api/v1/plugins
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 兜底。
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 确保项目根目录可导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugin_system.plugin_manager import get_manager, PLUGIN_TYPES, PERMISSIONS  # noqa: E402
from plugin_system.plugin_marketplace import get_marketplace, CATEGORIES  # noqa: E402
from plugin_system.plugin_sdk import get_sdk  # noqa: E402
from plugin_system.plugin_security import get_auditor  # noqa: E402
from plugin_system.plugin_runtime import get_runtime  # noqa: E402

router = APIRouter(prefix="/api/v1/plugins", tags=["插件系统"])


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _err(msg: str) -> JSONResponse:
    return JSONResponse({"success": False, "data": None, "error": msg})


# ============ 插件管理 ============
@router.get("/list")
def list_plugins(type: Optional[str] = Query(None), enabled_only: bool = Query(False)):
    try:
        mgr = get_manager()
        return _ok({"items": mgr.list_plugins(type, enabled_only), "types": PLUGIN_TYPES, "stats": mgr.stats()})
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/{plugin_id}/detail")
def plugin_detail(plugin_id: str):
    try:
        d = get_manager().get_detail(plugin_id)
        if not d:
            return _err("插件不存在")
        return _ok(d)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/{plugin_id}/install")
def plugin_install(plugin_id: str, metadata: Dict[str, Any] = Body(default={})):
    try:
        metadata.setdefault("id", plugin_id)
        res = get_manager().install(metadata)
        if not res.get("ok"):
            return _err(res.get("error", "安装失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/{plugin_id}/uninstall")
def plugin_uninstall(plugin_id: str):
    try:
        res = get_manager().uninstall(plugin_id)
        if not res.get("ok"):
            return _err(res.get("error", "卸载失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/{plugin_id}/enable")
def plugin_enable(plugin_id: str):
    try:
        res = get_manager().enable(plugin_id)
        if not res.get("ok"):
            return _err(res.get("error", "启用失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/{plugin_id}/disable")
def plugin_disable(plugin_id: str):
    try:
        res = get_manager().disable(plugin_id)
        if not res.get("ok"):
            return _err(res.get("error", "禁用失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/{plugin_id}/update")
def plugin_update(plugin_id: str, payload: Dict[str, Any] = Body(default={})):
    try:
        res = get_manager().update(plugin_id, payload.get("new_version", "1.0.1"),
                                    payload.get("metadata"))
        if not res.get("ok"):
            return _err(res.get("error", "更新失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/{plugin_id}/rollback")
def plugin_rollback(plugin_id: str, payload: Dict[str, Any] = Body(default={})):
    try:
        res = get_manager().rollback(plugin_id, payload.get("version"))
        if not res.get("ok"):
            return _err(res.get("error", "回滚失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/{plugin_id}/config")
def plugin_get_config(plugin_id: str):
    try:
        return _ok(get_manager().get_config(plugin_id))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.put("/{plugin_id}/config")
def plugin_put_config(plugin_id: str, settings: Dict[str, Any] = Body(default={})):
    try:
        res = get_manager().set_config(plugin_id, settings)
        if not res.get("ok"):
            return _err(res.get("error", "配置失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/{plugin_id}/permissions")
def plugin_get_perms(plugin_id: str):
    try:
        return _ok({"permissions": get_manager().get_permissions(plugin_id),
                    "available": PERMISSIONS})
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.put("/{plugin_id}/permissions")
def plugin_put_perms(plugin_id: str, payload: Dict[str, Any] = Body(default={})):
    try:
        granted = payload.get("granted", [])
        res = get_manager().set_permissions(plugin_id, granted, payload.get("approver", "admin"))
        if not res.get("ok"):
            return _err(res.get("error", "权限更新失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# ============ 插件市场 ============
@router.get("/marketplace/browse")
def mp_browse(category: Optional[str] = None, type: Optional[str] = None,
              tag: Optional[str] = None, q: Optional[str] = None,
              sort: str = "installs", page: int = 1, page_size: int = 20):
    try:
        return _ok(get_marketplace().browse(category, type, tag, q, sort, page, page_size))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/marketplace/search")
def mp_search(q: str = "", page: int = 1, page_size: int = 20):
    try:
        return _ok(get_marketplace().search(q, page, page_size))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/marketplace/categories")
def mp_categories():
    try:
        return _ok(CATEGORIES)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/marketplace/{plugin_id}/detail")
def mp_detail(plugin_id: str):
    try:
        d = get_marketplace().detail(plugin_id)
        if not d:
            return _err("市场插件不存在")
        return _ok(d)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/marketplace/{plugin_id}/install")
def mp_install(plugin_id: str):
    try:
        res = get_marketplace().install(plugin_id, get_manager())
        if not res.get("ok"):
            return _err(res.get("error", "安装失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/marketplace/{plugin_id}/reviews")
def mp_reviews(plugin_id: str, sort: str = "likes", page: int = 1, page_size: int = 10):
    try:
        return _ok(get_marketplace().list_reviews(plugin_id, sort, page, page_size))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/marketplace/{plugin_id}/review")
def mp_add_review(plugin_id: str, payload: Dict[str, Any] = Body(default={})):
    try:
        res = get_marketplace().add_review(
            plugin_id, payload.get("user", "anonymous"),
            int(payload.get("rating", 5)), payload.get("content", ""),
        )
        if not res.get("ok"):
            return _err(res.get("error", "评论失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/marketplace/{plugin_id}/rate")
def mp_rate(plugin_id: str, payload: Dict[str, Any] = Body(default={})):
    try:
        res = get_marketplace().rate(plugin_id, int(payload.get("rating", 5)),
                                      payload.get("reviewer", "anonymous"))
        if not res.get("ok"):
            return _err(res.get("error", "评分失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/marketplace/recommendations")
def mp_recommendations(kind: str = "hot", limit: int = 6):
    try:
        return _ok(get_marketplace().recommendations(kind, limit))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/marketplace/stats")
def mp_stats():
    try:
        return _ok(get_marketplace().stats())
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# ============ 插件开发 SDK ============
@router.get("/sdk/docs")
def sdk_docs():
    try:
        return _ok({
            "title": "插件 SDK 文档",
            "lifecycle": ["init", "start", "stop", "uninstall", "configure", "validate"],
            "interfaces": ["ScannerPlugin", "AnalyzerPlugin", "ConnectorPlugin",
                           "VisualizationPlugin", "WorkflowPlugin", "NotificationPlugin", "AIPlugin"],
        })
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/sdk/templates")
def sdk_templates():
    try:
        return _ok(get_sdk()["templates"])
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/sdk/examples")
def sdk_examples():
    try:
        return _ok(get_sdk()["examples"])
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/sdk/package")
def sdk_package(payload: Dict[str, Any] = Body(default={})):
    try:
        res = get_sdk()["packager"].package(
            payload.get("id", "my-plugin"),
            payload.get("code", ""),
            payload.get("metadata", {}),
            payload.get("format", "zip"),
        )
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/sdk/publish")
def sdk_publish(payload: Dict[str, Any] = Body(default={})):
    try:
        res = get_sdk()["publisher"].submit(
            payload.get("plugin_id", "my-plugin"),
            payload.get("version", "0.1.0"),
            payload.get("changelog", ""),
        )
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/sdk/validate")
def sdk_validate(path: str = ""):
    try:
        if not path:
            return _ok({"ok": True, "entries": [], "has_manifest": False})
        return _ok(get_sdk()["packager"].validate_package(path))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# ============ 插件安全 ============
@router.get("/security/{plugin_id}/audit")
def sec_audit(plugin_id: str):
    try:
        auditor = get_auditor()
        rep = auditor.get_report(plugin_id)
        return _ok({"report": rep, "stats": auditor.stats()})
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/security/{plugin_id}/submit")
def sec_submit(plugin_id: str, payload: Dict[str, Any] = Body(default={})):
    try:
        res = get_auditor().submit_for_review(
            plugin_id, payload.get("code", ""), payload.get("metadata", {}),
        )
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/security/{plugin_id}/report")
def sec_report(plugin_id: str):
    try:
        rep = get_auditor().get_report(plugin_id)
        if not rep:
            return _err("审核报告不存在")
        return _ok(rep)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/security/malicious")
def sec_malicious():
    try:
        return _ok(get_auditor().list_quarantined())
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/security/{plugin_id}/quarantine")
def sec_quarantine(plugin_id: str, payload: Dict[str, Any] = Body(default={})):
    try:
        res = get_auditor().quarantine_plugin(plugin_id, payload.get("reason", "人工标记"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


# ============ 插件运行时 ============
@router.get("/runtime/{plugin_id}/status")
def rt_status(plugin_id: str):
    try:
        res = get_runtime().status(plugin_id)
        if not res.get("ok"):
            return _err(res.get("error", "未加载"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/runtime/{plugin_id}/metrics")
def rt_metrics(plugin_id: str):
    try:
        return _ok(get_runtime().metrics_all().get(plugin_id, {}))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.get("/runtime/{plugin_id}/logs")
def rt_logs(plugin_id: str, level: Optional[str] = None, limit: int = 100):
    try:
        return _ok(get_runtime().get_logs(plugin_id, level, limit))
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/runtime/{plugin_id}/restart")
def rt_restart(plugin_id: str):
    try:
        res = get_runtime().restart(plugin_id)
        if not res.get("ok"):
            return _err(res.get("error", "重启失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))


@router.post("/runtime/{plugin_id}/invoke")
def rt_invoke(plugin_id: str, payload: Dict[str, Any] = Body(default={})):
    try:
        res = get_runtime().invoke(plugin_id, payload.get("method", "run"),
                                    payload.get("payload"))
        if not res.get("ok"):
            return _err(res.get("error", "调用失败"))
        return _ok(res)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))
