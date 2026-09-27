# -*- coding: utf-8 -*-
"""
frontend_v2_routes.py — 前端交互深度提升 REST API（第16轮升级方向2）。

路由前缀: /api/v1/task-console
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；数据全部内存字典模拟。
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from api_server.frontend_v2 import (
    task_panel, interactive_report, data_crud,
    notification_center, frontend_optimizer, navigation_layout,
)
from api_server.frontend_v2.common import _clean

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/task-console", tags=["前端交互深度提升"])


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class SubmitTaskReq(BaseModel):
    scenario: str
    target: str
    params: Dict[str, Any] = Field(default_factory=dict)


class CommentReq(BaseModel):
    author: str = "analyst"
    content: str


class StatusReq(BaseModel):
    status: str


class BatchStatusReq(BaseModel):
    vuln_ids: List[str] = Field(default_factory=list)
    status: str


class BatchIdsReq(BaseModel):
    ids: List[str] = Field(default_factory=list)


class PatchReq(BaseModel):
    field: str
    value: Any


class CreateReq(BaseModel):
    data: Dict[str, Any] = Field(default_factory=dict)


class ImportReq(BaseModel):
    content: str = ""
    fmt: str = "json"


class NotifyReq(BaseModel):
    type: str
    title: str
    body: str = ""


class MetricReq(BaseModel):
    page: str
    load_ms: float = 0.0
    api_ms: float = 0.0
    error: bool = False


class ThemeReq(BaseModel):
    patch: Dict[str, Any] = Field(default_factory=dict)


# =========================================================================== #
# 1. 任务执行面板（10 个端点）
# =========================================================================== #
@router.get("/scenarios")
def scenarios():
    try:
        return ok(task_panel.list_scenarios())
    except Exception as e:  # noqa: BLE001
        logger.exception("scenarios")
        return fail(f"获取场景模板失败: {e}")


@router.post("/tasks")
def submit_task(req: SubmitTaskReq):
    try:
        t = task_panel.submit_task(req.scenario, req.target, req.params)
        return ok(t)
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("submit_task")
        return fail(f"提交任务失败: {e}")


@router.get("/tasks")
def list_tasks(page: int = 1, page_size: int = 20, status: str = "",
               scenario: str = "", q: str = "",
               sort_by: str = "created_at", sort_dir: str = "desc"):
    try:
        return ok(task_panel.list_tasks(page, page_size, status, scenario,
                                         q, sort_by, sort_dir))
    except Exception as e:  # noqa: BLE001
        logger.exception("list_tasks")
        return fail(f"任务列表失败: {e}")


@router.get("/tasks/{task_id}")
def task_detail(task_id: str):
    try:
        t = task_panel.get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:  # noqa: BLE001
        logger.exception("task_detail")
        return fail(f"任务详情失败: {e}")


@router.get("/tasks/{task_id}/summary")
def task_summary(task_id: str):
    try:
        s = task_panel.task_summary(task_id)
        if not s:
            return fail("任务不存在", 404)
        return ok(s)
    except Exception as e:  # noqa: BLE001
        logger.exception("task_summary")
        return fail(f"任务摘要失败: {e}")


@router.post("/tasks/{task_id}/retry")
def retry_task(task_id: str):
    try:
        t = task_panel.retry_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:  # noqa: BLE001
        logger.exception("retry_task")
        return fail(f"重试任务失败: {e}")


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: str):
    try:
        t = task_panel.cancel_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:  # noqa: BLE001
        logger.exception("cancel_task")
        return fail(f"取消任务失败: {e}")


@router.delete("/tasks/{task_id}")
def delete_task(task_id: str):
    try:
        if not task_panel.delete_task(task_id):
            return fail("任务不存在", 404)
        return ok({"deleted": task_id})
    except Exception as e:  # noqa: BLE001
        logger.exception("delete_task")
        return fail(f"删除任务失败: {e}")


@router.get("/tasks/{task_id}/export")
def export_task(task_id: str, fmt: str = "json"):
    try:
        r = task_panel.export_task_report(task_id, fmt)
        if not r:
            return fail("任务不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        logger.exception("export_task")
        return fail(f"导出失败: {e}")


@router.get("/tasks/{task_id}/share")
def share_task(task_id: str):
    try:
        r = task_panel.share_task_report(task_id)
        if not r:
            return fail("任务不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        logger.exception("share_task")
        return fail(f"生成分享链接失败: {e}")


# =========================================================================== #
# 2. 交互式报告查看器（9 个端点）
# =========================================================================== #
@router.get("/reports")
def list_reports(page: int = 1, page_size: int = 20, q: str = "",
                 sort_by: str = "created_at", sort_dir: str = "desc"):
    try:
        return ok(interactive_report.list_reports(page, page_size, q,
                                                  sort_by, sort_dir))
    except Exception as e:  # noqa: BLE001
        logger.exception("list_reports")
        return fail(f"报告列表失败: {e}")


@router.get("/reports/{report_id}")
def report_detail(report_id: str):
    try:
        r = interactive_report.get_report(report_id)
        if not r:
            return fail("报告不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        logger.exception("report_detail")
        return fail(f"报告详情失败: {e}")


@router.get("/reports/{report_id}/vulns")
def report_vulns(report_id: str, severity: str = "", status: str = "",
                 vtype: str = "", q: str = "", page: int = 1,
                 page_size: int = 20, sort_by: str = "cvss",
                 sort_dir: str = "desc"):
    try:
        return ok(interactive_report.list_vulns(report_id, severity, status,
                                                 vtype, q, page, page_size,
                                                 sort_by, sort_dir))
    except Exception as e:  # noqa: BLE001
        logger.exception("report_vulns")
        return fail(f"漏洞列表失败: {e}")


@router.get("/reports/{report_id}/vulns/{vuln_id}")
def vuln_detail(report_id: str, vuln_id: str):
    try:
        v = interactive_report.get_vuln(report_id, vuln_id)
        if not v:
            return fail("漏洞不存在", 404)
        return ok(v)
    except Exception as e:  # noqa: BLE001
        logger.exception("vuln_detail")
        return fail(f"漏洞详情失败: {e}")


@router.patch("/reports/{report_id}/vulns/{vuln_id}/status")
def vuln_status(report_id: str, vuln_id: str, req: StatusReq):
    try:
        v = interactive_report.update_vuln_status(report_id, vuln_id, req.status)
        if not v:
            return fail("漏洞不存在", 404)
        return ok(v)
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("vuln_status")
        return fail(f"更新状态失败: {e}")


@router.get("/reports/{report_id}/vulns/{vuln_id}/comments")
def vuln_comments(report_id: str, vuln_id: str):
    try:
        return ok(interactive_report.list_comments(report_id, vuln_id))
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("vuln_comments")
        return fail(f"评论列表失败: {e}")


@router.post("/reports/{report_id}/vulns/{vuln_id}/comments")
def vuln_comment_add(report_id: str, vuln_id: str, req: CommentReq):
    try:
        c = interactive_report.add_comment(report_id, vuln_id, req.author,
                                            req.content)
        return ok(c)
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("vuln_comment_add")
        return fail(f"添加评论失败: {e}")


@router.delete("/reports/{report_id}/vulns/{vuln_id}/comments/{comment_id}")
def vuln_comment_del(report_id: str, vuln_id: str, comment_id: str):
    try:
        ok_ = interactive_report.delete_comment(report_id, vuln_id, comment_id)
        return ok({"deleted": ok_})
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("vuln_comment_del")
        return fail(f"删除评论失败: {e}")


@router.post("/reports/{report_id}/vulns/batch")
def vuln_batch(report_id: str, req: BatchStatusReq):
    try:
        return ok(interactive_report.batch_update_status(report_id,
                                                         req.vuln_ids, req.status))
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("vuln_batch")
        return fail(f"批量操作失败: {e}")


@router.get("/reports/{report_id}/export")
def report_export(report_id: str, fmt: str = "html"):
    try:
        r = interactive_report.export_report(report_id, fmt)
        if not r:
            return fail("报告不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        logger.exception("report_export")
        return fail(f"导出报告失败: {e}")


# =========================================================================== #
# 3. 数据管理 CRUD（10 个端点）
# =========================================================================== #
@router.get("/crud/{entity}")
def crud_list(entity: str, page: int = 1, page_size: int = 20, q: str = "",
              status: str = "", severity: str = "", category: str = "",
              sort_by: str = "created_at", sort_dir: str = "desc"):
    try:
        filters = {"status": status, "severity": severity, "category": category}
        return ok(data_crud.list_items(entity, page, page_size, q, filters,
                                        sort_by, sort_dir))
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("crud_list")
        return fail(f"列表失败: {e}")


@router.post("/crud/{entity}")
def crud_create(entity: str, req: CreateReq):
    try:
        return ok(data_crud.create_item(entity, req.data))
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("crud_create")
        return fail(f"创建失败: {e}")


@router.get("/crud/{entity}/{item_id}")
def crud_detail(entity: str, item_id: str):
    try:
        it = data_crud.get_item(entity, item_id)
        if not it:
            return fail("记录不存在", 404)
        return ok(it)
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("crud_detail")
        return fail(f"详情失败: {e}")


@router.put("/crud/{entity}/{item_id}")
def crud_update(entity: str, item_id: str, req: CreateReq):
    try:
        it = data_crud.update_item(entity, item_id, req.data)
        if not it:
            return fail("记录不存在", 404)
        return ok(it)
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("crud_update")
        return fail(f"更新失败: {e}")


@router.patch("/crud/{entity}/{item_id}/field")
def crud_patch(entity: str, item_id: str, req: PatchReq):
    try:
        it = data_crud.patch_field(entity, item_id, req.field, req.value)
        if not it:
            return fail("记录不存在", 404)
        return ok(it)
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("crud_patch")
        return fail(f"字段更新失败: {e}")


@router.delete("/crud/{entity}/{item_id}")
def crud_delete(entity: str, item_id: str):
    try:
        if not data_crud.delete_item(entity, item_id):
            return fail("记录不存在", 404)
        return ok({"deleted": item_id})
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("crud_delete")
        return fail(f"删除失败: {e}")


@router.post("/crud/{entity}/batch-delete")
def crud_batch_delete(entity: str, req: BatchIdsReq):
    try:
        return ok(data_crud.batch_delete(entity, req.ids))
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("crud_batch_delete")
        return fail(f"批量删除失败: {e}")


@router.post("/crud/{entity}/batch-update")
def crud_batch_update(entity: str, req: Dict[str, Any] = Body(...)):
    try:
        ids = req.get("ids", [])
        patch = req.get("patch", {})
        return ok(data_crud.batch_update(entity, ids, patch))
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("crud_batch_update")
        return fail(f"批量更新失败: {e}")


@router.get("/crud/{entity}/export")
def crud_export(entity: str, fmt: str = "json"):
    try:
        return ok(data_crud.export_data(entity, fmt))
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("crud_export")
        return fail(f"导出失败: {e}")


@router.post("/crud/{entity}/import")
def crud_import(entity: str, req: ImportReq):
    try:
        return ok(data_crud.import_data(entity, req.content, req.fmt))
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("crud_import")
        return fail(f"导入失败: {e}")


# =========================================================================== #
# 4. 通知与活动流（8 个端点）
# =========================================================================== #
@router.get("/notifications")
def ntf_list(ntype: str = "", unread_only: bool = False,
             page: int = 1, page_size: int = 20):
    try:
        return ok(notification_center.list_notifications(ntype, unread_only,
                                                         page, page_size))
    except Exception as e:  # noqa: BLE001
        logger.exception("ntf_list")
        return fail(f"通知列表失败: {e}")


@router.post("/notifications")
def ntf_create(req: NotifyReq):
    try:
        return ok(notification_center.create_notification(req.type, req.title,
                                                          req.body))
    except ValueError as e:
        return fail(str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("ntf_create")
        return fail(f"创建通知失败: {e}")


@router.post("/notifications/{nid}/read")
def ntf_read(nid: str):
    try:
        n = notification_center.mark_read(nid)
        if not n:
            return fail("通知不存在", 404)
        return ok(n)
    except Exception as e:  # noqa: BLE001
        logger.exception("ntf_read")
        return fail(f"标记已读失败: {e}")


@router.post("/notifications/read-all")
def ntf_read_all():
    try:
        return ok({"marked": notification_center.mark_all_read()})
    except Exception as e:  # noqa: BLE001
        logger.exception("ntf_read_all")
        return fail(f"全部已读失败: {e}")


@router.delete("/notifications/{nid}")
def ntf_delete(nid: str):
    try:
        if not notification_center.delete_notification(nid):
            return fail("通知不存在", 404)
        return ok({"deleted": nid})
    except Exception as e:  # noqa: BLE001
        logger.exception("ntf_delete")
        return fail(f"删除通知失败: {e}")


@router.post("/notifications/clear")
def ntf_clear():
    try:
        return ok({"cleared": notification_center.clear_all()})
    except Exception as e:  # noqa: BLE001
        logger.exception("ntf_clear")
        return fail(f"清空通知失败: {e}")


@router.get("/notifications/unread-count")
def ntf_unread():
    try:
        return ok(notification_center.unread_count())
    except Exception as e:  # noqa: BLE001
        logger.exception("ntf_unread")
        return fail(f"未读统计失败: {e}")


@router.get("/activity")
def activity(kind: str = "", limit: int = 50):
    try:
        return ok(notification_center.list_activity(kind, limit))
    except Exception as e:  # noqa: BLE001
        logger.exception("activity")
        return fail(f"活动流失败: {e}")


@router.get("/notification-settings")
def ntf_settings():
    try:
        return ok(notification_center.get_settings())
    except Exception as e:  # noqa: BLE001
        logger.exception("ntf_settings")
        return fail(f"获取设置失败: {e}")


@router.put("/notification-settings")
def ntf_settings_update(req: Dict[str, Any] = Body(...)):
    try:
        return ok(notification_center.update_settings(req))
    except Exception as e:  # noqa: BLE001
        logger.exception("ntf_settings_update")
        return fail(f"更新设置失败: {e}")


# =========================================================================== #
# 5. 性能与体验（7 个端点）
# =========================================================================== #
@router.get("/perf/summary")
def perf_summary():
    try:
        return ok(frontend_optimizer.perf_summary())
    except Exception as e:  # noqa: BLE001
        logger.exception("perf_summary")
        return fail(f"性能汇总失败: {e}")


@router.post("/perf/metrics")
def perf_report(req: MetricReq):
    try:
        return ok(frontend_optimizer.report_metric(req.page, req.load_ms,
                                                    req.api_ms, req.error))
    except Exception as e:  # noqa: BLE001
        logger.exception("perf_report")
        return fail(f"上报指标失败: {e}")


@router.get("/perf/skeleton")
def perf_skeleton(module: str = "tasks"):
    try:
        return ok(frontend_optimizer.skeleton(module))
    except Exception as e:  # noqa: BLE001
        logger.exception("perf_skeleton")
        return fail(f"骨架屏失败: {e}")


@router.get("/perf/virtual-list")
def perf_virtual(offset: int = 0, limit: int = 50):
    try:
        return ok(frontend_optimizer.virtual_list(offset, limit))
    except Exception as e:  # noqa: BLE001
        logger.exception("perf_virtual")
        return fail(f"虚拟滚动数据失败: {e}")


@router.get("/perf/cache")
def perf_cache():
    try:
        return ok(frontend_optimizer.cache_stats())
    except Exception as e:  # noqa: BLE001
        logger.exception("perf_cache")
        return fail(f"缓存统计失败: {e}")


@router.post("/perf/cache/invalidate")
def perf_cache_invalidate(key: str = ""):
    try:
        return ok(frontend_optimizer.cache_invalidate(key))
    except Exception as e:  # noqa: BLE001
        logger.exception("perf_cache_invalidate")
        return fail(f"缓存失效失败: {e}")


@router.post("/perf/cache/warmup")
def perf_cache_warmup():
    try:
        return ok(frontend_optimizer.cache_warmup())
    except Exception as e:  # noqa: BLE001
        logger.exception("perf_cache_warmup")
        return fail(f"缓存预热失败: {e}")


@router.get("/search/suggest")
def search_suggest(q: str = "", limit: int = 10):
    try:
        return ok(frontend_optimizer.search_suggest(q, limit))
    except Exception as e:  # noqa: BLE001
        logger.exception("search_suggest")
        return fail(f"搜索建议失败: {e}")


# =========================================================================== #
# 6. 导航与布局（7 个端点）
# =========================================================================== #
@router.get("/nav/menu")
def nav_menu():
    try:
        return ok(navigation_layout.get_menu())
    except Exception as e:  # noqa: BLE001
        logger.exception("nav_menu")
        return fail(f"菜单获取失败: {e}")


@router.get("/nav/breadcrumbs")
def nav_breadcrumbs(path: str = ""):
    try:
        return ok(navigation_layout.breadcrumbs(path))
    except Exception as e:  # noqa: BLE001
        logger.exception("nav_breadcrumbs")
        return fail(f"面包屑失败: {e}")


@router.get("/global-search")
def global_search(q: str = "", limit: int = 10):
    try:
        return ok(navigation_layout.global_search(q, limit))
    except Exception as e:  # noqa: BLE001
        logger.exception("global_search")
        return fail(f"全局搜索失败: {e}")


@router.get("/theme")
def get_theme():
    try:
        return ok(navigation_layout.get_theme())
    except Exception as e:  # noqa: BLE001
        logger.exception("get_theme")
        return fail(f"主题获取失败: {e}")


@router.put("/theme")
def set_theme(req: ThemeReq):
    try:
        return ok(navigation_layout.update_theme(req.patch))
    except Exception as e:  # noqa: BLE001
        logger.exception("set_theme")
        return fail(f"主题更新失败: {e}")


@router.get("/user-menu")
def user_menu():
    try:
        return ok(navigation_layout.get_user_menu())
    except Exception as e:  # noqa: BLE001
        logger.exception("user_menu")
        return fail(f"用户菜单失败: {e}")


@router.get("/quick-actions")
def quick_actions():
    try:
        return ok(navigation_layout.quick_actions())
    except Exception as e:  # noqa: BLE001
        logger.exception("quick_actions")
        return fail(f"快捷操作失败: {e}")
