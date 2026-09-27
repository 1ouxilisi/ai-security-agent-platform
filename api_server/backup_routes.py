# -*- coding: utf-8 -*-
"""
backup_routes.py - 数据备份恢复 REST API（第10轮全面升级，覆盖第6轮简单版本）。

路由前缀：/api/v1/backup
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

# 认证依赖（导入失败时透传兜底，保证路由可挂载）
try:
    from api_server.auth_integration import verify_auth, require_admin  # noqa: F401
    _AUTH_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("backup_routes: 认证依赖导入失败，使用透传: %s", _e)
    _AUTH_OK = False

    async def verify_auth() -> dict:  # type: ignore
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin"}

    async def require_admin() -> dict:  # type: ignore
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin"}


router = APIRouter(prefix="/api/v1/backup", tags=["数据备份恢复"])


# ==================== 响应工具 ====================

def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": data, "error": err})


# ==================== 请求模型 ====================

class CreateBackupReq(BaseModel):
    """创建备份请求。"""
    backup_type: str = "full"
    tables: Optional[List[str]] = None
    compress: bool = True
    encrypt: bool = False
    password: Optional[str] = None
    include_configs: bool = True
    include_logs: bool = False
    description: str = ""
    backup_method: str = "online"
    compression_level: int = 6


class CreateScheduleReq(BaseModel):
    """创建备份计划请求。"""
    name: str
    schedule_type: str = "daily"
    time: str = "02:00"
    backup_type: str = "full"
    retention_days: int = 30
    retention_count: int = 10
    tables: Optional[List[str]] = None
    include_configs: bool = True
    include_logs: bool = False


class UpdateScheduleReq(BaseModel):
    """更新备份计划请求。"""
    name: Optional[str] = None
    schedule_type: Optional[str] = None
    time: Optional[str] = None
    backup_type: Optional[str] = None
    retention_days: Optional[int] = None
    retention_count: Optional[int] = None
    enabled: Optional[bool] = None
    tables: Optional[List[str]] = None


class RestoreExecuteReq(BaseModel):
    """执行恢复请求。"""
    tables: Optional[List[str]] = None
    target_db: Optional[str] = None
    password: Optional[str] = None


class MigrationReq(BaseModel):
    """迁移请求（预览/执行共用）。"""
    migration_type: str = "version_upgrade"
    source: Optional[str] = None
    target: Optional[str] = None


class CreateExportReq(BaseModel):
    """创建导出请求。"""
    tables: Optional[List[str]] = None
    query: Optional[str] = None
    format: str = "json"
    fields: Optional[List[str]] = None
    time_range: Optional[Dict[str, str]] = None
    compress: bool = False
    encrypt: bool = False
    password: Optional[str] = None
    description: str = ""


# ==================== 备份管理（10个） ====================

@router.post("/create", summary="创建备份")
async def create_backup(req: CreateBackupReq,
                        user: dict = Depends(require_admin)):
    """创建备份（full/incremental/differential），仅管理员。"""
    try:
        from backup.backup_manager import backup_manager
        return _ok(backup_manager.create_backup(
            backup_type=req.backup_type, tables=req.tables, compress=req.compress,
            encrypt=req.encrypt, password=req.password,
            include_configs=req.include_configs, include_logs=req.include_logs,
            description=req.description, backup_method=req.backup_method,
            compression_level=req.compression_level))
    except Exception as e:
        log.exception("创建备份失败: %s", e)
        return _fail(f"创建备份失败: {e}")


@router.get("/list", summary="备份列表")
async def list_backups(page: int = Query(1, ge=1),
                       page_size: int = Query(20, ge=1, le=200),
                       backup_type: Optional[str] = None,
                       user: dict = Depends(verify_auth)):
    """分页列出备份。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.list_backups(page=page, page_size=page_size,
                                        backup_type=backup_type)
        return _ok(r["data"] if r["success"] else None)
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/schedule", summary="备份计划列表")
async def list_schedules(user: dict = Depends(verify_auth)):
    """列出所有备份计划。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.list_schedules()
        return _ok(r["data"] if r["success"] else None)
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.post("/schedule", summary="创建备份计划")
async def create_schedule(req: CreateScheduleReq,
                          user: dict = Depends(require_admin)):
    """创建定时备份计划。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.create_schedule(
            name=req.name, schedule_type=req.schedule_type, time=req.time,
            backup_type=req.backup_type, retention_days=req.retention_days,
            retention_count=req.retention_count, tables=req.tables,
            include_configs=req.include_configs, include_logs=req.include_logs)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"创建计划失败: {e}")


@router.put("/schedule/{schedule_id}", summary="更新备份计划")
async def update_schedule(schedule_id: str, req: UpdateScheduleReq,
                          user: dict = Depends(require_admin)):
    """更新备份计划字段。"""
    try:
        from backup.backup_manager import backup_manager
        kwargs = req.model_dump(exclude_none=True)
        r = backup_manager.update_schedule(schedule_id, **kwargs)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"更新计划失败: {e}")


@router.post("/schedule/{schedule_id}/execute", summary="立即执行备份计划")
async def exec_schedule(schedule_id: str,
                        user: dict = Depends(require_admin)):
    """立即执行一个备份计划。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.execute_schedule(schedule_id)
        return _ok(r.get("data")) if r.get("success") else _fail(r.get("error", "执行失败"))
    except Exception as e:
        return _fail(f"执行计划失败: {e}")


@router.delete("/schedule/{schedule_id}", summary="删除备份计划")
async def delete_schedule(schedule_id: str,
                         user: dict = Depends(require_admin)):
    """删除备份计划。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.delete_schedule(schedule_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"删除计划失败: {e}")


@router.get("/schedule/{schedule_id}/history", summary="计划执行历史")
async def schedule_history(schedule_id: str,
                           user: dict = Depends(verify_auth)):
    """获取计划执行历史。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.get_schedule_history(schedule_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"查询历史失败: {e}")


@router.get("/stats", summary="备份系统统计")
async def backup_stats(user: dict = Depends(verify_auth)):
    """备份系统总览统计。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.get_stats()
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"统计失败: {e}")


@router.post("/cleanup", summary="清理过期备份")
async def cleanup_expired(retention_days: Optional[int] = 30,
                          retention_count: Optional[int] = None,
                          user: dict = Depends(require_admin)):
    """按天数/数量清理过期备份。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.cleanup_expired_backups(
            retention_days=retention_days, retention_count=retention_count)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"清理失败: {e}")


# ---- 动态路径 {backup_id} 放在最后，避免被静态路径抢占 ----

@router.get("/{backup_id}", summary="备份详情")
async def get_backup(backup_id: str, user: dict = Depends(verify_auth)):
    """获取单个备份详情。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.get_backup(backup_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.post("/{backup_id}/verify", summary="验证备份")
async def verify_backup(backup_id: str, user: dict = Depends(verify_auth)):
    """验证备份完整性。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.verify_backup(backup_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"验证失败: {e}")


@router.delete("/{backup_id}", summary="删除备份")
async def delete_backup(backup_id: str, user: dict = Depends(require_admin)):
    """删除备份。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.delete_backup(backup_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"删除失败: {e}")


@router.get("/{backup_id}/download", summary="下载备份")
async def download_backup(backup_id: str, user: dict = Depends(verify_auth)):
    """下载备份文件。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.download_backup(backup_id)
        if not r["success"]:
            return _fail(r["error"])
        info = r["data"]
        return FileResponse(path=info["path"], filename=info["name"],
                            media_type="application/octet-stream")
    except Exception as e:
        return _fail(f"下载失败: {e}")


@router.get("/{backup_id}/content", summary="备份内容预览")
async def backup_content(backup_id: str, password: Optional[str] = None,
                         user: dict = Depends(verify_auth)):
    """读取并解包备份内容（文本预览）。"""
    try:
        from backup.backup_manager import backup_manager
        r = backup_manager.get_backup_content(backup_id, password=password)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"读取失败: {e}")


# ==================== 恢复管理（5个） ====================

@router.post("/restore/{backup_id}/preview", summary="恢复预览")
async def restore_preview(backup_id: str,
                          tables: Optional[List[str]] = None,
                          user: dict = Depends(verify_auth)):
    """恢复前预览。"""
    try:
        from backup.restore_manager import restore_manager
        r = restore_manager.preview_restore(backup_id, tables=tables)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"预览失败: {e}")


@router.post("/restore/{backup_id}/execute", summary="执行恢复")
async def restore_execute(backup_id: str, req: RestoreExecuteReq,
                          user: dict = Depends(require_admin)):
    """执行恢复（自动备份当前数据）。"""
    try:
        from backup.restore_manager import restore_manager
        r = restore_manager.execute_restore(
            backup_id, tables=req.tables, target_db=req.target_db,
            password=req.password)
        return _ok(r.get("data")) if r.get("success") else _fail(r.get("error", "恢复失败"))
    except Exception as e:
        return _fail(f"恢复失败: {e}")


@router.get("/restore/{task_id}/status", summary="恢复状态")
async def restore_status(task_id: str, user: dict = Depends(verify_auth)):
    """查询恢复任务状态。"""
    try:
        from backup.restore_manager import restore_manager
        r = restore_manager.get_restore_status(task_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/restore/{task_id}/report", summary="恢复报告")
async def restore_report(task_id: str, user: dict = Depends(verify_auth)):
    """获取恢复报告。"""
    try:
        from backup.restore_manager import restore_manager
        r = restore_manager.get_restore_report(task_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.post("/restore/{task_id}/rollback", summary="回滚恢复")
async def restore_rollback(task_id: str, user: dict = Depends(require_admin)):
    """回滚恢复操作。"""
    try:
        from backup.restore_manager import restore_manager
        r = restore_manager.rollback_restore(task_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"回滚失败: {e}")


@router.get("/restore/list", summary="恢复任务列表")
async def restore_list(page: int = Query(1, ge=1),
                       page_size: int = Query(20, ge=1, le=200),
                       user: dict = Depends(verify_auth)):
    """分页列出恢复任务。"""
    try:
        from backup.restore_manager import restore_manager
        r = restore_manager.list_restores(page=page, page_size=page_size)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== 迁移管理（4个） ====================

@router.post("/migration/preview", summary="迁移预览")
async def migration_preview(req: MigrationReq, user: dict = Depends(verify_auth)):
    """迁移前预览。"""
    try:
        from backup.migration_manager import migration_manager
        r = migration_manager.preview_migration(
            req.migration_type, source=req.source, target=req.target)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"预览失败: {e}")


@router.post("/migration/execute", summary="执行迁移")
async def migration_execute(req: MigrationReq,
                            user: dict = Depends(require_admin)):
    """执行迁移。"""
    try:
        from backup.migration_manager import migration_manager
        r = migration_manager.execute_migration(
            req.migration_type, source=req.source, target=req.target)
        return _ok(r.get("data")) if r.get("success") else _fail(r.get("error", "迁移失败"))
    except Exception as e:
        return _fail(f"迁移失败: {e}")


@router.get("/migration/{task_id}/status", summary="迁移状态")
async def migration_status(task_id: str, user: dict = Depends(verify_auth)):
    """查询迁移任务状态。"""
    try:
        from backup.migration_manager import migration_manager
        r = migration_manager.get_migration_status(task_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/migration/{task_id}/report", summary="迁移报告")
async def migration_report(task_id: str, user: dict = Depends(verify_auth)):
    """获取迁移报告。"""
    try:
        from backup.migration_manager import migration_manager
        r = migration_manager.get_migration_report(task_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.post("/migration/{task_id}/rollback", summary="迁移回滚")
async def migration_rollback(task_id: str,
                             user: dict = Depends(require_admin)):
    """回滚迁移。"""
    try:
        from backup.migration_manager import migration_manager
        r = migration_manager.rollback_migration(task_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"回滚失败: {e}")


@router.get("/migration/list", summary="迁移任务列表")
async def migration_list(page: int = Query(1, ge=1),
                         page_size: int = Query(20, ge=1, le=200),
                         user: dict = Depends(verify_auth)):
    """分页列出迁移任务。"""
    try:
        from backup.migration_manager import migration_manager
        r = migration_manager.list_migrations(page=page, page_size=page_size)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


# ==================== 导出管理（4个） ====================

@router.post("/export/create", summary="创建导出")
async def export_create(req: CreateExportReq,
                        user: dict = Depends(require_admin)):
    """创建导出任务（立即执行）。"""
    try:
        from backup.export_manager import export_manager
        r = export_manager.create_export(
            tables=req.tables, query=req.query, format=req.format,
            fields=req.fields, time_range=req.time_range,
            compress=req.compress, encrypt=req.encrypt, password=req.password,
            description=req.description)
        return _ok(r.get("data")) if r.get("success") else _fail(r.get("error", "导出失败"))
    except Exception as e:
        return _fail(f"导出失败: {e}")


@router.get("/export/list", summary="导出列表")
async def export_list(page: int = Query(1, ge=1),
                      page_size: int = Query(20, ge=1, le=200),
                      user: dict = Depends(verify_auth)):
    """分页列出导出记录。"""
    try:
        from backup.export_manager import export_manager
        r = export_manager.list_exports(page=page, page_size=page_size)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"查询失败: {e}")


@router.get("/export/stats", summary="导出统计")
async def export_stats(user: dict = Depends(verify_auth)):
    """导出系统统计。"""
    try:
        from backup.export_manager import export_manager
        r = export_manager.get_stats()
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"统计失败: {e}")


@router.get("/export/{export_id}/download", summary="下载导出")
async def export_download(export_id: str,
                         user: dict = Depends(verify_auth)):
    """下载导出文件。"""
    try:
        from backup.export_manager import export_manager
        r = export_manager.download_export(export_id)
        if not r["success"]:
            return _fail(r["error"])
        info = r["data"]
        return FileResponse(path=info["path"], filename=info["name"],
                            media_type="application/octet-stream")
    except Exception as e:
        return _fail(f"下载失败: {e}")


@router.delete("/export/{export_id}", summary="删除导出")
async def export_delete(export_id: str,
                        user: dict = Depends(require_admin)):
    """删除导出记录与文件。"""
    try:
        from backup.export_manager import export_manager
        r = export_manager.delete_export(export_id)
        return _ok(r["data"]) if r["success"] else _fail(r["error"])
    except Exception as e:
        return _fail(f"删除失败: {e}")
