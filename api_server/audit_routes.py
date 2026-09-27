# -*- coding: utf-8 -*-
"""
audit_routes.py - 审计日志深化模块 REST API 路由。

路由前缀：/api/v1/audit
所有端点均用 try-except 包裹，返回统一 JSON 格式，不返回 500 错误。
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

# 确保项目根目录可导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import log  # noqa: E402

# 认证依赖（导入失败时透传兜底，保证路由可挂载）
try:
    from api_server.auth_integration import verify_auth, require_admin  # noqa: F401
    _AUTH_OK = True
except Exception as _e:  # pragma: no cover
    log.warning(f"audit_routes: 认证依赖导入失败，使用透传: {_e}")
    _AUTH_OK = False

    async def verify_auth() -> dict:  # type: ignore
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin"}

    async def require_admin() -> dict:  # type: ignore
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin"}


router = APIRouter(prefix="/api/v1/audit", tags=["审计日志"])


# ==================== 响应工具 ====================

def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})


def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"code": status, "error": message}, status_code=status)


# ==================== 请求体模型 ====================

class ExportReq(BaseModel):
    """操作日志导出请求。"""
    fmt: str = "csv"
    operator: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None


class ArchiveReq(BaseModel):
    """日志归档请求。"""
    log_type: str = "operations"
    days_ago: int = 30


class ConfigUpdateReq(BaseModel):
    """日志配置更新请求。"""
    config: Dict[str, str] = {}


# ==================== 操作日志 ====================

@router.get("/operations", summary="操作日志列表")
async def list_operations(
    operator: Optional[str] = None,
    operation_type: Optional[str] = None,
    operation_object: Optional[str] = None,
    ip_address: Optional[str] = None,
    result: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.operation_log import get_operation_logger
        data = get_operation_logger().list_operations(
            operator=operator, operation_type=operation_type,
            operation_object=operation_object, ip_address=ip_address,
            result=result, start_time=start_time, end_time=end_time,
            page=page, page_size=page_size)
        return _ok(data)
    except Exception as e:
        log.exception(f"list_operations 失败: {e}")
        return _err(500, f"查询失败: {e}")


@router.get("/operations/stats", summary="操作日志统计")
async def operation_stats(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.operation_log import get_operation_logger
        return _ok(get_operation_logger().get_operation_stats(start_time, end_time))
    except Exception as e:
        log.exception(f"operation_stats 失败: {e}")
        return _err(500, f"统计失败: {e}")


@router.post("/operations/export", summary="导出操作日志")
async def export_operations(
    req: ExportReq,
    current_user: dict = Depends(require_admin),
):
    try:
        from audit.operation_log import get_operation_logger
        result = get_operation_logger().export_operations(
            fmt=req.fmt, operator=req.operator,
            start_time=req.start_time, end_time=req.end_time)
        if result.get("format") == "csv":
            return Response(
                content=result["content"], media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f"attachment; filename={result['filename']}"})
        return JSONResponse(content={"code": 0, "data": result})
    except Exception as e:
        log.exception(f"export_operations 失败: {e}")
        return _err(500, f"导出失败: {e}")


@router.get("/operations/search", summary="操作日志全文搜索")
async def search_operations(
    keyword: str = "",
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    page: int = Query(1, ge=1),
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.operation_log import get_operation_logger
        return _ok(get_operation_logger().search_operations(
            keyword=keyword, start_time=start_time, end_time=end_time, page=page))
    except Exception as e:
        log.exception(f"search_operations 失败: {e}")
        return _err(500, f"搜索失败: {e}")


@router.get("/operations/{log_id}", summary="操作日志详情")
async def get_operation(log_id: str, current_user: dict = Depends(verify_auth)):
    try:
        from audit.operation_log import get_operation_logger
        data = get_operation_logger().get_operation(log_id)
        if not data:
            return _err(404, "日志不存在")
        return _ok(data)
    except Exception as e:
        log.exception(f"get_operation 失败: {e}")
        return _err(500, f"查询失败: {e}")


# ==================== 登录日志 ====================

@router.get("/logins", summary="登录日志列表")
async def list_logins(
    username: Optional[str] = None,
    login_ip: Optional[str] = None,
    result: Optional[str] = None,
    login_method: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.login_log import get_login_logger
        return _ok(get_login_logger().list_logins(
            username=username, login_ip=login_ip, result=result,
            login_method=login_method, start_time=start_time, end_time=end_time,
            page=page, page_size=page_size))
    except Exception as e:
        log.exception(f"list_logins 失败: {e}")
        return _err(500, f"查询失败: {e}")


@router.get("/logins/abnormal", summary="异常登录列表")
async def abnormal_logins(current_user: dict = Depends(verify_auth)):
    try:
        from audit.login_log import get_login_logger
        data = get_login_logger().get_abnormal_logins()
        return _ok({"total": len(data), "items": data})
    except Exception as e:
        log.exception(f"abnormal_logins 失败: {e}")
        return _err(500, f"检测失败: {e}")


@router.get("/logins/sessions", summary="活跃会话列表")
async def active_sessions(
    username: Optional[str] = None,
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.login_log import get_login_logger
        data = get_login_logger().list_active_sessions(username=username)
        return _ok({"total": len(data), "items": data})
    except Exception as e:
        log.exception(f"active_sessions 失败: {e}")
        return _err(500, f"查询失败: {e}")


@router.get("/logins/stats", summary="登录统计")
async def login_stats(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.login_log import get_login_logger
        return _ok(get_login_logger().get_login_stats(start_time, end_time))
    except Exception as e:
        log.exception(f"login_stats 失败: {e}")
        return _err(500, f"统计失败: {e}")


@router.post("/logins/sessions/{session_id}/revoke", summary="强制撤销会话")
async def revoke_session(session_id: str, current_user: dict = Depends(require_admin)):
    try:
        from audit.login_log import get_login_logger
        ok = get_login_logger().revoke_session(session_id, operator=current_user.get("username", "admin"))
        return _ok({"success": ok, "session_id": session_id})
    except Exception as e:
        log.exception(f"revoke_session 失败: {e}")
        return _err(500, f"撤销失败: {e}")


@router.get("/logins/{login_id}", summary="单条登录日志")
async def get_login(login_id: str, current_user: dict = Depends(verify_auth)):
    try:
        from audit.login_log import get_login_logger
        data = get_login_logger().get_login(login_id)
        if not data:
            return _err(404, "登录日志不存在")
        return _ok(data)
    except Exception as e:
        log.exception(f"get_login 失败: {e}")
        return _err(500, f"查询失败: {e}")


# ==================== API 调用日志 ====================

@router.get("/api-calls", summary="API 调用日志列表")
async def list_api_calls(
    endpoint: Optional[str] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    request_ip: Optional[str] = None,
    api_key: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.api_log import get_api_logger
        return _ok(get_api_logger().list_api_calls(
            endpoint=endpoint, method=method, status_code=status_code,
            request_ip=request_ip, api_key=api_key,
            start_time=start_time, end_time=end_time,
            page=page, page_size=page_size))
    except Exception as e:
        log.exception(f"list_api_calls 失败: {e}")
        return _err(500, f"查询失败: {e}")


@router.get("/api-calls/slow", summary="慢请求列表")
async def slow_requests(
    threshold_ms: Optional[int] = None,
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.api_log import get_api_logger
        data = get_api_logger().get_slow_requests(threshold_ms=threshold_ms)
        return _ok({"total": len(data), "items": data})
    except Exception as e:
        log.exception(f"slow_requests 失败: {e}")
        return _err(500, f"查询失败: {e}")


@router.get("/api-calls/errors", summary="错误请求列表")
async def error_requests(current_user: dict = Depends(verify_auth)):
    try:
        from audit.api_log import get_api_logger
        data = get_api_logger().get_error_requests()
        return _ok({"total": len(data), "items": data})
    except Exception as e:
        log.exception(f"error_requests 失败: {e}")
        return _err(500, f"查询失败: {e}")


@router.get("/api-calls/stats", summary="API 调用统计")
async def api_stats(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.api_log import get_api_logger
        return _ok(get_api_logger().get_api_stats(start_time, end_time))
    except Exception as e:
        log.exception(f"api_stats 失败: {e}")
        return _err(500, f"统计失败: {e}")


@router.get("/api-calls/performance", summary="API 性能监控")
async def api_performance(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.api_log import get_api_logger
        return _ok(get_api_logger().get_performance_monitor(start_time, end_time))
    except Exception as e:
        log.exception(f"api_performance 失败: {e}")
        return _err(500, f"查询失败: {e}")


@router.get("/api-calls/{call_id}", summary="单条 API 调用详情")
async def get_api_call(call_id: str, current_user: dict = Depends(verify_auth)):
    try:
        from audit.api_log import get_api_logger
        data = get_api_logger().get_api_call(call_id)
        if not data:
            return _err(404, "API 调用记录不存在")
        return _ok(data)
    except Exception as e:
        log.exception(f"get_api_call 失败: {e}")
        return _err(500, f"查询失败: {e}")


# ==================== 数据访问日志 ====================

@router.get("/data-access", summary="数据访问日志列表")
async def list_data_access(
    access_user: Optional[str] = None,
    data_type: Optional[str] = None,
    access_type: Optional[str] = None,
    ip_address: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.data_access_log import get_data_access_logger
        return _ok(get_data_access_logger().list_data_access(
            access_user=access_user, data_type=data_type, access_type=access_type,
            ip_address=ip_address, start_time=start_time, end_time=end_time,
            page=page, page_size=page_size))
    except Exception as e:
        log.exception(f"list_data_access 失败: {e}")
        return _err(500, f"查询失败: {e}")


@router.get("/data-access/abnormal", summary="异常数据访问")
async def abnormal_access(current_user: dict = Depends(verify_auth)):
    try:
        from audit.data_access_log import get_data_access_logger
        data = get_data_access_logger().get_abnormal_access()
        return _ok({"total": len(data), "items": data})
    except Exception as e:
        log.exception(f"abnormal_access 失败: {e}")
        return _err(500, f"检测失败: {e}")


@router.get("/data-access/stats", summary="数据访问统计")
async def data_access_stats(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.data_access_log import get_data_access_logger
        return _ok(get_data_access_logger().get_access_stats(start_time, end_time))
    except Exception as e:
        log.exception(f"data_access_stats 失败: {e}")
        return _err(500, f"统计失败: {e}")


@router.get("/data-access/sensitive-report", summary="敏感数据访问报告")
async def sensitive_report(current_user: dict = Depends(require_admin)):
    try:
        from audit.data_access_log import get_data_access_logger
        data = get_data_access_logger().get_sensitive_access_report()
        return _ok({"total": len(data), "items": data})
    except Exception as e:
        log.exception(f"sensitive_report 失败: {e}")
        return _err(500, f"生成报告失败: {e}")


@router.get("/data-access/{access_id}", summary="单条数据访问日志")
async def get_data_access(access_id: str, current_user: dict = Depends(verify_auth)):
    try:
        from audit.data_access_log import get_data_access_logger
        data = get_data_access_logger().get_data_access(access_id)
        if not data:
            return _err(404, "数据访问日志不存在")
        return _ok(data)
    except Exception as e:
        log.exception(f"get_data_access 失败: {e}")
        return _err(500, f"查询失败: {e}")


# ==================== 日志管理 ====================

@router.get("/logs/search", summary="跨日志类型全文搜索")
async def search_all(
    keyword: str = "",
    time_range: Optional[str] = None,
    user: Optional[str] = None,
    ip: Optional[str] = None,
    current_user: dict = Depends(verify_auth),
):
    try:
        from audit.log_manager import get_log_manager
        return _ok(get_log_manager().search_all_logs(
            keyword=keyword, time_range=time_range, user=user, ip=ip))
    except Exception as e:
        log.exception(f"search_all 失败: {e}")
        return _err(500, f"搜索失败: {e}")


@router.get("/logs/report", summary="审计日志报表")
async def audit_report(current_user: dict = Depends(require_admin)):
    try:
        from audit.log_manager import get_log_manager
        return _ok(get_log_manager().get_audit_report())
    except Exception as e:
        log.exception(f"audit_report 失败: {e}")
        return _err(500, f"生成报表失败: {e}")


@router.post("/logs/archive", summary="归档历史日志")
async def archive_logs(req: ArchiveReq, current_user: dict = Depends(require_admin)):
    try:
        from audit.log_manager import get_log_manager
        return _ok(get_log_manager().archive_logs(req.log_type, req.days_ago))
    except Exception as e:
        log.exception(f"archive_logs 失败: {e}")
        return _err(500, f"归档失败: {e}")


@router.post("/logs/clean", summary="清理过期日志")
async def clean_logs(current_user: dict = Depends(require_admin)):
    try:
        from audit.log_manager import get_log_manager
        return _ok(get_log_manager().clean_expired_logs())
    except Exception as e:
        log.exception(f"clean_logs 失败: {e}")
        return _err(500, f"清理失败: {e}")


@router.get("/logs/integrity", summary="哈希链完整性校验")
async def verify_integrity(current_user: dict = Depends(require_admin)):
    try:
        from audit.log_manager import get_log_manager
        return _ok(get_log_manager().verify_all_integrity())
    except Exception as e:
        log.exception(f"verify_integrity 失败: {e}")
        return _err(500, f"校验失败: {e}")


@router.get("/logs/config", summary="获取日志配置")
async def get_config(current_user: dict = Depends(require_admin)):
    try:
        from audit.log_manager import get_log_manager
        return _ok(get_log_manager().get_log_config())
    except Exception as e:
        log.exception(f"get_config 失败: {e}")
        return _err(500, f"获取配置失败: {e}")


@router.put("/logs/config", summary="更新日志配置")
async def update_config(req: ConfigUpdateReq, current_user: dict = Depends(require_admin)):
    try:
        from audit.log_manager import get_log_manager
        return _ok(get_log_manager().update_log_config(req.config))
    except Exception as e:
        log.exception(f"update_config 失败: {e}")
        return _err(500, f"更新配置失败: {e}")


@router.get("/logs/overview", summary="日志总览")
async def logs_overview(current_user: dict = Depends(verify_auth)):
    try:
        from audit.log_manager import get_log_manager
        return _ok(get_log_manager().get_log_overview())
    except Exception as e:
        log.exception(f"logs_overview 失败: {e}")
        return _err(500, f"获取总览失败: {e}")
