# -*- coding: utf-8 -*-
"""
api_gateway_routes.py - API 网关深化模块 REST API 路由。

路由前缀：/api/v1/api-gateway
统一 JSON 响应格式：{"success": bool, "data": ..., "error": ...}
所有端点均用 try-except 包裹，不返回 500 错误。
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 确保项目根目录可导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from api_gateway import (
        rate_limiter,
        circuit_breaker,
        degradation_manager,
        api_cache,
        api_logger,
        api_monitor,
    )
    _GW_OK = True
except Exception as _e:  # pragma: no cover
    _GW_OK = False
    _IMPORT_ERR = str(_e)
    # 兜底空对象，保证路由可挂载
    class _Dummy:  # type: ignore
        def __getattr__(self, name):
            def _noop(*a, **kw):
                return {}
            return _noop
    rate_limiter = circuit_breaker = degradation_manager = api_cache = _Dummy()  # type: ignore
    api_logger = api_monitor = _Dummy()  # type: ignore


router = APIRouter(prefix="/api/v1/api-gateway", tags=["API网关"])


# ==================== 响应工具 ====================

def _ok(data: Any = None) -> JSONResponse:
    """成功响应。"""
    return JSONResponse({"success": True, "data": data, "error": None})


def _fail(message: str, status: int = 400) -> JSONResponse:
    """失败响应（不抛 500）。"""
    return JSONResponse({"success": False, "data": None, "error": message},
                        status_code=status)


# ==================== 请求体模型 ====================

class RateLimitConfigReq(BaseModel):
    """限流配置更新请求。"""
    endpoint: Optional[str] = None
    dimension: str = "ip"
    requests_per_minute: int = 60
    burst: int = 10


class WhitelistReq(BaseModel):
    """白名单添加请求。"""
    identifier: str
    dimension: str = "ip"


class CBConfigReq(BaseModel):
    """熔断配置更新请求。"""
    endpoint: Optional[str] = None
    failure_rate_threshold: Optional[float] = None
    time_window: Optional[int] = None
    open_timeout: Optional[int] = None
    half_open_requests: Optional[int] = None
    min_requests: Optional[int] = None


class DegradationConfigReq(BaseModel):
    """降级配置更新请求。"""
    endpoint: str
    strategy: str = "default"
    data: Optional[Any] = None
    reason: str = "manual"
    action: str = "enable"  # enable / disable


class CacheWarmupReq(BaseModel):
    """缓存预热请求。"""
    endpoints: Optional[list] = None


class LogExportReq(BaseModel):
    """日志导出请求。"""
    format: str = "json"
    filters: Optional[Dict[str, Any]] = None


# ==================== 限流（4） ====================

@router.get("/rate-limit/config", summary="限流配置列表")
async def list_rate_limit_config():
    """获取限流默认策略与已配置策略。"""
    try:
        data = {
            "default_policy": rate_limiter.get_policy(None, "ip"),
            "stats_summary": rate_limiter.get_stats(),
        }
        return _ok(data)
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取限流配置失败: {e}")


@router.put("/rate-limit/config", summary="更新限流配置")
async def update_rate_limit_config(req: RateLimitConfigReq):
    """更新指定维度/端点的限流策略。"""
    try:
        result = rate_limiter.set_policy(
            endpoint=req.endpoint,
            dimension=req.dimension,
            requests_per_minute=req.requests_per_minute,
            burst=req.burst,
        )
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        return _fail(f"更新限流配置失败: {e}")


@router.get("/rate-limit/stats", summary="限流统计")
async def rate_limit_stats():
    """获取限流统计与被限流分布。"""
    try:
        return _ok(rate_limiter.get_stats())
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取限流统计失败: {e}")


@router.post("/rate-limit/whitelist", summary="添加限流白名单")
async def add_whitelist(req: WhitelistReq):
    """添加限流白名单（IP/用户/Key 等）。"""
    try:
        rate_limiter.add_whitelist(req.identifier, req.dimension)
        return _ok({"whitelist": rate_limiter.get_whitelist()})
    except Exception as e:  # noqa: BLE001
        return _fail(f"添加白名单失败: {e}")


# ==================== 熔断（5） ====================

@router.get("/circuit-breaker/status", summary="熔断状态列表")
async def circuit_breaker_status():
    """获取所有端点熔断状态。"""
    try:
        return _ok(circuit_breaker.get_all_states())
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取熔断状态失败: {e}")


@router.get("/circuit-breaker/config", summary="熔断配置")
async def circuit_breaker_config(endpoint: Optional[str] = None):
    """获取熔断配置。"""
    try:
        return _ok(circuit_breaker.get_config(endpoint))
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取熔断配置失败: {e}")


@router.put("/circuit-breaker/config", summary="更新熔断配置")
async def update_circuit_breaker_config(req: CBConfigReq):
    """更新熔断配置（支持端点级覆盖）。"""
    try:
        cfg: Dict[str, Any] = {}
        for k in ("failure_rate_threshold", "time_window", "open_timeout",
                  "half_open_requests", "min_requests"):
            v = getattr(req, k)
            if v is not None:
                cfg[k] = v
        result = circuit_breaker.set_config(req.endpoint, **cfg)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        return _fail(f"更新熔断配置失败: {e}")


@router.post("/circuit-breaker/{endpoint}/reset", summary="重置熔断")
async def reset_circuit_breaker(endpoint: str):
    """手动重置指定端点的熔断器。"""
    try:
        circuit_breaker.reset(endpoint)
        return _ok({"endpoint": endpoint, "reset": True})
    except Exception as e:  # noqa: BLE001
        return _fail(f"重置熔断失败: {e}")


@router.get("/circuit-breaker/stats", summary="熔断统计")
async def circuit_breaker_stats():
    """获取熔断统计汇总。"""
    try:
        return _ok(circuit_breaker.get_stats())
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取熔断统计失败: {e}")


# ==================== 降级（3） ====================

@router.get("/degradation/config", summary="降级配置列表")
async def degradation_config():
    """获取降级配置与当前降级端点。"""
    try:
        return _ok({
            "config": degradation_manager.get_config(),
            "degraded_endpoints": degradation_manager.get_degraded_endpoints(),
        })
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取降级配置失败: {e}")


@router.put("/degradation/config", summary="更新降级配置")
async def update_degradation_config(req: DegradationConfigReq):
    """启用/禁用端点降级。"""
    try:
        if req.action == "disable":
            ok = degradation_manager.disable_degradation(req.endpoint)
            return _ok({"endpoint": req.endpoint, "disabled": ok})
        result = degradation_manager.enable_degradation(
            req.endpoint, strategy=req.strategy,
            data=req.data, reason=req.reason)
        return _ok(result)
    except Exception as e:  # noqa: BLE001
        return _fail(f"更新降级配置失败: {e}")


@router.get("/degradation/stats", summary="降级统计")
async def degradation_stats():
    """获取降级统计。"""
    try:
        return _ok(degradation_manager.get_stats())
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取降级统计失败: {e}")


# ==================== 缓存（4） ====================

@router.get("/cache/status", summary="缓存状态")
async def cache_status():
    """获取缓存状态（大小/命中率）。"""
    try:
        return _ok({
            "cache_items": api_cache.get_cache_size(),
            "hit_rate": api_cache.get_hit_rate(),
        })
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取缓存状态失败: {e}")


@router.get("/cache/stats", summary="缓存统计")
async def cache_stats():
    """获取缓存详细统计。"""
    try:
        return _ok(api_cache.get_stats())
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取缓存统计失败: {e}")


@router.post("/cache/clear", summary="清除缓存")
async def clear_cache():
    """清空全部缓存。"""
    try:
        removed = api_cache.clear()
        return _ok({"cleared": removed})
    except Exception as e:  # noqa: BLE001
        return _fail(f"清除缓存失败: {e}")


@router.post("/cache/warmup", summary="预热缓存")
async def warmup_cache(req: CacheWarmupReq):
    """预热热点 API 缓存。"""
    try:
        return _ok(api_cache.warmup(req.endpoints))
    except Exception as e:  # noqa: BLE001
        return _fail(f"预热缓存失败: {e}")


# ==================== 日志（3） ====================

@router.get("/logs", summary="日志列表")
async def list_logs(
    endpoint: Optional[str] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    client_ip: Optional[str] = None,
    user_id: Optional[str] = None,
    request_id: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """分页查询 API 日志（支持多条件过滤）。"""
    try:
        filters: Dict[str, Any] = {}
        if endpoint:
            filters["endpoint"] = endpoint
        if method:
            filters["method"] = method
        if status_code is not None:
            filters["status_code"] = status_code
        if client_ip:
            filters["client_ip"] = client_ip
        if user_id:
            filters["user_id"] = user_id
        if request_id:
            filters["request_id"] = request_id
        return _ok(api_logger.get_logs(filters=filters, page=page,
                                        page_size=page_size))
    except Exception as e:  # noqa: BLE001
        return _fail(f"查询日志失败: {e}")


@router.get("/logs/stats", summary="日志统计")
async def logs_stats(time_range: str = "1h"):
    """获取日志统计（错误端点/慢请求排名）。"""
    try:
        return _ok(api_logger.get_stats(time_range=time_range))
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取日志统计失败: {e}")


@router.post("/logs/export", summary="导出日志")
async def export_logs(req: LogExportReq):
    """导出日志为 JSON/CSV 文件。"""
    try:
        return _ok(api_logger.export_logs(fmt=req.format, filters=req.filters))
    except Exception as e:  # noqa: BLE001
        return _fail(f"导出日志失败: {e}")


# ==================== 监控（5） ====================

@router.get("/monitor/endpoints", summary="监控端点列表")
async def monitor_endpoints():
    """获取所有被监控的端点。"""
    try:
        return _ok({"endpoints": api_monitor.get_all_endpoints()})
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取监控端点失败: {e}")


@router.get("/monitor/trends", summary="性能趋势")
async def monitor_trends(time_range: str = "1h"):
    """获取性能趋势。"""
    try:
        return _ok(api_monitor.get_trends(time_range=time_range))
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取性能趋势失败: {e}")


@router.get("/monitor/alerts", summary="告警列表")
async def monitor_alerts(active_only: bool = True):
    """获取告警列表。"""
    try:
        return _ok(api_monitor.get_alerts(active_only=active_only))
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取告警失败: {e}")


@router.get("/monitor/report", summary="监控报告")
async def monitor_report(time_range: str = "24h"):
    """生成 API 监控报告。"""
    try:
        return _ok(api_monitor.generate_report(time_range=time_range))
    except Exception as e:  # noqa: BLE001
        return _fail(f"生成监控报告失败: {e}")


@router.get("/monitor/{endpoint}/stats", summary="端点统计")
async def monitor_endpoint_stats(endpoint: str):
    """获取指定端点的性能/错误/可用性统计。"""
    try:
        return _ok(api_monitor.get_endpoint_stats(endpoint))
    except Exception as e:  # noqa: BLE001
        return _fail(f"获取端点统计失败: {e}")
