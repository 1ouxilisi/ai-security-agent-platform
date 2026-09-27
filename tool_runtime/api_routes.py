# -*- coding: utf-8 -*-
"""
tool_runtime/api_routes.py — 外部工具运行时与性能 REST API（36 个端点）。

路由前缀: /api/v1/system-health
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底，自动记录响应时间到 PerformanceMonitor。

设计定位：仅用于授权安全测试环境的工具链自检、降级与运维监控。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import install_guide as ig
from . import smart_fallback as sf
from . import system_health as sh
from .performance_monitor import get_monitor
from .startup_optimizer import get_optimizer
from .tool_detector import CATEGORIES, get_detector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/system-health", tags=["工具运行时与性能"])


# --------------------------------------------------------------------------- #
# 统一响应 + 自动计时
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符，防止 JSON 序列化失败。"""
    if isinstance(obj, str):
        out = []
        for ch in obj:
            o = ord(ch)
            if ch in "\n\r\t":
                out.append(ch)
            elif o < 32 or o == 127:
                continue
            else:
                out.append(ch)
        return "".join(out).encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {str(k): _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def timed(path: str):
    """记录每个端点响应时间。"""
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            t0 = time.perf_counter()
            status = 200
            try:
                resp = fn(*args, **kwargs)
                return resp
            except Exception as e:
                status = 500
                logger.exception("endpoint %s error", path)
                return fail(f"内部错误: {e}", 500)
            finally:
                ms = (time.perf_counter() - t0) * 1000
                try:
                    get_monitor().record_request(path, ms, status)
                except Exception:
                    pass
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper
    return deco


# =========================================================================== #
# 1. 工具检测（8 个端点）
# =========================================================================== #
@router.get("/tools")
@timed("/api/v1/system-health/tools")
def list_tools(category: Optional[str] = None):
    try:
        det = get_detector()
        tools = det.all_tools()
        if category:
            tools = [t for t in tools if t["category"] == category]
        return ok({"tools": tools, "count": len(tools)})
    except Exception as e:
        return fail(f"查询工具列表失败: {e}")


@router.get("/tools/summary")
@timed("/api/v1/system-health/tools/summary")
def tools_summary():
    try:
        return ok(get_detector().summary())
    except Exception as e:
        return fail(f"汇总失败: {e}")


@router.get("/tools/categories")
@timed("/api/v1/system-health/tools/categories")
def tools_categories():
    try:
        grouped = get_detector().by_category()
        return ok({"categories": CATEGORIES, "grouped": grouped})
    except Exception as e:
        return fail(f"分类查询失败: {e}")


@router.get("/tools/available")
@timed("/api/v1/system-health/tools/available")
def tools_available():
    try:
        avail = [t for t in get_detector().all_tools() if t["available"]]
        return ok({"tools": avail, "count": len(avail)})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/tools/missing")
@timed("/api/v1/system-health/tools/missing")
def tools_missing():
    try:
        missing = [t for t in get_detector().all_tools() if not t["available"]]
        return ok({"tools": missing, "count": len(missing)})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.post("/tools/refresh")
@timed("/api/v1/system-health/tools/refresh")
def tools_refresh():
    try:
        det = get_detector()
        det.detect_all(parallel=True)
        return ok({"summary": det.summary(),
                   "message": "工具检测已刷新"})
    except Exception as e:
        return fail(f"刷新失败: {e}")


@router.get("/tools/export")
@timed("/api/v1/system-health/tools/export")
def tools_export():
    try:
        det = get_detector()
        return ok({
            "summary": det.summary(),
            "tools": det.all_tools(),
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        return fail(f"导出失败: {e}")


@router.get("/tools/{name}")
@timed("/api/v1/system-health/tools/{name}")
def tool_detail(name: str):
    try:
        entry = get_detector().get(name)
        if not entry:
            return fail(f"工具 {name} 不在注册表中", 404)
        return ok(entry)
    except Exception as e:
        return fail(f"查询失败: {e}")


# =========================================================================== #
# 2. 智能降级（5 个端点）
# =========================================================================== #
@router.get("/fallback/map")
@timed("/api/v1/system-health/fallback/map")
def fallback_map():
    try:
        return ok({"mappings": sf.get_all_mappings(),
                   "count": len(sf.get_all_mappings())})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/fallback/diff/{tool}")
@timed("/api/v1/system-health/fallback/diff/{tool}")
def fallback_diff(tool: str):
    try:
        return ok(sf.get_diff(tool))
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/fallback/records")
@timed("/api/v1/system-health/fallback/records")
def fallback_records(limit: int = 100):
    try:
        return ok({"records": sf.list_records(limit),
                   "stats": sf.fallback_stats()})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.post("/fallback/record")
@timed("/api/v1/system-health/fallback/record")
def fallback_record(payload: Dict[str, Any]):
    try:
        tool = payload.get("tool", "")
        reason = payload.get("reason", "not_installed")
        context = payload.get("context", {})
        if not tool:
            return fail("tool 不能为空")
        entry = sf.record_fallback(tool, reason, context)
        return ok(entry)
    except Exception as e:
        return fail(f"记录失败: {e}")


@router.get("/fallback/performance")
@timed("/api/v1/system-health/fallback/performance")
def fallback_performance():
    try:
        return ok({"comparison": sf.performance_compare()})
    except Exception as e:
        return fail(f"查询失败: {e}")


# =========================================================================== #
# 3. 安装引导（5 个端点）
# =========================================================================== #
@router.get("/install/missing")
@timed("/api/v1/system-health/install/missing")
def install_missing():
    try:
        det = get_detector()
        missing = [t["name"] for t in det.all_tools() if not t["available"]]
        guides = ig.missing_guides(missing)
        return ok({"missing": missing, "guides": guides,
                   "count": len(missing)})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/install/guide/{tool}")
@timed("/api/v1/system-health/install/guide/{tool}")
def install_guide(tool: str):
    try:
        guide = ig.get_guide(tool)
        if not guide:
            return fail(f"未收录 {tool} 的安装指引", 404)
        return ok({"tool": tool, **guide})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.post("/install/verify/{tool}")
@timed("/api/v1/system-health/install/verify/{tool}")
def install_verify(tool: str):
    try:
        from .tool_detector import TOOL_REGISTRY
        det = get_detector()
        meta = next((m for m in TOOL_REGISTRY if m["name"] == tool), None)
        if meta is None:
            return fail(f"工具 {tool} 不在注册表", 404)
        entry = det.detect_one(meta)
        status = "available" if entry["available"] else "still_missing"
        return ok({"tool": tool, "status": status, "detail": entry})
    except Exception as e:
        return fail(f"验证失败: {e}")


@router.get("/install/faq/{tool}")
@timed("/api/v1/system-health/install/faq/{tool}")
def install_faq(tool: str):
    try:
        guide = ig.get_guide(tool)
        if not guide:
            return fail(f"未收录 {tool}", 404)
        return ok({"tool": tool, "faq": guide.get("faq", []),
                   "dependencies": guide.get("dependencies", [])})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/install/offline/{tool}")
@timed("/api/v1/system-health/install/offline/{tool}")
def install_offline(tool: str):
    try:
        guide = ig.get_guide(tool)
        if not guide:
            return fail(f"未收录 {tool}", 404)
        return ok({"tool": tool, "offline_url": guide.get("offline", ""),
                   "verify": guide.get("verify", "")})
    except Exception as e:
        return fail(f"查询失败: {e}")


# =========================================================================== #
# 4. 性能监控（7 个端点）
# =========================================================================== #
@router.get("/performance/overview")
@timed("/api/v1/system-health/performance/overview")
def perf_overview():
    try:
        return ok(get_monitor().overview())
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/performance/endpoints")
@timed("/api/v1/system-health/performance/endpoints")
def perf_endpoints():
    try:
        return ok({"endpoints": get_monitor().endpoint_stats()})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/performance/slow")
@timed("/api/v1/system-health/performance/slow")
def perf_slow(limit: int = 50):
    try:
        return ok({"slow_calls": get_monitor().slow_calls_list(limit)})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/performance/cache")
@timed("/api/v1/system-health/performance/cache")
def perf_cache():
    try:
        return ok(get_monitor().cache_stats())
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/performance/resources")
@timed("/api/v1/system-health/performance/resources")
def perf_resources():
    try:
        return ok(get_monitor().resources())
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/performance/report")
@timed("/api/v1/system-health/performance/report")
def perf_report():
    try:
        return ok(get_monitor().report())
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/performance/suggestions")
@timed("/api/v1/system-health/performance/suggestions")
def perf_suggestions():
    try:
        return ok({"suggestions": get_monitor().suggestions()})
    except Exception as e:
        return fail(f"查询失败: {e}")


# =========================================================================== #
# 5. 系统健康（6 个端点）
# =========================================================================== #
@router.get("/health/summary")
@timed("/api/v1/system-health/health/summary")
def health_summary():
    try:
        return ok(sh.full_health())
    except Exception as e:
        return fail(f"汇总失败: {e}")


@router.get("/health/service")
@timed("/api/v1/system-health/health/service")
def health_service():
    try:
        return ok(sh.service_status())
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/health/database")
@timed("/api/v1/system-health/health/database")
def health_database():
    try:
        return ok(sh.database_status())
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/health/api")
@timed("/api/v1/system-health/health/api")
def health_api():
    try:
        return ok(sh.api_health())
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/health/resources")
@timed("/api/v1/system-health/health/resources")
def health_resources():
    try:
        return ok(sh.resources_status())
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/health/anomalies")
@timed("/api/v1/system-health/health/anomalies")
def health_anomalies():
    try:
        return ok({"anomalies": sh.anomalies()})
    except Exception as e:
        return fail(f"查询失败: {e}")


# =========================================================================== #
# 6. 启动优化（5 个端点）
# =========================================================================== #
@router.get("/startup/report")
@timed("/api/v1/system-health/startup/report")
def startup_report():
    try:
        return ok(get_optimizer().report())
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/startup/timeline")
@timed("/api/v1/system-health/startup/timeline")
def startup_timeline():
    try:
        rep = get_optimizer().report()
        return ok({"stages": rep["stages"],
                   "slowest_3": rep["slowest_3"],
                   "total_duration_ms": rep["total_duration_ms"]})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.post("/startup/warmup")
@timed("/api/v1/system-health/startup/warmup")
def startup_warmup():
    try:
        rep = get_optimizer().warmup()
        get_optimizer().post_health_check()
        return ok(rep)
    except Exception as e:
        return fail(f"预热失败: {e}")


@router.get("/startup/failures")
@timed("/api/v1/system-health/startup/failures")
def startup_failures():
    try:
        rep = get_optimizer().report()
        return ok({"failed_stages": rep["failed_stages"],
                   "health_report": rep["health_report"]})
    except Exception as e:
        return fail(f"查询失败: {e}")


@router.get("/startup/progress")
@timed("/api/v1/system-health/startup/progress")
def startup_progress():
    try:
        return ok(get_optimizer().progress())
    except Exception as e:
        return fail(f"查询失败: {e}")
