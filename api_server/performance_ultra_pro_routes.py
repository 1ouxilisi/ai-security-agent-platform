# -*- coding: utf-8 -*-
"""
api_server/performance_ultra_pro_routes.py — 方向5：性能极致优化 REST API。

路由前缀: /api/v1/performance-ultra-pro
统一响应: {"success": bool, "data": ..., "error": ...}
覆盖：启动优化Pro / 响应优化Pro / 并发控制Pro / DB优化Pro /
      静态资源优化Pro / 内存优化 / 仪表盘聚合（35+ 端点）。
前端页面: GET /performance-ultra-pro/page → performance_ultra_pro_console.html
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/performance-ultra-pro", tags=["性能极致优化Pro"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from performance_ultra_pro.startup_optimizer_pro import get_startup_optimizer_pro
    from performance_ultra_pro.response_optimizer_pro import get_response_optimizer_pro
    from performance_ultra_pro.concurrency_controller_pro import get_concurrency_controller_pro
    from performance_ultra_pro.db_optimizer_pro import get_db_optimizer_pro
    from performance_ultra_pro.static_optimizer_pro import get_static_optimizer_pro
    from performance_ultra_pro.memory_optimizer import get_memory_optimizer
    from performance_ultra_pro.perf_ultra_pro_dashboard import (
        get_perf_ultra_pro_dashboard)
    _MOD_AVAILABLE = True
    logger.info("performance_ultra_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("performance_ultra_pro_routes: load failed: %s", e)
    try:
        import sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from performance_ultra_pro.startup_optimizer_pro import get_startup_optimizer_pro  # noqa
        from performance_ultra_pro.response_optimizer_pro import get_response_optimizer_pro  # noqa
        from performance_ultra_pro.concurrency_controller_pro import get_concurrency_controller_pro  # noqa
        from performance_ultra_pro.db_optimizer_pro import get_db_optimizer_pro  # noqa
        from performance_ultra_pro.static_optimizer_pro import get_static_optimizer_pro  # noqa
        from performance_ultra_pro.memory_optimizer import get_memory_optimizer  # noqa
        from performance_ultra_pro.perf_ultra_pro_dashboard import (  # noqa
            get_perf_ultra_pro_dashboard)
        _MOD_AVAILABLE = True
        logger.info("performance_ultra_pro_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("performance_ultra_pro_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
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
        return fail("性能极致模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class WarmupReq(BaseModel):
    modules: List[str] = Field(default_factory=list)


class ReportModReq(BaseModel):
    module: str
    cost_ms: float = 100.0


class LatencyReq(BaseModel):
    ms: float = 12.0


class CacheSetReq(BaseModel):
    key: str
    value: Any = None
    ttl: int = 60


class CompressReq(BaseModel):
    raw_kb: float = 100.0


class BatchReq(BaseModel):
    paths: List[str] = Field(default_factory=lambda: ["/a", "/b", "/c"])


class EnqueueReq(BaseModel):
    kind: str = "demo"
    work_ms: int = 20


class ExplainReq(BaseModel):
    sql: str = "SELECT * FROM vulns WHERE severity='high'"


class MemReportReq(BaseModel):
    delta_mb: float = 0.0


# =========================================================================== #
# 1. 仪表盘聚合（3 个端点）
# =========================================================================== #
@router.get("/overview")
def pup_overview():
    g = _guard()
    if g:
        return g
    return ok(get_perf_ultra_pro_dashboard().overview())


@router.get("/scorecard")
def pup_scorecard():
    g = _guard()
    if g:
        return g
    return ok(get_perf_ultra_pro_dashboard().scorecard())


@router.get("/all")
def pup_all():
    """批量接口合并演示。"""
    g = _guard()
    if g:
        return g
    return ok(get_perf_ultra_pro_dashboard().all_in_one())


# =========================================================================== #
# 2. 启动优化 Pro（5 个端点）
# =========================================================================== #
@router.get("/startup/compare")
def startup_compare():
    g = _guard()
    if g:
        return g
    return ok(get_startup_optimizer_pro().startup_compare())


@router.get("/startup/status")
def startup_status():
    g = _guard()
    if g:
        return g
    return ok(get_startup_optimizer_pro().status())


@router.post("/startup/warmup")
def startup_warmup(req: WarmupReq):
    g = _guard()
    if g:
        return g
    return ok(get_startup_optimizer_pro().warmup(req.modules or None))


@router.post("/startup/report")
def startup_report(req: ReportModReq):
    g = _guard()
    if g:
        return g
    return ok(get_startup_optimizer_pro().report(req.module, req.cost_ms))


@router.get("/startup/heartbeat")
def startup_heartbeat():
    g = _guard()
    if g:
        return g
    return ok(get_startup_optimizer_pro().heartbeat())


# =========================================================================== #
# 3. 响应 / 缓存 / 压缩（10 个端点）
# =========================================================================== #
@router.get("/response/latency")
def resp_latency():
    g = _guard()
    if g:
        return g
    return ok(get_response_optimizer_pro().percentiles())


@router.post("/response/latency")
def resp_record_latency(req: LatencyReq):
    g = _guard()
    if g:
        return g
    return ok(get_response_optimizer_pro().record_latency(req.ms))


@router.get("/response/cache/stats")
def resp_cache_stats():
    g = _guard()
    if g:
        return g
    return ok(get_response_optimizer_pro().cache_stats())


@router.post("/response/cache/set")
def resp_cache_set(req: CacheSetReq):
    g = _guard()
    if g:
        return g
    get_response_optimizer_pro().get_or_set(
        req.key, (lambda v=req.value: v), ttl=req.ttl)
    return ok({"set": req.key, "ttl": req.ttl})


@router.get("/response/cache/get")
def resp_cache_get(key: str = Query(...)):
    g = _guard()
    if g:
        return g
    return ok(get_response_optimizer_pro().get_or_set(key, (lambda: {"data": key})))


@router.delete("/response/cache/invalidate")
def resp_cache_invalidate(key: str = Query(...)):
    g = _guard()
    if g:
        return g
    return ok({"invalidated": get_response_optimizer_pro().invalidate(key)})


@router.delete("/response/cache/clear")
def resp_cache_clear():
    g = _guard()
    if g:
        return g
    return ok(get_response_optimizer_pro().clear())


@router.get("/response/cache/demo")
def resp_cache_demo():
    g = _guard()
    if g:
        return g
    return ok(get_response_optimizer_pro().demo())


@router.post("/response/compress")
def resp_compress(req: CompressReq):
    g = _guard()
    if g:
        return g
    return ok(get_response_optimizer_pro().compress(req.raw_kb))


@router.post("/response/batch")
def resp_batch(req: BatchReq):
    """批量接口合并。"""
    g = _guard()
    if g:
        return g
    return ok(get_response_optimizer_pro().batch_merge(req.paths))


# =========================================================================== #
# 4. 并发控制 Pro（5 个端点）
# =========================================================================== #
@router.get("/concurrency/health")
def conc_health():
    g = _guard()
    if g:
        return g
    return ok(get_concurrency_controller_pro().health())


@router.post("/concurrency/enqueue")
def conc_enqueue(req: EnqueueReq):
    g = _guard()
    if g:
        return g
    return ok(get_concurrency_controller_pro().enqueue(req.kind, req.work_ms))


@router.get("/concurrency/tasks")
def conc_tasks():
    g = _guard()
    if g:
        return g
    return ok({"items": get_concurrency_controller_pro().tasks()})


@router.post("/concurrency/stress")
def conc_stress(n: int = Query(200, description="并发数")):
    g = _guard()
    if g:
        return g
    return ok(get_concurrency_controller_pro().stress(n))


@router.post("/concurrency/complete/{task_id}")
def conc_complete(task_id: str):
    g = _guard()
    if g:
        return g
    try:
        return ok(get_concurrency_controller_pro().complete(task_id))
    except Exception as e:
        return fail(str(e), 404)


# =========================================================================== #
# 5. DB 优化 Pro（7 个端点）
# =========================================================================== #
@router.get("/db/schema")
def db_schema():
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer_pro().schema())


@router.get("/db/index-recommendations")
def db_index_rec():
    g = _guard()
    if g:
        return g
    return ok({"items": get_db_optimizer_pro().index_recommendations()})


@router.post("/db/explain")
def db_explain(req: ExplainReq):
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer_pro().explain(req.sql))


@router.get("/db/cache-layer")
def db_cache_layer():
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer_pro().cache_layer())


@router.get("/db/slow-queries")
def db_slow():
    g = _guard()
    if g:
        return g
    return ok({"items": get_db_optimizer_pro().slow_queries()})


@router.get("/db/pool")
def db_pool():
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer_pro().connection_pool())


@router.get("/db/stats")
def db_stats():
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer_pro().stats())


# =========================================================================== #
# 6. 静态资源优化（3 个端点）
# =========================================================================== #
@router.get("/static/report")
def static_report():
    g = _guard()
    if g:
        return g
    return ok(get_static_optimizer_pro().report())


@router.get("/static/policy")
def static_policy():
    g = _guard()
    if g:
        return g
    return ok(get_static_optimizer_pro().policy())


@router.get("/static/preload")
def static_preload():
    g = _guard()
    if g:
        return g
    return ok({"preload_hints": get_static_optimizer_pro().preload()})


# =========================================================================== #
# 7. 内存优化（5 个端点）
# =========================================================================== #
@router.get("/memory/summary")
def mem_summary():
    g = _guard()
    if g:
        return g
    return ok(get_memory_optimizer().summary())


@router.post("/memory/report")
def mem_report(req: MemReportReq):
    g = _guard()
    if g:
        return g
    return ok(get_memory_optimizer().report(req.delta_mb))


@router.post("/memory/gc")
def mem_gc(generation: int = Query(2, ge=0, le=2)):
    g = _guard()
    if g:
        return g
    return ok(get_memory_optimizer().gc_now(generation))


@router.get("/memory/leak-scan")
def mem_leak():
    g = _guard()
    if g:
        return g
    return ok(get_memory_optimizer().leak_scan())


@router.get("/memory/trend")
def mem_trend():
    g = _guard()
    if g:
        return g
    return ok({"items": get_memory_optimizer().trend()})


# =========================================================================== #
# 8. 前端页面路由（自包含）
# =========================================================================== #
@router.get("/page", include_in_schema=False)
def performance_ultra_pro_page():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "performance_ultra_pro_console.html")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>性能极致控制台页面未找到</h1>")
