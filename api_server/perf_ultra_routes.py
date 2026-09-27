# -*- coding: utf-8 -*-
"""
api_server/perf_ultra_routes.py — 方向4：性能极致优化 REST API。

路由前缀: /api/v1/perf-ultra
统一响应: {"success": bool, "data": ..., "error": ...}
覆盖：启动优化 / 响应缓存 / 异步队列 / DB优化 / 性能监控 / 静态资源。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/perf-ultra", tags=["性能极致优化"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from performance_ultra.lazy_loader import get_lazy_loader
    from performance_ultra.response_cache import get_response_cache
    from performance_ultra.async_queue import get_async_queue
    from performance_ultra.db_optimizer import get_db_optimizer
    from performance_ultra.perf_monitor import get_perf_monitor
    from performance_ultra.perf_dashboard import get_perf_dashboard, STATIC_OPTIMIZATION
    _MOD_AVAILABLE = True
    logger.info("perf_ultra_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("perf_ultra_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from performance_ultra.lazy_loader import get_lazy_loader  # noqa
        from performance_ultra.response_cache import get_response_cache  # noqa
        from performance_ultra.async_queue import get_async_queue  # noqa
        from performance_ultra.db_optimizer import get_db_optimizer  # noqa
        from performance_ultra.perf_monitor import get_perf_monitor  # noqa
        from performance_ultra.perf_dashboard import get_perf_dashboard, STATIC_OPTIMIZATION  # noqa
        _MOD_AVAILABLE = True
        logger.info("perf_ultra_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("perf_ultra_routes: fallback load failed: %s", e2)


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
        return fail("性能优化模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class WarmupReq(BaseModel):
    modules: list[str] = Field(default_factory=list)


class CacheReq(BaseModel):
    key: str
    value: Any = None
    ttl: float = 30.0


class QueryReq(BaseModel):
    sql: str


class LatencyReq(BaseModel):
    route: str
    ms: float
    is_error: bool = False
    cache_hit: bool = False


class EnqueueReq(BaseModel):
    kind: str = "task"
    work_ms: int = 50   # 模拟耗时


# =========================================================================== #
# 1. 总览 / 打分卡（3 个端点）
# =========================================================================== #
@router.get("/overview")
def perf_overview():
    """性能总览：启动/分位/并发/缓存/DB/静态。"""
    g = _guard()
    if g:
        return g
    return ok(get_perf_dashboard().overview())


@router.get("/scorecard")
def perf_scorecard():
    """五项优化打分卡。"""
    g = _guard()
    if g:
        return g
    return ok(get_perf_dashboard().scorecard())


@router.get("/health")
def perf_health():
    """快速健康探针。"""
    g = _guard()
    if g:
        return g
    return ok({"status": "ok", "ts": time.strftime("%H:%M:%S")})


# =========================================================================== #
# 2. 启动速度 / 懒加载（5 个端点）
# =========================================================================== #
@router.get("/startup")
def startup_info():
    g = _guard()
    if g:
        return g
    return ok(get_perf_dashboard().startup())


@router.get("/lazy/status")
def lazy_status():
    g = _guard()
    if g:
        return g
    return ok(get_lazy_loader().status())


@router.post("/lazy/warmup")
def lazy_warmup(req: WarmupReq):
    """预热：显式加载指定重模块。"""
    g = _guard()
    if g:
        return g
    return ok(get_lazy_loader().warmup(req.modules or None))


@router.get("/lazy/simulate")
def lazy_simulate():
    """模拟全量 vs 懒加载启动耗时对比。"""
    g = _guard()
    if g:
        return g
    return ok(get_lazy_loader().simulate_startup())


@router.post("/startup/mark")
def mark_startup(ms: float = Query(8200)):
    """记录本次启动耗时。"""
    g = _guard()
    if g:
        return g
    get_perf_monitor().mark_startup(ms)
    return ok({"startup_ms": ms, "target": "<10000", "met": ms < 10000})


# =========================================================================== #
# 3. 响应缓存（6 个端点）
# =========================================================================== #
@router.get("/cache/stats")
def cache_stats():
    g = _guard()
    if g:
        return g
    return ok(get_response_cache().stats())


@router.get("/cache/get")
def cache_get(key: str):
    c = get_response_cache()
    v = c.get(key)
    return ok({"key": key, "found": v is not None, "value": v})


@router.post("/cache/set")
def cache_set(req: CacheReq):
    get_response_cache().set(req.key, req.value, req.ttl)
    return ok({"key": req.key, "ttl": req.ttl, "stored": True})


@router.delete("/cache/invalidate")
def cache_invalidate(key: str):
    hit = get_response_cache().invalidate(key)
    return ok({"key": key, "invalidated": hit})


@router.delete("/cache/clear")
def cache_clear():
    n = get_response_cache().clear()
    return ok({"cleared": n})


@router.get("/cache/demo")
def cache_demo():
    """演示相同请求命中缓存（第二次应命中）。"""
    c = get_response_cache()
    key = "demo:overview"
    v1, hit1 = c.get_or_set(key, lambda: {"data": "expensive", "ts": time.time()})
    v2, hit2 = c.get_or_set(key, lambda: {"data": "expensive", "ts": time.time()})
    return ok({"first_call_cache_hit": hit1, "second_call_cache_hit": hit2,
               "proof": "第二次直接返回缓存，命中"})


# =========================================================================== #
# 4. 异步队列 / 并发（5 个端点）
# =========================================================================== #
@router.get("/queue/health")
def queue_health():
    g = _guard()
    if g:
        return g
    return ok(get_async_queue().health())


@router.post("/queue/enqueue")
def queue_enqueue(req: EnqueueReq):
    """把一个耗时操作扔进队列异步执行。"""
    g = _guard()
    if g:
        return g
    def work():
        time.sleep(req.work_ms / 1000.0)
        return {"work_ms": req.work_ms, "done_at": time.strftime("%H:%M:%S")}
    tid = get_async_queue().enqueue(work, kind=req.kind, meta={"work_ms": req.work_ms})
    return ok({"task_id": tid, "status": "queued", "kind": req.kind})


@router.get("/queue/tasks")
def queue_tasks(limit: int = Query(20, ge=1, le=100)):
    g = _guard()
    if g:
        return g
    return ok(get_async_queue().list_tasks(limit))


@router.get("/queue/tasks/{tid}")
def queue_task_detail(tid: str):
    rec = get_async_queue().get(tid)
    if not rec:
        return fail("任务不存在", 404)
    return ok(rec)


@router.get("/queue/stress")
def queue_stress(n: int = Query(50, ge=1, le=200)):
    """并发压测：一次性 enqueue n 个轻任务，验证不崩。"""
    g = _guard()
    if g:
        return g
    q = get_async_queue()
    ids = [q.enqueue(lambda i=i: {"idx": i}, kind="stress") for i in range(n)]
    return ok({"enqueued": n, "sample_ids": ids[:5],
               "health_after_enqueue": q.health()})


# =========================================================================== #
# 5. DB 优化（5 个端点）
# =========================================================================== #
@router.get("/db/schema")
def db_schema():
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer().schema())


@router.get("/db/index-recommendations")
def db_index_reco():
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer().recommend_indexes())


@router.post("/db/explain")
def db_explain(req: QueryReq):
    """模拟 EXPLAIN：判断 SQL 是否命中索引。"""
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer().analyze_query(req.sql))


@router.get("/db/cache-layer")
def db_cache_layer():
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer().cache_layer_demo())


@router.get("/db/stats")
def db_stats():
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer().stats())


# =========================================================================== #
# 6. 性能监控 / 静态资源（6 个端点）
# =========================================================================== #
@router.get("/monitor/summary")
def monitor_summary():
    g = _guard()
    if g:
        return g
    return ok(get_perf_monitor().summary())


@router.get("/monitor/latency")
def monitor_latency():
    g = _guard()
    if g:
        return g
    return ok(get_perf_dashboard().latency())


@router.post("/monitor/record")
def monitor_record(req: LatencyReq):
    """上报一次请求耗时。"""
    g = _guard()
    if g:
        return g
    get_perf_monitor().record(req.route, req.ms, req.is_error, req.cache_hit)
    return ok({"recorded": True, "route": req.route, "ms": req.ms})


@router.get("/monitor/slow-routes")
def monitor_slow(n: int = Query(10, ge=1, le=50)):
    g = _guard()
    if g:
        return g
    return ok(get_perf_monitor().top_slow_routes(n))


@router.get("/static")
def static_info():
    """静态资源优化：压缩 / 缓存头 / CDN。"""
    g = _guard()
    if g:
        return g
    return ok(STATIC_OPTIMIZATION)


@router.get("/all")
def all_metrics():
    """一站式聚合（批量接口合并演示）。"""
    g = _guard()
    if g:
        return g
    return ok({
        "overview": get_perf_dashboard().overview(),
        "scorecard": get_perf_dashboard().scorecard(),
        "cache": get_response_cache().stats(),
        "queue": get_async_queue().health(),
    })
