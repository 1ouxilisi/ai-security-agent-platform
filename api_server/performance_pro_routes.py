# -*- coding: utf-8 -*-
"""
api_server/performance_pro_routes.py — 方向6：性能大升级 REST API。

路由前缀: /api/v1/performance-pro
统一响应: {"success": bool, "data": ..., "error": ...}
覆盖：启动优化 / 响应优化 / 并发控制 / DB优化V2 / 静态资源（28+ 端点）。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/performance-pro", tags=["性能大升级"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from performance_pro.startup_optimizer import get_startup_optimizer
    from performance_pro.response_optimizer import get_response_optimizer
    from performance_pro.concurrency_controller import get_concurrency_controller
    from performance_pro.db_optimizer_v2 import get_db_optimizer_v2
    from performance_pro.static_optimizer import get_static_optimizer
    from performance_pro.perf_pro_dashboard import get_perf_pro_dashboard
    _MOD_AVAILABLE = True
    logger.info("performance_pro_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("performance_pro_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from performance_pro.startup_optimizer import get_startup_optimizer  # noqa
        from performance_pro.response_optimizer import get_response_optimizer  # noqa
        from performance_pro.concurrency_controller import get_concurrency_controller  # noqa
        from performance_pro.db_optimizer_v2 import get_db_optimizer_v2  # noqa
        from performance_pro.static_optimizer import get_static_optimizer  # noqa
        from performance_pro.perf_pro_dashboard import get_perf_pro_dashboard  # noqa
        _MOD_AVAILABLE = True
        logger.info("performance_pro_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("performance_pro_routes: fallback load failed: %s", e2)


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
        return fail("性能模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class WarmupReq(BaseModel):
    modules: list[str] = Field(default_factory=list)


class CacheReq(BaseModel):
    key: str
    value: Any = None
    ttl: float = 15.0


class LatencyReq(BaseModel):
    route: str
    ms: float


class EnqueueReq(BaseModel):
    kind: str = "task"
    work_ms: int = 5


class SqlReq(BaseModel):
    sql: str


class BatchReq(BaseModel):
    resources: list[str] = Field(default_factory=list)


# =========================================================================== #
# 1. 聚合总览（3 个端点）
# =========================================================================== #
@router.get("/overview")
def pp_overview():
    g = _guard()
    if g:
        return g
    return ok(get_perf_pro_dashboard().overview())


@router.get("/scorecard")
def pp_scorecard():
    g = _guard()
    if g:
        return g
    return ok(get_perf_pro_dashboard().scorecard())


@router.get("/all")
def pp_all():
    """一站式聚合（批量接口合并演示）。"""
    g = _guard()
    if g:
        return g
    return ok({
        "overview": get_perf_pro_dashboard().overview(),
        "scorecard": get_perf_pro_dashboard().scorecard(),
    })


# =========================================================================== #
# 2. 启动速度（5 个端点）
# =========================================================================== #
@router.get("/startup/simulate")
def startup_simulate():
    """全量 vs 懒加载 启动耗时对比。"""
    g = _guard()
    if g:
        return g
    return ok(get_perf_pro_dashboard().startup_view())


@router.get("/startup/lazy/status")
def lazy_status():
    g = _guard()
    if g:
        return g
    return ok(get_startup_optimizer().status())


@router.post("/startup/lazy/warmup")
def lazy_warmup(req: WarmupReq):
    """预热重模块。"""
    g = _guard()
    if g:
        return g
    return ok(get_startup_optimizer().warmup(req.modules or None))


@router.get("/startup/uptime")
def startup_uptime():
    g = _guard()
    if g:
        return g
    return ok({"uptime_s": get_startup_optimizer().uptime()})


# =========================================================================== #
# 3. 响应优化 / 缓存 / 分位（8 个端点）
# =========================================================================== #
@router.get("/cache/stats")
def cache_stats():
    g = _guard()
    if g:
        return g
    return ok(get_response_optimizer().cache_stats())


@router.get("/cache/get")
def cache_get(key: str):
    v = get_response_optimizer().get(key)
    return ok({"key": key, "found": v is not None, "value": v})


@router.post("/cache/set")
def cache_set(req: CacheReq):
    get_response_optimizer().set(req.key, req.value, req.ttl)
    return ok({"key": req.key, "ttl": req.ttl, "stored": True})


@router.delete("/cache/invalidate")
def cache_invalidate(key: str):
    return ok({"key": key, "invalidated": get_response_optimizer().invalidate(key)})


@router.delete("/cache/clear")
def cache_clear():
    return ok({"cleared": get_response_optimizer().clear()})


@router.get("/latency/pct")
def latency_pct():
    """当前 P50/P95/P99。"""
    g = _guard()
    if g:
        return g
    return ok(get_response_optimizer().overall_pct())


@router.post("/latency/record")
def latency_record(req: LatencyReq):
    get_response_optimizer().record(req.route, req.ms)
    return ok({"recorded": True, "route": req.route, "ms": req.ms})


@router.post("/batch/merge")
def batch_merge(req: BatchReq):
    """批量接口合并：一次取多个资源，走缓存。"""
    g = _guard()
    if g:
        return g
    items = {r: (lambda r=r: f"payload-of-{r}") for r in req.resources or ["a", "b", "c"]}
    return ok({"merged": get_response_optimizer().batch_merge(items),
               "round_trips": 1, "note": "N 个资源合并为 1 次请求"})


# =========================================================================== #
# 4. 并发控制（6 个端点）
# =========================================================================== #
@router.get("/concurrency/health")
def concurrency_health():
    g = _guard()
    if g:
        return g
    return ok(get_concurrency_controller().health())


@router.post("/concurrency/run")
def concurrency_run(work_ms: int = Query(2, ge=0, le=500)):
    """同步限流执行一个轻任务。"""
    g = _guard()
    if g:
        return g
    try:
        t0 = time.time()
        get_concurrency_controller().run(lambda: time.sleep(work_ms / 1000.0))
        return ok({"ran": True, "took_ms": round((time.time() - t0) * 1000, 1),
                    "health": get_concurrency_controller().health()})
    except Exception as e:
        return fail(str(e), 429)


@router.post("/concurrency/enqueue")
def concurrency_enqueue(req: EnqueueReq):
    """异步入队耗时操作。"""
    g = _guard()
    if g:
        return g

    def work():
        time.sleep(req.work_ms / 1000.0)
        return {"work_ms": req.work_ms, "done_at": time.strftime("%H:%M:%S")}
    tid = get_concurrency_controller().enqueue(work, kind=req.kind,
                                                 meta={"work_ms": req.work_ms})
    return ok({"task_id": tid, "status": "queued", "kind": req.kind})


@router.get("/concurrency/tasks")
def concurrency_tasks(limit: int = Query(20, ge=1, le=100)):
    g = _guard()
    if g:
        return g
    return ok({"items": get_concurrency_controller().list_tasks(limit)})


@router.get("/concurrency/tasks/{task_id}")
def concurrency_task(task_id: str):
    rec = get_concurrency_controller().get(task_id)
    if not rec:
        return fail("任务不存在", 404)
    return ok(rec)


@router.get("/concurrency/stress")
def concurrency_stress(n: int = Query(100, ge=1, le=500)):
    """压测：一次性提交 n 个任务，验证不崩。"""
    g = _guard()
    if g:
        return g
    return ok(get_concurrency_controller().stress(n))


# =========================================================================== #
# 5. DB 优化 V2（5 个端点）
# =========================================================================== #
@router.get("/db/schema")
def db_schema():
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer_v2().schema())


@router.get("/db/indexes")
def db_indexes():
    g = _guard()
    if g:
        return g
    return ok({"recommended": get_db_optimizer_v2().recommend_indexes()})


@router.post("/db/explain")
def db_explain(req: SqlReq):
    """模拟 EXPLAIN。"""
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer_v2().analyze_query(req.sql))


@router.get("/db/cache-demo")
def db_cache_demo():
    g = _guard()
    if g:
        return g
    return ok({"first": get_db_optimizer_v2().cache_layer_demo(),
               "second": get_db_optimizer_v2().cache_layer_demo()})


@router.get("/db/stats")
def db_stats():
    g = _guard()
    if g:
        return g
    return ok(get_db_optimizer_v2().stats())


# =========================================================================== #
# 6. 静态资源优化（3 个端点）
# =========================================================================== #
@router.get("/static/summary")
def static_summary():
    g = _guard()
    if g:
        return g
    return ok(get_static_optimizer().summary())


@router.get("/static/headers")
def static_headers():
    g = _guard()
    if g:
        return g
    return ok({"recommended_headers": get_static_optimizer().headers()})


@router.get("/static/assets")
def static_assets():
    g = _guard()
    if g:
        return g
    return ok({"items": get_static_optimizer().assets()})
