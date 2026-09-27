# -*- coding: utf-8 -*-
"""
api_server/performance_routes.py — 性能优化 REST API（第19轮·方向1）。

路由前缀: /api/v1/performance
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底，不向调用方抛 500；任务用内存字典 TASKS 模拟异步。
依赖 performance/ 包内 6 个核心模块；第三方库缺失时由模块内部回退模拟。
"""

from __future__ import annotations

import os
import re
import sys
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# 保证项目根目录可导入 performance 包
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from performance.query_optimizer import query_optimizer            # noqa: E402
from performance.api_performance import api_performance_monitor     # noqa: E402
from performance.concurrency_optimizer import optimizer as conc     # noqa: E402
from performance.startup_memory import optimizer as mem_opt        # noqa: E402
from performance.database_performance import db_perf                # noqa: E402
from performance.performance_dashboard import dashboard             # noqa: E402

router = APIRouter(prefix="/api/v1/performance", tags=["性能优化"])


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = uuid.uuid4().hex[:16]
    TASKS[tid] = {"task_id": tid, "kind": kind, "status": "pending",
                  "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "finished_at": None, "result": None, "error": None}
    return tid


def _finish(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in TASKS:
        t = TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应 + 控制字符清理
# --------------------------------------------------------------------------- #
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理字符串中的控制字符，避免编码/渲染异常。"""
    if isinstance(obj, str):
        return _CTRL_RE.sub(" ", obj)
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


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class AnalyzeQueryIn(BaseModel):
    sql: str = ""
    db_path: Optional[str] = None


class ObserveIn(BaseModel):
    endpoint: str
    elapsed_ms: float
    method: str = "GET"
    status: int = 200


class TaskIn(BaseModel):
    name: str = "background_job"
    priority: int = 5
    count: int = 10
    steps: int = 5
    fail: bool = False


class BatchIn(BaseModel):
    total_rows: int = 1000
    kind: str = "insert"


class EventIn(BaseModel):
    topic: str = "general"
    payload: Dict[str, Any] = Field(default_factory=dict)


class LoadTestIn(BaseModel):
    url: str = "/api/v1/performance/overview"
    concurrency: int = 10
    requests: int = 100


# =========================================================================== #
# 0. 总览
# =========================================================================== #
@router.get("/overview")
def overview():
    try:
        return ok({
            "modules": ["query", "api", "concurrency", "startup_memory",
                         "database", "dashboard"],
            "realtime": dashboard.realtime()["metrics"],
            "score": dashboard.score()["overall"],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:  # noqa: BLE001
        return fail(f"总览失败: {e}", 500)


# =========================================================================== #
# 1. 查询优化（13 个端点）
# =========================================================================== #
@router.get("/query/slow")
def query_slow(limit: int = 50, min_ms: Optional[float] = None):
    try:
        return ok(query_optimizer.list_slow(limit=limit, min_ms=min_ms))
    except Exception as e:  # noqa: BLE001
        return fail(f"慢查询查询失败: {e}", 500)


@router.get("/query/top")
def query_top(limit: int = 20):
    try:
        return ok(query_optimizer.top_queries(limit=limit))
    except Exception as e:  # noqa: BLE001
        return fail(f"高频查询查询失败: {e}", 500)


@router.post("/query/analyze")
def query_analyze(req: AnalyzeQueryIn):
    try:
        task_id = _new_task("query_analyze")
        result = query_optimizer.analyze_query(req.sql, req.db_path or "")
        _finish(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(f"查询分析失败: {e}", 500)


@router.get("/query/indexes")
def query_indexes(db: Optional[str] = None):
    try:
        return ok(query_optimizer.inventory_indexes(db))
    except Exception as e:  # noqa: BLE001
        return fail(f"索引盘点失败: {e}", 500)


@router.get("/query/index-suggestions")
def query_index_suggestions(db: Optional[str] = None):
    try:
        return ok(query_optimizer.suggest_indexes(db))
    except Exception as e:  # noqa: BLE001
        return fail(f"缺失索引建议失败: {e}", 500)


@router.get("/query/redundant-indexes")
def query_redundant():
    try:
        return ok(query_optimizer.detect_redundant_indexes())
    except Exception as e:  # noqa: BLE001
        return fail(f"冗余索引检测失败: {e}", 500)


@router.get("/query/index-usage")
def query_index_usage():
    try:
        return ok(query_optimizer.index_usage())
    except Exception as e:  # noqa: BLE001
        return fail(f"索引使用率失败: {e}", 500)


@router.get("/query/create-script")
def query_create_script():
    try:
        return ok(query_optimizer.create_index_script())
    except Exception as e:  # noqa: BLE001
        return fail(f"生成索引脚本失败: {e}", 500)


@router.get("/query/cache/stats")
def query_cache_stats():
    try:
        return ok(query_optimizer.cache_stats())
    except Exception as e:  # noqa: BLE001
        return fail(f"缓存统计失败: {e}", 500)


@router.post("/query/cache/warmup")
def query_cache_warmup():
    try:
        return ok(query_optimizer.cache_warmup())
    except Exception as e:  # noqa: BLE001
        return fail(f"缓存预热失败: {e}", 500)


@router.post("/query/cache/invalidate")
def query_cache_invalidate(namespace: str = Query(...)):
    try:
        return ok(query_optimizer.cache_invalidate(namespace))
    except Exception as e:  # noqa: BLE001
        return fail(f"缓存失效失败: {e}", 500)


@router.get("/query/nplusone")
def query_nplusone():
    try:
        task_id = _new_task("nplusone")
        result = query_optimizer.detect_n_plus_one()
        _finish(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(f"N+1 检测失败: {e}", 500)


@router.get("/query/patterns")
def query_patterns():
    try:
        return ok(query_optimizer.project_sql_patterns())
    except Exception as e:  # noqa: BLE001
        return fail(f"查询模式分析失败: {e}", 500)


# =========================================================================== #
# 2. API 性能（9 个端点）
# =========================================================================== #
@router.post("/api/observe")
def api_observe(req: ObserveIn):
    try:
        return ok(api_performance_monitor.observe(
            req.endpoint, req.elapsed_ms, method=req.method, status=req.status))
    except Exception as e:  # noqa: BLE001
        return fail(f"观测记录失败: {e}", 500)


@router.get("/api/latency")
def api_latency():
    try:
        return ok(api_performance_monitor.latency_summary())
    except Exception as e:  # noqa: BLE001
        return fail(f"延迟汇总失败: {e}", 500)


@router.get("/api/slow-endpoints")
def api_slow(threshold: Optional[float] = None):
    try:
        return ok(api_performance_monitor.slow_endpoints(threshold))
    except Exception as e:  # noqa: BLE001
        return fail(f"慢端点查询失败: {e}", 500)


@router.get("/api/advice")
def api_advice():
    try:
        return ok({"advice": api_performance_monitor.optimization_advice()})
    except Exception as e:  # noqa: BLE001
        return fail(f"优化建议失败: {e}", 500)


@router.post("/api/limit-check")
def api_limit_check(key: str = Query(default="default"), cost: float = 1.0):
    try:
        return ok(api_performance_monitor.limit_check(key, cost))
    except Exception as e:  # noqa: BLE001
        return fail(f"限流检查失败: {e}", 500)


@router.post("/api/limit-config")
def api_limit_config(capacity: Optional[int] = None,
                     refill: Optional[float] = None):
    try:
        return ok(api_performance_monitor.limiter_config(capacity, refill))
    except Exception as e:  # noqa: BLE001
        return fail(f"限流配置失败: {e}", 500)


@router.get("/api/compress")
def api_compress(level: Optional[int] = None):
    try:
        return ok(api_performance_monitor.compress_demo(level=level))
    except Exception as e:  # noqa: BLE001
        return fail(f"压缩统计失败: {e}", 500)


@router.get("/api/pool")
def api_pool():
    try:
        return ok(api_performance_monitor.pool_status())
    except Exception as e:  # noqa: BLE001
        return fail(f"连接池状态失败: {e}", 500)


@router.get("/api/endpoints-scan")
def api_endpoints_scan():
    try:
        return ok(api_performance_monitor.scan_endpoints())
    except Exception as e:  # noqa: BLE001
        return fail(f"端点扫描失败: {e}", 500)


# =========================================================================== #
# 3. 并发与异步（10 个端点）
# =========================================================================== #
@router.post("/concurrency/task")
def concurrency_task(req: TaskIn):
    try:
        tid = conc.queue.submit(req.name, req.model_dump(
            include={"count", "steps", "fail"}), priority=req.priority)
        return ok({"task_id": tid, "status": "queued"})
    except Exception as e:  # noqa: BLE001
        return fail(f"任务提交失败: {e}", 500)


@router.get("/concurrency/tasks")
def concurrency_tasks():
    try:
        return ok(conc.queue.list_tasks())
    except Exception as e:  # noqa: BLE001
        return fail(f"任务列表失败: {e}", 500)


@router.get("/concurrency/task/{task_id}")
def concurrency_task_status(task_id: str):
    try:
        r = conc.queue.status(task_id)
        if not r:
            return fail("任务不存在", 404)
        return ok(r)
    except Exception as e:  # noqa: BLE001
        return fail(f"任务状态失败: {e}", 500)


@router.post("/concurrency/run-next")
def concurrency_run_next():
    try:
        return ok(conc.queue.run_next())
    except Exception as e:  # noqa: BLE001
        return fail(f"任务执行失败: {e}", 500)


@router.post("/concurrency/retry-dlq")
def concurrency_retry_dlq():
    try:
        return ok(conc.queue.retry_dead_letter())
    except Exception as e:  # noqa: BLE001
        return fail(f"死信重投失败: {e}", 500)


@router.get("/concurrency/control")
def concurrency_control():
    try:
        return ok(conc.cc.status())
    except Exception as e:  # noqa: BLE001
        return fail(f"并发控制状态失败: {e}", 500)


@router.get("/concurrency/batch-plan")
def concurrency_batch(total_rows: int = 1000, kind: str = "insert"):
    try:
        return ok(conc.batch.plan(total_rows, kind))
    except Exception as e:  # noqa: BLE001
        return fail(f"批处理规划失败: {e}", 500)


@router.get("/concurrency/events")
def concurrency_events(topic: Optional[str] = None):
    try:
        return ok(conc.events.history(topic))
    except Exception as e:  # noqa: BLE001
        return fail(f"事件日志失败: {e}", 500)


@router.post("/concurrency/publish")
def concurrency_publish(req: EventIn):
    try:
        return ok(conc.events.publish(req.topic, req.payload))
    except Exception as e:  # noqa: BLE001
        return fail(f"事件发布失败: {e}", 500)


@router.get("/concurrency/blocking")
def concurrency_blocking():
    try:
        task_id = _new_task("blocking_analysis")
        result = conc.analyze_blocking()
        _finish(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(f"阻塞点分析失败: {e}", 500)


# =========================================================================== #
# 4. 启动与内存（7 个端点）
# =========================================================================== #
@router.get("/startup/report")
def startup_report():
    try:
        return ok(mem_opt.startup_report())
    except Exception as e:  # noqa: BLE001
        return fail(f"启动报告失败: {e}", 500)


@router.get("/startup/lazy-advice")
def startup_lazy():
    try:
        return ok(mem_opt.lazy_load_advice())
    except Exception as e:  # noqa: BLE001
        return fail(f"懒加载建议失败: {e}", 500)


@router.get("/memory/snapshot")
def memory_snapshot():
    try:
        return ok(mem_opt.memory_snapshot())
    except Exception as e:  # noqa: BLE001
        return fail(f"内存快照失败: {e}", 500)


@router.get("/memory/big-objects")
def memory_big():
    try:
        return ok(mem_opt.big_objects())
    except Exception as e:  # noqa: BLE001
        return fail(f"大对象检测失败: {e}", 500)


@router.get("/memory/leak")
def memory_leak():
    try:
        return ok(mem_opt.leak_check())
    except Exception as e:  # noqa: BLE001
        return fail(f"泄漏检测失败: {e}", 500)


@router.get("/memory/advice")
def memory_advice():
    try:
        return ok({"advice": mem_opt.memory_advice()})
    except Exception as e:  # noqa: BLE001
        return fail(f"内存建议失败: {e}", 500)


@router.post("/memory/warmup")
def memory_warmup():
    try:
        return ok(mem_opt.warmup())
    except Exception as e:  # noqa: BLE001
        return fail(f"预热失败: {e}", 500)


# =========================================================================== #
# 5. 数据库性能（9 个端点）
# =========================================================================== #
@router.get("/db/pool")
def db_pool():
    try:
        return ok(db_perf.pool_status())
    except Exception as e:  # noqa: BLE001
        return fail(f"DB 连接池失败: {e}", 500)


@router.post("/db/pool-tune")
def db_pool_tune(size: Optional[int] = None,
                 timeout_ms: Optional[int] = None,
                 max_lifetime_ms: Optional[int] = None):
    try:
        return ok(db_perf.pool_tune(size, timeout_ms, max_lifetime_ms))
    except Exception as e:  # noqa: BLE001
        return fail(f"连接池调优失败: {e}", 500)


@router.get("/db/plan-cache")
def db_plan_cache():
    try:
        return ok(db_perf.plan_cache_report())
    except Exception as e:  # noqa: BLE001
        return fail(f"计划缓存失败: {e}", 500)


@router.get("/db/schema")
def db_schema(db: Optional[str] = None):
    try:
        return ok(db_perf.schema_report(db))
    except Exception as e:  # noqa: BLE001
        return fail(f"表结构扫描失败: {e}", 500)


@router.get("/db/large-tables")
def db_large(min_rows: int = 10000):
    try:
        return ok(db_perf.large_tables(min_rows))
    except Exception as e:  # noqa: BLE001
        return fail(f"大表识别失败: {e}", 500)


@router.get("/db/sharding")
def db_sharding():
    try:
        return ok(db_perf.sharding_advice())
    except Exception as e:  # noqa: BLE001
        return fail(f"分库分表建议失败: {e}", 500)


@router.get("/db/maintenance")
def db_maintenance(db: Optional[str] = None):
    try:
        return ok(db_perf.maintenance(db))
    except Exception as e:  # noqa: BLE001
        return fail(f"维护建议失败: {e}", 500)


@router.get("/db/monitor")
def db_monitor():
    try:
        return ok(db_perf.monitor())
    except Exception as e:  # noqa: BLE001
        return fail(f"DB 监控失败: {e}", 500)


@router.get("/db/table-sizes")
def db_table_sizes():
    try:
        return ok(db_perf.table_sizes())
    except Exception as e:  # noqa: BLE001
        return fail(f"表大小查询失败: {e}", 500)


# =========================================================================== #
# 6. 性能仪表盘（6 个端点）
# =========================================================================== #
@router.get("/dashboard/realtime")
def dash_realtime():
    try:
        return ok(dashboard.realtime())
    except Exception as e:  # noqa: BLE001
        return fail(f"实时大屏失败: {e}", 500)


@router.get("/dashboard/trends")
def dash_trends():
    try:
        return ok(dashboard.trends())
    except Exception as e:  # noqa: BLE001
        return fail(f"趋势分析失败: {e}", 500)


@router.get("/dashboard/report")
def dash_report():
    try:
        return ok(dashboard.report())
    except Exception as e:  # noqa: BLE001
        return fail(f"报告生成失败: {e}", 500)


@router.post("/dashboard/loadtest")
def dash_loadtest(req: LoadTestIn):
    try:
        task_id = _new_task("loadtest")
        result = dashboard.load_test(req.url, req.concurrency, req.requests)
        _finish(task_id, result)
        return ok({"task_id": task_id, "status": "done", "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(f"压测失败: {e}", 500)


@router.get("/dashboard/sla")
def dash_sla():
    try:
        return ok(dashboard.sla_status())
    except Exception as e:  # noqa: BLE001
        return fail(f"SLA 查询失败: {e}", 500)


@router.get("/dashboard/score")
def dash_score():
    try:
        return ok(dashboard.score())
    except Exception as e:  # noqa: BLE001
        return fail(f"性能评分失败: {e}", 500)
