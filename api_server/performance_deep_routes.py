# -*- coding: utf-8 -*-
"""
api_server/performance_deep_routes.py — 第28轮升级方向3：性能优化与压力测试 REST API。

路由前缀: /api/v1/performance-deep
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/performance-deep", tags=["性能优化与压力测试"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from performance_deep.benchmark import (
        get_benchmark_runner, TEST_SCENARIOS, METRIC_DEFS, TOOL_CONFIG,
    )
    from performance_deep.high_concurrency import get_concurrency_manager
    from performance_deep.big_data import get_big_data_manager
    from performance_deep.distributed_scan_perf import get_distributed_scan_manager
    from performance_deep.stress_test import get_stress_runner
    from performance_deep.performance_monitor import get_monitor_manager
    from performance_deep.performance_dashboard import (
        get_performance_dashboard, SYSTEM_SETTINGS,
    )
    _MOD_AVAILABLE = True
    logger.info("performance_deep_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("performance_deep_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from performance_deep.benchmark import (  # noqa
            get_benchmark_runner, TEST_SCENARIOS, METRIC_DEFS, TOOL_CONFIG,
        )
        from performance_deep.high_concurrency import get_concurrency_manager  # noqa
        from performance_deep.big_data import get_big_data_manager  # noqa
        from performance_deep.distributed_scan_perf import get_distributed_scan_manager  # noqa
        from performance_deep.stress_test import get_stress_runner  # noqa
        from performance_deep.performance_monitor import get_monitor_manager  # noqa
        from performance_deep.performance_dashboard import (  # noqa
            get_performance_dashboard, SYSTEM_SETTINGS,
        )
        _MOD_AVAILABLE = True
        logger.info("performance_deep_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("performance_deep_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    import uuid
    tid = uuid.uuid4().hex[:12]
    TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish_task(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in TASKS:
        t = TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


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
        return fail("性能优化与压力测试模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class BenchmarkRunReq(BaseModel):
    url: str = "http://127.0.0.1:8000/api/v1/health"
    scenario: str = "multi_user"
    concurrency: Optional[int] = None
    requests: Optional[int] = None
    method: str = "GET"


class CacheWarmupReq(BaseModel):
    keys: List[str] = Field(default_factory=lambda: ["k1", "k2", "k3"])


class CacheInvalidateReq(BaseModel):
    pattern: str = ""


class ExecuteReq(BaseModel):
    key: str = "demo"
    cost_ms: float = 5.0
    force_miss: bool = False


class TaskSubmitReq(BaseModel):
    payload: str = "demo"
    queue: str = "default"


class BatchReq(BaseModel):
    total: int = 10000
    batch_size: int = 500
    op: str = "insert"


class ShardRouteReq(BaseModel):
    key: str = "example.com"


class ShardMigrateReq(BaseModel):
    src: int = 0
    dst: int = 1


class PartitionPruneReq(BaseModel):
    range: str = "2026-Q4"


class StreamReq(BaseModel):
    window_sec: int = 10
    events: int = 1000


class QueryExplainReq(BaseModel):
    sql: str = "SELECT * FROM scan_result WHERE target='example.com'"


class MVCreateReq(BaseModel):
    name: str = "mv_daily_summary"
    query: str = "SELECT date, COUNT(*) FROM scan_result GROUP BY date"


class ScanSubmitReq(BaseModel):
    target: str = "example.com"
    ports: str = "1-1024"
    priority: int = 5


class CheckpointReq(BaseModel):
    task_id: str = "scan-001"
    progress: int = 50
    cursor: str = "port:8080"


class LoadTestReq(BaseModel):
    vusers: int = 50
    duration_sec: int = 5
    ramp_up_sec: int = 1


class SoakReq(BaseModel):
    hours: int = 2


class FaultCpuReq(BaseModel):
    load_pct: int = 50
    duration_sec: int = 3


class FaultMemReq(BaseModel):
    alloc_mb: int = 50


class FaultNetReq(BaseModel):
    latency_ms: int = 500
    loss_pct: float = 5.0


class FaultSvcReq(BaseModel):
    service: str = "payment"
    error_rate: float = 0.3


class ChaosCreateReq(BaseModel):
    name: str = "支付服务故障注入"
    hypothesis: str = "支付服务30%错误率不影响下单"
    blast_radius: str = "10%"
    duration_min: int = 10


class RecoveryReq(BaseModel):
    scenario: str = "db_failover"


class RuleUpdateReq(BaseModel):
    values: Dict[str, Any] = Field(default_factory=dict)


class SettingsUpdateReq(BaseModel):
    values: Dict[str, Any] = Field(default_factory=dict)


# 解析 from __future__ import annotations 产生的字符串注解
for _m in (BenchmarkRunReq, CacheWarmupReq, CacheInvalidateReq, ExecuteReq,
           TaskSubmitReq, BatchReq, ShardRouteReq, ShardMigrateReq,
           PartitionPruneReq, StreamReq, QueryExplainReq, MVCreateReq,
           ScanSubmitReq, CheckpointReq, LoadTestReq, SoakReq,
           FaultCpuReq, FaultMemReq, FaultNetReq, FaultSvcReq,
           ChaosCreateReq, RecoveryReq, RuleUpdateReq, SettingsUpdateReq):
    try:
        _m.model_rebuild()
    except Exception:  # pragma: no cover
        pass


# =========================================================================== #
# 一、基准测试 (benchmark)
# =========================================================================== #
@router.get("/benchmark/scenarios")
def bm_scenarios():
    try:
        return ok(TEST_SCENARIOS)
    except Exception as e:
        return fail(str(e))


@router.get("/benchmark/metrics")
def bm_metrics():
    try:
        return ok(METRIC_DEFS)
    except Exception as e:
        return fail(str(e))


@router.get("/benchmark/tool-config")
def bm_tool_config():
    try:
        return ok(TOOL_CONFIG)
    except Exception as e:
        return fail(str(e))


@router.post("/benchmark/run")
def bm_run(req: BenchmarkRunReq):
    try:
        g = _guard()
        if g:
            return g
        runner = get_benchmark_runner()
        result = runner.run_benchmark(req.url, req.scenario,
                                      req.concurrency, req.requests, req.method)
        return ok(result)
    except Exception as e:
        logger.exception("bm_run error")
        return fail(str(e))


@router.get("/benchmark/reports")
def bm_list_reports():
    try:
        return ok(get_benchmark_runner().list_reports())
    except Exception as e:
        return fail(str(e))


@router.get("/benchmark/reports/{bid}")
def bm_get_report(bid: str):
    try:
        r = get_benchmark_runner().get_report(bid)
        if not r:
            return fail("报告不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(str(e))


@router.get("/benchmark/compare")
def bm_compare(a: str = Query(...), b: str = Query(...)):
    try:
        r = get_benchmark_runner().compare(a, b)
        if not r:
            return fail("报告不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(str(e))


@router.get("/benchmark/reports/{bid}/bottleneck")
def bm_bottleneck(bid: str):
    try:
        r = get_benchmark_runner().bottleneck_analysis(bid)
        if not r:
            return fail("报告不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(str(e))


@router.post("/benchmark/env/prepare")
def bm_prepare_env(rows: int = Query(10000)):
    try:
        return ok(get_benchmark_runner().prepare_env(rows))
    except Exception as e:
        return fail(str(e))


@router.post("/benchmark/env/reset")
def bm_reset_env():
    try:
        return ok(get_benchmark_runner().reset_env())
    except Exception as e:
        return fail(str(e))


@router.get("/benchmark/reports/{bid}/export")
def bm_export(bid: str, fmt: str = "json"):
    try:
        r = get_benchmark_runner().export_report(bid, fmt)
        if not r:
            return fail("报告不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 二、高并发优化 (high_concurrency)
# =========================================================================== #
@router.get("/concurrency/pools")
def hc_pools():
    try:
        return ok(get_concurrency_manager().pool_status())
    except Exception as e:
        return fail(str(e))


@router.post("/concurrency/execute")
def hc_execute(req: ExecuteReq):
    try:
        return ok(get_concurrency_manager().execute_request(req.key, req.cost_ms,
                                                           req.force_miss))
    except Exception as e:
        return fail(str(e))


@router.get("/concurrency/cache")
def hc_cache():
    try:
        return ok(get_concurrency_manager().cache_overview())
    except Exception as e:
        return fail(str(e))


@router.post("/concurrency/cache/warmup")
def hc_warmup(req: CacheWarmupReq):
    try:
        return ok(get_concurrency_manager().warmup_cache(req.keys))
    except Exception as e:
        return fail(str(e))


@router.post("/concurrency/cache/invalidate")
def hc_invalidate(req: CacheInvalidateReq):
    try:
        return ok(get_concurrency_manager().invalidate_cache(req.pattern))
    except Exception as e:
        return fail(str(e))


@router.get("/concurrency/resilience")
def hc_resilience():
    try:
        return ok(get_concurrency_manager().resilience_status())
    except Exception as e:
        return fail(str(e))


@router.post("/concurrency/breaker/trip")
def hc_trip_breaker():
    try:
        return ok(get_concurrency_manager().trip_breaker())
    except Exception as e:
        return fail(str(e))


@router.post("/concurrency/task")
def hc_submit_task(req: TaskSubmitReq):
    try:
        return ok(get_concurrency_manager().submit_task(req.payload, req.queue))
    except Exception as e:
        return fail(str(e))


@router.get("/concurrency/queues")
def hc_queues():
    try:
        return ok(get_concurrency_manager().queue_status())
    except Exception as e:
        return fail(str(e))


@router.get("/concurrency/tuning")
def hc_tuning():
    try:
        return ok(get_concurrency_manager().resource_tuning())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 三、大数据优化 (big_data)
# =========================================================================== #
@router.get("/bigdata/overview")
def bd_overview():
    try:
        return ok(get_big_data_manager().overview())
    except Exception as e:
        return fail(str(e))


@router.get("/bigdata/shards")
def bd_shards():
    try:
        return ok(get_big_data_manager().shards.list_shards())
    except Exception as e:
        return fail(str(e))


@router.post("/bigdata/shards/route")
def bd_route(req: ShardRouteReq):
    try:
        return ok(get_big_data_manager().shards.route_key(req.key))
    except Exception as e:
        return fail(str(e))


@router.post("/bigdata/shards/rebalance")
def bd_rebalance():
    try:
        return ok(get_big_data_manager().shards.rebalance())
    except Exception as e:
        return fail(str(e))


@router.post("/bigdata/shards/migrate")
def bd_migrate(req: ShardMigrateReq):
    try:
        return ok(get_big_data_manager().shards.migrate_shard(req.src, req.dst))
    except Exception as e:
        return fail(str(e))


@router.get("/bigdata/partitions")
def bd_partitions():
    try:
        return ok(get_big_data_manager().partitions.list_partitions())
    except Exception as e:
        return fail(str(e))


@router.post("/bigdata/partitions/prune")
def bd_prune(req: PartitionPruneReq):
    try:
        return ok(get_big_data_manager().partitions.prune(req.range))
    except Exception as e:
        return fail(str(e))


@router.post("/bigdata/partitions/archive")
def bd_archive():
    try:
        return ok(get_big_data_manager().partitions.archive_cold())
    except Exception as e:
        return fail(str(e))


@router.post("/bigdata/batch")
def bd_batch(req: BatchReq):
    try:
        return ok(get_big_data_manager().batch.batch_op(req.total, req.batch_size, req.op))
    except Exception as e:
        return fail(str(e))


@router.post("/bigdata/batch/compare")
def bd_batch_compare(total: int = Query(10000)):
    try:
        return ok(get_big_data_manager().batch.compare_batch_vs_single(total))
    except Exception as e:
        return fail(str(e))


@router.post("/bigdata/stream/window")
def bd_stream(req: StreamReq):
    try:
        return ok(get_big_data_manager().stream.process_window(req.window_sec, req.events))
    except Exception as e:
        return fail(str(e))


@router.get("/bigdata/stream/backpressure")
def bd_backpressure():
    try:
        return ok(get_big_data_manager().stream.backpressure_status())
    except Exception as e:
        return fail(str(e))


@router.get("/bigdata/compression")
def bd_compression():
    try:
        return ok({"formats": get_big_data_manager().compression.formats(),
                   "demo": get_big_data_manager().compression.compress_demo()})
    except Exception as e:
        return fail(str(e))


@router.post("/bigdata/query/explain")
def bd_explain(req: QueryExplainReq):
    try:
        return ok(get_big_data_manager().optimizer.explain(req.sql))
    except Exception as e:
        return fail(str(e))


@router.get("/bigdata/indexes")
def bd_indexes():
    try:
        return ok(get_big_data_manager().optimizer.list_indexes())
    except Exception as e:
        return fail(str(e))


@router.post("/bigdata/mv")
def bd_mv(req: MVCreateReq):
    try:
        return ok(get_big_data_manager().optimizer.create_materialized_view(req.name, req.query))
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 四、分布式扫描优化 (distributed_scan_perf)
# =========================================================================== #
@router.get("/distributed/overview")
def ds_overview():
    try:
        return ok(get_distributed_scan_manager().overview())
    except Exception as e:
        return fail(str(e))


@router.post("/distributed/scan")
def ds_scan(req: ScanSubmitReq):
    try:
        return ok(get_distributed_scan_manager().mw.submit_scan(req.target, req.ports,
                                                                  req.priority))
    except Exception as e:
        return fail(str(e))


@router.get("/distributed/tasks")
def ds_tasks():
    try:
        return ok(get_distributed_scan_manager().mw.list_tasks())
    except Exception as e:
        return fail(str(e))


@router.post("/distributed/dispatch")
def ds_dispatch():
    try:
        return ok(get_distributed_scan_manager().mw.dispatch())
    except Exception as e:
        return fail(str(e))


@router.post("/distributed/tasks/{tid}/complete")
def ds_complete(tid: str):
    try:
        r = get_distributed_scan_manager().mw.complete_task(tid)
        if not r:
            return fail("任务不存在", 404)
        return ok(r)
    except Exception as e:
        return fail(str(e))


@router.get("/distributed/workers")
def ds_workers():
    try:
        return ok(get_distributed_scan_manager().mw.list_workers())
    except Exception as e:
        return fail(str(e))


@router.get("/distributed/proxies")
def ds_proxies():
    try:
        return ok(get_distributed_scan_manager().proxy_pool.list_proxies())
    except Exception as e:
        return fail(str(e))


@router.post("/distributed/proxies/health-check")
def ds_proxy_health():
    try:
        return ok(get_distributed_scan_manager().proxy_pool.health_check())
    except Exception as e:
        return fail(str(e))


@router.post("/distributed/proxies/rotate")
def ds_proxy_rotate(strategy: str = Query("weighted")):
    try:
        return ok(get_distributed_scan_manager().proxy_pool.rotate())
    except Exception as e:
        return fail(str(e))


@router.post("/distributed/checkpoint")
def ds_checkpoint(req: CheckpointReq):
    try:
        return ok(get_distributed_scan_manager().resume.save_checkpoint(
            req.task_id, req.progress, req.cursor))
    except Exception as e:
        return fail(str(e))


@router.get("/distributed/checkpoints")
def ds_list_checkpoints():
    try:
        return ok(get_distributed_scan_manager().resume.list_checkpoints())
    except Exception as e:
        return fail(str(e))


@router.post("/distributed/checkpoints/{tid}/restore")
def ds_restore(tid: str):
    try:
        return ok(get_distributed_scan_manager().resume.restore(tid))
    except Exception as e:
        return fail(str(e))


@router.get("/distributed/speed")
def ds_speed():
    try:
        return ok(get_distributed_scan_manager().scan_speed_report())
    except Exception as e:
        return fail(str(e))


@router.get("/distributed/bottlenecks")
def ds_bottlenecks():
    try:
        return ok(get_distributed_scan_manager().bottleneck())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 五、压力测试 (stress_test)
# =========================================================================== #
@router.post("/stress/load")
def st_load(req: LoadTestReq):
    try:
        return ok(get_stress_runner().load_test(req.vusers, req.duration_sec,
                                                 req.ramp_up_sec))
    except Exception as e:
        return fail(str(e))


@router.get("/stress/runs")
def st_runs():
    try:
        return ok(list(get_stress_runner().runs.values())[-20:])
    except Exception as e:
        return fail(str(e))


@router.post("/stress/soak")
def st_soak(req: SoakReq):
    try:
        return ok(get_stress_runner().soak_test(req.hours))
    except Exception as e:
        return fail(str(e))


@router.get("/stress/capacity-curve")
def st_curve():
    try:
        return ok(get_stress_runner().capacity_curve())
    except Exception as e:
        return fail(str(e))


@router.post("/stress/fault/cpu")
def st_fault_cpu(req: FaultCpuReq):
    try:
        return ok(get_stress_runner().injector.inject_cpu(req.load_pct, req.duration_sec))
    except Exception as e:
        return fail(str(e))


@router.post("/stress/fault/memory")
def st_fault_mem(req: FaultMemReq):
    try:
        return ok(get_stress_runner().injector.inject_memory(req.alloc_mb))
    except Exception as e:
        return fail(str(e))


@router.post("/stress/fault/network")
def st_fault_net(req: FaultNetReq):
    try:
        return ok(get_stress_runner().injector.inject_network(req.latency_ms, req.loss_pct))
    except Exception as e:
        return fail(str(e))


@router.post("/stress/fault/service")
def st_fault_svc(req: FaultSvcReq):
    try:
        return ok(get_stress_runner().injector.inject_service(req.service, req.error_rate))
    except Exception as e:
        return fail(str(e))


@router.get("/stress/faults")
def st_faults():
    try:
        return ok(get_stress_runner().injector.list_active())
    except Exception as e:
        return fail(str(e))


@router.post("/stress/faults/{fid}/stop")
def st_fault_stop(fid: str):
    try:
        return ok(get_stress_runner().injector.stop(fid))
    except Exception as e:
        return fail(str(e))


@router.post("/stress/chaos")
def st_chaos(req: ChaosCreateReq):
    try:
        return ok(get_stress_runner().chaos.create(req.name, req.hypothesis,
                                                    req.blast_radius, req.duration_min))
    except Exception as e:
        return fail(str(e))


@router.get("/stress/chaos")
def st_chaos_list():
    try:
        return ok(get_stress_runner().chaos.list())
    except Exception as e:
        return fail(str(e))


@router.get("/stress/chaos/practices")
def st_chaos_practices():
    try:
        return ok(get_stress_runner().chaos.best_practices())
    except Exception as e:
        return fail(str(e))


@router.post("/stress/recovery")
def st_recovery(req: RecoveryReq):
    try:
        return ok(get_stress_runner().recovery_test(req.scenario))
    except Exception as e:
        return fail(str(e))


@router.get("/stress/capacity")
def st_capacity():
    try:
        return ok(get_stress_runner().capacity_planning())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 六、性能监控 (performance_monitor)
# =========================================================================== #
@router.get("/monitor/snapshot")
def pm_snapshot():
    try:
        return ok(get_monitor_manager().collector.snapshot())
    except Exception as e:
        return fail(str(e))


@router.get("/monitor/api-metrics")
def pm_api():
    try:
        return ok(get_monitor_manager().collector.api_metrics())
    except Exception as e:
        return fail(str(e))


@router.get("/monitor/db-metrics")
def pm_db():
    try:
        return ok(get_monitor_manager().collector.db_metrics())
    except Exception as e:
        return fail(str(e))


@router.get("/monitor/trend")
def pm_trend(points: int = Query(24, ge=6, le=168)):
    try:
        return ok(get_monitor_manager().collector.trend(points))
    except Exception as e:
        return fail(str(e))


@router.get("/monitor/alerts")
def pm_alerts():
    try:
        return ok(get_monitor_manager().alerts.list_alerts())
    except Exception as e:
        return fail(str(e))


@router.get("/monitor/rules")
def pm_rules():
    try:
        return ok(get_monitor_manager().alerts.list_rules())
    except Exception as e:
        return fail(str(e))


@router.put("/monitor/rules/{name}")
def pm_update_rule(name: str, req: RuleUpdateReq):
    try:
        return ok(get_monitor_manager().alerts.update_rule(name, req.values))
    except Exception as e:
        return fail(str(e))


@router.get("/monitor/slow-endpoints")
def pm_slow_ep():
    try:
        return ok(get_monitor_manager().analyzer.slow_endpoints())
    except Exception as e:
        return fail(str(e))


@router.get("/monitor/slow-queries")
def pm_slow_q():
    try:
        return ok(get_monitor_manager().analyzer.slow_queries())
    except Exception as e:
        return fail(str(e))


@router.get("/monitor/call-chain")
def pm_chain():
    try:
        return ok(get_monitor_manager().analyzer.call_chain())
    except Exception as e:
        return fail(str(e))


@router.get("/monitor/dashboard")
def pm_dashboard():
    try:
        return ok(get_monitor_manager().dashboard())
    except Exception as e:
        return fail(str(e))


# =========================================================================== #
# 七、控制台聚合 (dashboard) + 系统设置 + 健康检查
# =========================================================================== #
@router.get("/dashboard/overview")
def dash_overview():
    try:
        g = _guard()
        if g:
            return g
        return ok(get_performance_dashboard().overview())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/benchmark")
def dash_bench():
    try:
        return ok(get_performance_dashboard().benchmark_view())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/concurrency")
def dash_concurrency():
    try:
        return ok(get_performance_dashboard().concurrency_view())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/bigdata")
def dash_bigdata():
    try:
        return ok(get_performance_dashboard().bigdata_view())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/distributed")
def dash_distributed():
    try:
        return ok(get_performance_dashboard().distributed_view())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/stress")
def dash_stress():
    try:
        return ok(get_performance_dashboard().stress_view())
    except Exception as e:
        return fail(str(e))


@router.get("/dashboard/monitor")
def dash_monitor():
    try:
        return ok(get_performance_dashboard().monitor_view())
    except Exception as e:
        return fail(str(e))


@router.get("/settings")
def get_settings():
    try:
        return ok(SYSTEM_SETTINGS)
    except Exception as e:
        return fail(str(e))


@router.put("/settings/{section}")
def update_settings(section: str, req: SettingsUpdateReq):
    try:
        if section in SYSTEM_SETTINGS:
            SYSTEM_SETTINGS[section].update(req.values)
        return ok({"section": section, "values": SYSTEM_SETTINGS.get(section, {})})
    except Exception as e:
        return fail(str(e))


@router.get("/health")
def health():
    try:
        return ok({
            "status": "ok",
            "modules_loaded": _MOD_AVAILABLE,
            "tasks_in_memory": len(TASKS),
            "benchmark_reports": len(get_benchmark_runner().reports),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        return fail(str(e))
