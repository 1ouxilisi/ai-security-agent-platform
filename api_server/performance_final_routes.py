# -*- coding: utf-8 -*-
"""
api_server/performance_final_routes.py — 性能最终优化 REST API（第22轮·方向3）。

路由前缀: /api/v1/performance-final
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底，不向调用方抛 500；任务用内存字典 TASKS 模拟异步。
依赖 performance_final/ 包内 6 个核心模块；第三方库缺失时由模块内部回退模拟。
不修改 app.py（由集成脚本统一注入）。
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

# 保证项目根目录可导入 performance_final 包
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from performance_final.load_testing import engine as load_engine            # noqa: E402
from performance_final.bottleneck_fixer import fixer                        # noqa: E402
from performance_final.startup_optimizer import optimizer as startup_opt    # noqa: E402
from performance_final.api_optimizer import optimizer as api_opt             # noqa: E402
from performance_final.memory_optimizer import optimizer as mem_opt         # noqa: E402
from performance_final.perf_dashboard import dashboard                       # noqa: E402

router = APIRouter(prefix="/api/v1/performance-final", tags=["性能最终优化"])


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
class LoadTestIn(BaseModel):
    scenario: str = "api"
    concurrent_users: int = 50
    duration_sec: int = 60
    requests_per_sec: int = 200


class ObserveIn(BaseModel):
    endpoint: str
    elapsed_ms: float
    method: str = "GET"
    status: int = 200


class CacheIn(BaseModel):
    key: str
    value: Optional[Any] = None


class PoolTuneIn(BaseModel):
    kind: str = "db"
    size: int = 20


# =========================================================================== #
# 0. 总览
# =========================================================================== #
@router.get("/overview")
def overview():
    try:
        rt = dashboard.realtime()
        return ok({
            "modules": ["load_testing", "bottleneck_fixer", "startup_optimizer",
                         "api_optimizer", "memory_optimizer", "perf_dashboard"],
            "realtime": rt["metrics"],
            "slo": dashboard.slo,
            "psutil": rt["psutil"],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:  # noqa: BLE001
        return fail(f"总览失败: {e}", 500)


# =========================================================================== #
# 1. 全链路压测（7 个端点）
# =========================================================================== #
@router.get("/load/scenarios")
def load_scenarios():
    try:
        return ok(load_engine.list_scenarios())
    except Exception as e:  # noqa: BLE001
        return fail(f"压测场景失败: {e}", 500)


@router.get("/load/config")
def load_config(scenario: str = "api"):
    try:
        return ok(load_engine.default_config(scenario))
    except Exception as e:  # noqa: BLE001
        return fail(f"压测配置失败: {e}", 500)


@router.post("/load/run")
def load_run(req: LoadTestIn):
    try:
        tid = _new_task("load_run")
        result = load_engine.run({"scenario": req.scenario,
                                  "concurrent_users": req.concurrent_users,
                                  "duration_sec": req.duration_sec,
                                  "requests_per_sec": req.requests_per_sec})
        _finish(tid, result)
        return ok({"task_id": tid, "status": "done", "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(f"压测执行失败: {e}", 500)


@router.get("/load/report")
def load_report(run_id: Optional[str] = None):
    try:
        return ok(load_engine.report(run_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"压测报告失败: {e}", 500)


@router.get("/load/history")
def load_history():
    try:
        return ok(load_engine.history_trend())
    except Exception as e:  # noqa: BLE001
        return fail(f"压测历史失败: {e}", 500)


@router.get("/load/ci-gate")
def load_ci_gate(run_id: Optional[str] = None):
    try:
        return ok(load_engine.ci_gate(run_id))
    except Exception as e:  # noqa: BLE001
        return fail(f"CI 门禁失败: {e}", 500)


@router.get("/load/automation")
def load_automation():
    try:
        return ok(load_engine.automation_config())
    except Exception as e:  # noqa: BLE001
        return fail(f"压测自动化失败: {e}", 500)


# =========================================================================== #
# 2. 瓶颈定位与修复（8 个端点）
# =========================================================================== #
@router.get("/bottleneck/detect")
def bn_detect():
    try:
        return ok(fixer.detect())
    except Exception as e:  # noqa: BLE001
        return fail(f"瓶颈检测失败: {e}", 500)


@router.get("/bottleneck/scan-source")
def bn_scan(max_files: int = 400):
    try:
        tid = _new_task("scan_source")
        result = fixer.scan_source(max_files=max_files)
        _finish(tid, result)
        return ok({"task_id": tid, "status": "done", "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(f"源码扫描失败: {e}", 500)


@router.get("/bottleneck/methods")
def bn_methods():
    try:
        return ok(fixer.profiling_methods())
    except Exception as e:  # noqa: BLE001
        return fail(f"定位方法失败: {e}", 500)


@router.get("/bottleneck/flame")
def bn_flame(top: int = 20):
    try:
        return ok(fixer.flame_graph(top=top))
    except Exception as e:  # noqa: BLE001
        return fail(f"火焰图失败: {e}", 500)


@router.get("/bottleneck/fix-suggestions")
def bn_fix():
    try:
        return ok(fixer.fix_suggestions())
    except Exception as e:  # noqa: BLE001
        return fail(f"修复建议失败: {e}", 500)


@router.post("/bottleneck/verify")
def bn_verify(baseline: float = 22.0, optimized: float = 9.0):
    try:
        return ok(fixer.verify_fix(baseline, optimized))
    except Exception as e:  # noqa: BLE001
        return fail(f"修复验证失败: {e}", 500)


@router.get("/bottleneck/tuning-guide")
def bn_tuning():
    try:
        return ok(fixer.tuning_guide())
    except Exception as e:  # noqa: BLE001
        return fail(f"调优指南失败: {e}", 500)


@router.get("/bottleneck/best-practices")
def bn_practices():
    try:
        return ok({"practices": fixer.best_practices()})
    except Exception as e:  # noqa: BLE001
        return fail(f"最佳实践失败: {e}", 500)


# =========================================================================== #
# 3. 启动时间优化（5 个端点）
# =========================================================================== #
@router.get("/startup/analyze")
def startup_analyze():
    try:
        return ok(startup_opt.analyze())
    except Exception as e:  # noqa: BLE001
        return fail(f"启动分析失败: {e}", 500)


@router.get("/startup/lazy-advice")
def startup_lazy():
    try:
        return ok(startup_opt.lazy_advice())
    except Exception as e:  # noqa: BLE001
        return fail(f"懒加载建议失败: {e}", 500)


@router.post("/startup/warmup")
def startup_warmup():
    try:
        return ok(startup_opt.warmup())
    except Exception as e:  # noqa: BLE001
        return fail(f"预热失败: {e}", 500)


@router.get("/startup/deps")
def startup_deps():
    try:
        return ok(startup_opt.dependency_optimization())
    except Exception as e:  # noqa: BLE001
        return fail(f"依赖优化失败: {e}", 500)


@router.get("/startup/config")
def startup_config():
    try:
        return ok(startup_opt.config_optimization())
    except Exception as e:  # noqa: BLE001
        return fail(f"启动配置失败: {e}", 500)


# =========================================================================== #
# 4. API 性能优化（10 个端点）
# =========================================================================== #
@router.post("/api/observe")
def api_observe(req: ObserveIn):
    try:
        return ok(api_opt.observe(req.endpoint, req.elapsed_ms,
                                  method=req.method, status=req.status))
    except Exception as e:  # noqa: BLE001
        return fail(f"观测记录失败: {e}", 500)


@router.get("/api/latency")
def api_latency():
    try:
        return ok(api_opt.latency_summary())
    except Exception as e:  # noqa: BLE001
        return fail(f"延迟汇总失败: {e}", 500)


@router.get("/api/slow-endpoints")
def api_slow(threshold: Optional[float] = None):
    try:
        return ok(api_opt.slow_endpoints(threshold))
    except Exception as e:  # noqa: BLE001
        return fail(f"慢端点失败: {e}", 500)


@router.get("/api/throughput")
def api_throughput():
    try:
        return ok(api_opt.throughput())
    except Exception as e:  # noqa: BLE001
        return fail(f"吞吐失败: {e}", 500)


@router.post("/api/pool-tune")
def api_pool_tune(req: PoolTuneIn):
    try:
        return ok(api_opt.pool_tune(req.kind, req.size))
    except Exception as e:  # noqa: BLE001
        return fail(f"连接池调优失败: {e}", 500)


@router.get("/api/cache/stats")
def api_cache_stats():
    try:
        return ok(api_opt.cache_stats())
    except Exception as e:  # noqa: BLE001
        return fail(f"缓存统计失败: {e}", 500)


@router.get("/api/cache/get")
def api_cache_get(key: str = Query(...)):
    try:
        return ok(api_opt.cache_get(key))
    except Exception as e:  # noqa: BLE001
        return fail(f"缓存读取失败: {e}", 500)


@router.post("/api/cache/invalidate")
def api_cache_invalidate(namespace: str = Query(default="")):
    try:
        return ok(api_opt.cache_invalidate(namespace))
    except Exception as e:  # noqa: BLE001
        return fail(f"缓存失效失败: {e}", 500)


@router.get("/api/db-advice")
def api_db_advice():
    try:
        return ok(api_opt.db_advice())
    except Exception as e:  # noqa: BLE001
        return fail(f"DB 建议失败: {e}", 500)


@router.get("/api/compress")
def api_compress(level: int = 6):
    try:
        return ok(api_opt.compress_demo(level=level))
    except Exception as e:  # noqa: BLE001
        return fail(f"压缩实测失败: {e}", 500)


# =========================================================================== #
# 5. 内存与资源优化（8 个端点）
# =========================================================================== #
@router.get("/memory/snapshot")
def mem_snapshot():
    try:
        return ok(mem_opt.snapshot())
    except Exception as e:  # noqa: BLE001
        return fail(f"内存快照失败: {e}", 500)


@router.get("/memory/trend")
def mem_trend():
    try:
        return ok(mem_opt.trend())
    except Exception as e:  # noqa: BLE001
        return fail(f"内存趋势失败: {e}", 500)


@router.get("/memory/leak")
def mem_leak():
    try:
        tid = _new_task("leak_check")
        result = mem_opt.leak_check()
        _finish(tid, result)
        return ok({"task_id": tid, "status": "done", "result": result})
    except Exception as e:  # noqa: BLE001
        return fail(f"泄漏检测失败: {e}", 500)


@router.get("/memory/tips")
def mem_tips():
    try:
        return ok(mem_opt.optimization_tips())
    except Exception as e:  # noqa: BLE001
        return fail(f"内存建议失败: {e}", 500)


@router.post("/memory/pool")
def mem_pool(n: int = 100):
    try:
        return ok(mem_opt.object_pool_demo(n))
    except Exception as e:  # noqa: BLE001
        return fail(f"对象池失败: {e}", 500)


@router.get("/memory/gc")
def mem_gc():
    try:
        return ok(mem_opt.gc_status())
    except Exception as e:  # noqa: BLE001
        return fail(f"GC 状态失败: {e}", 500)


@router.get("/memory/usage")
def mem_usage():
    try:
        return ok(mem_opt.resource_usage())
    except Exception as e:  # noqa: BLE001
        return fail(f"资源使用失败: {e}", 500)


@router.get("/memory/limits")
def mem_limits():
    try:
        return ok(mem_opt.resource_limits())
    except Exception as e:  # noqa: BLE001
        return fail(f"资源限制失败: {e}", 500)


# =========================================================================== #
# 6. 性能监控与告警（6 个端点）
# =========================================================================== #
@router.get("/dashboard/realtime")
def dash_realtime():
    try:
        return ok(dashboard.realtime())
    except Exception as e:  # noqa: BLE001
        return fail(f"实时大屏失败: {e}", 500)


@router.get("/dashboard/metrics")
def dash_metrics():
    try:
        return ok(dashboard.metric_system())
    except Exception as e:  # noqa: BLE001
        return fail(f"指标体系失败: {e}", 500)


@router.get("/dashboard/alerts")
def dash_alerts():
    try:
        return ok(dashboard.alerts_list())
    except Exception as e:  # noqa: BLE001
        return fail(f"告警查询失败: {e}", 500)


@router.get("/dashboard/views")
def dash_views():
    try:
        return ok(dashboard.dashboard_views())
    except Exception as e:  # noqa: BLE001
        return fail(f"仪表盘视图失败: {e}", 500)


@router.get("/dashboard/logs")
def dash_logs():
    try:
        return ok(dashboard.perf_logs())
    except Exception as e:  # noqa: BLE001
        return fail(f"性能日志失败: {e}", 500)


@router.get("/dashboard/report")
def dash_report():
    try:
        return ok(dashboard.report())
    except Exception as e:  # noqa: BLE001
        return fail(f"性能报告失败: {e}", 500)


# =========================================================================== #
# 任务查询（2 个端点）
# =========================================================================== #
@router.get("/tasks")
def list_tasks():
    try:
        return ok({"tasks": list(TASKS.values())[-50:], "total": len(TASKS)})
    except Exception as e:  # noqa: BLE001
        return fail(f"任务列表失败: {e}", 500)


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        if task_id not in TASKS:
            return fail("任务不存在", 404)
        return ok(TASKS[task_id])
    except Exception as e:  # noqa: BLE001
        return fail(f"任务查询失败: {e}", 500)
