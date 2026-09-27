# -*- coding: utf-8 -*-
"""
distributed_scan_routes.py — 分布式扫描与任务调度 REST API（第23轮升级 · 方向2）。

路由前缀：/api/v1/distributed-scan
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500。
任务用内存字典 + 集群运行时模拟（真实队列/优先级/重试/死信/心跳/分片聚合）。
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 可选 logger
try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging as log  # type: ignore

# 核心模块 try-import
try:
    from distributed_scan.cluster_arch import get_cluster_state, simulate_worker_run
    from distributed_scan.task_manager import get_task_manager
    from distributed_scan.proxy_pool import get_proxy_pool
    from distributed_scan.resume_scan import get_resume_manager
    from distributed_scan.resource_manager import get_resource_manager
    from distributed_scan.cluster_dashboard import get_dashboard
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    log.warning("distributed_scan_routes: 模块导入失败: %s", _e)
    get_cluster_state = None  # type: ignore
    simulate_worker_run = None  # type: ignore
    get_task_manager = None  # type: ignore
    get_proxy_pool = None  # type: ignore
    get_resume_manager = None  # type: ignore
    get_resource_manager = None  # type: ignore
    get_dashboard = None  # type: ignore
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/distributed-scan", tags=["分布式扫描与任务调度"])


# ==================== 响应工具 ====================

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, list):
        return [_clean(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": err})


# ==================== 请求模型 ====================

class NodeRegisterReq(BaseModel):
    node_id: str = "worker-auto-01"
    capabilities: List[str] = Field(default_factory=lambda: ["scan"])
    resources: Dict[str, float] = Field(default_factory=lambda: {"cpu": 30, "mem": 40, "disk": 20, "net": 15})
    tags: Dict[str, str] = Field(default_factory=dict)
    auth_token: str = "auto-token"


class HeartbeatReq(BaseModel):
    resources: Optional[Dict[str, float]] = None
    status: str = "online"


class StrategyReq(BaseModel):
    strategy: str = "priority"


class DispatchReq(BaseModel):
    node_id: Optional[str] = None


class TaskCreateReq(BaseModel):
    name: str = "未命名扫描任务"
    targets: List[str] = Field(default_factory=lambda: ["192.168.1.1", "192.168.1.2"])
    scan_config: Dict[str, Any] = Field(default_factory=dict)
    schedule_config: Dict[str, Any] = Field(default_factory=dict)
    notification_config: Dict[str, Any] = Field(default_factory=dict)
    resource_config: Dict[str, Any] = Field(default_factory=dict)
    priority: int = 5


class TaskControlReq(BaseModel):
    action: str = "pause"   # pause/resume/cancel/retry/set_priority/adjust_resource
    priority: Optional[int] = None


class CompareReq(BaseModel):
    task_ids: List[str] = Field(default_factory=list)


class TemplateCreateReq(BaseModel):
    name: str = ""
    desc: str = ""
    scan_config: Dict[str, Any] = Field(default_factory=dict)


class ProxyAddReq(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    type: str = "http"
    username: str = ""
    password: str = ""
    group: str = "default"
    tags: Dict[str, str] = Field(default_factory=dict)


class ProxyPolicyReq(BaseModel):
    rotation_strategy: Optional[str] = None
    global_rps: Optional[float] = None
    per_proxy_rps: Optional[float] = None
    per_target_rps: Optional[float] = None
    min_score: Optional[float] = None


class ProxyAcquireReq(BaseModel):
    target: str = ""
    sticky_key: str = ""


class IncrementalReq(BaseModel):
    assets: List[Dict[str, Any]] = Field(default_factory=list)


class SnapshotTakeReq(BaseModel):
    name: str = ""


class SnapshotCompareReq(BaseModel):
    snapshot_a: str = ""
    snapshot_b: str = ""


class ShardReq(BaseModel):
    targets: List[str] = Field(default_factory=list)
    shard_size: int = 50


class QuotaReq(BaseModel):
    scope: str = "default"
    cpu_pct: Optional[float] = None
    mem_pct: Optional[float] = None
    disk_pct: Optional[float] = None
    net_mbps: Optional[float] = None
    max_conns: Optional[int] = None
    max_threads: Optional[int] = None


class IsolationReq(BaseModel):
    scope: str = "default"
    cgroup: Optional[bool] = None
    process_isolation: Optional[bool] = None
    network_isolation: Optional[bool] = None
    max_tasks_per_node: Optional[int] = None


class AlarmRuleReq(BaseModel):
    name: str = ""
    metric: str = "cpu_pct"
    threshold: float = 85.0
    level: str = "warning"


class SettingsReq(BaseModel):
    patch: Dict[str, Any] = Field(default_factory=dict)


# ==================== 1. 集群架构 / 节点 / 队列 ====================

@router.get("/cluster/overview")
def cluster_overview():
    try:
        return _ok(get_dashboard().overview())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/cluster/queue")
def cluster_queue():
    try:
        return _ok(get_cluster_state().queue_stats())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/cluster/nodes/register")
def node_register(req: NodeRegisterReq):
    try:
        return _ok(get_dashboard().node_register(
            req.node_id, req.capabilities, req.resources, req.tags, req.auth_token))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/cluster/nodes")
def node_list(online: bool = Query(False)):
    try:
        return _ok(get_cluster_state().list_nodes(only_online=online))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/cluster/nodes/{node_id}")
def node_detail(node_id: str):
    try:
        return _ok(get_dashboard().node_detail(node_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/cluster/nodes/{node_id}/heartbeat")
def node_heartbeat(node_id: str, req: HeartbeatReq):
    try:
        return _ok(get_dashboard().node_heartbeat(node_id, req.resources))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.delete("/cluster/nodes/{node_id}")
def node_remove(node_id: str):
    try:
        ok = get_dashboard().node_remove(node_id)
        return _ok({"removed": ok, "node_id": node_id})
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/cluster/schedule/strategy")
def set_strategy(req: StrategyReq):
    try:
        get_cluster_state().master["schedule_strategy"] = req.strategy
        return _ok({"strategy": req.strategy})
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/cluster/dispatch")
def dispatch_and_run(req: DispatchReq):
    try:
        return _ok(get_dashboard().dispatch_and_run(req.node_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/cluster/events")
def cluster_events(limit: int = Query(50)):
    try:
        return _ok(get_cluster_state().event_log[-limit:][::-1])
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


# ==================== 2. 任务管理 ====================

@router.post("/tasks")
def create_task(req: TaskCreateReq):
    try:
        return _ok(get_task_manager().create_scan_task(
            name=req.name, targets=req.targets,
            scan_config=req.scan_config, schedule_config=req.schedule_config,
            notification_config=req.notification_config,
            resource_config=req.resource_config, priority=req.priority))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/tasks")
def list_tasks(status: Optional[str] = Query(None),
               keyword: Optional[str] = Query(None)):
    try:
        return _ok(get_task_manager().list_tasks(status=status, keyword=keyword))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/tasks/{task_id}")
def task_detail(task_id: str):
    try:
        return _ok(get_task_manager().task_monitor(task_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/tasks/{task_id}/control")
def task_control(task_id: str, req: TaskControlReq):
    try:
        return _ok(get_task_manager().control_task(
            task_id, req.action, priority=req.priority))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/tasks/{task_id}/result")
def task_result(task_id: str):
    try:
        return _ok(get_cluster_state().aggregate_results(task_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/tasks/{task_id}/logs")
def task_logs(task_id: str, limit: int = Query(50)):
    try:
        return _ok(get_dashboard().task_logs(task_id, limit))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/tasks/history/list")
def task_history(limit: int = Query(50)):
    try:
        return _ok(get_task_manager().task_history(limit))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/tasks/search/list")
def task_search(keyword: str = Query("")):
    try:
        return _ok(get_task_manager().search_tasks(keyword))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/tasks/compare")
def task_compare(req: CompareReq):
    try:
        return _ok(get_task_manager().compare_tasks(req.task_ids))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/tasks/{task_id}/export")
def task_export(task_id: str):
    try:
        return _ok(get_task_manager().export_task(task_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/tasks/{task_id}/archive")
def task_archive(task_id: str):
    try:
        ok = get_task_manager().archive_task(task_id)
        return _ok({"archived": ok, "task_id": task_id})
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/archives")
def list_archives():
    try:
        return _ok(get_task_manager().list_archives())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/templates")
def list_templates():
    try:
        return _ok(get_task_manager().list_templates())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/templates")
def create_template(req: TemplateCreateReq):
    try:
        return _ok(get_task_manager().create_template(req.name, req.desc, req.scan_config))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/templates/{template_id}/share")
def share_template(template_id: str):
    try:
        return _ok(get_task_manager().share_template(template_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


# ==================== 3. 代理池 ====================

@router.get("/proxy/pool")
def proxy_stats():
    try:
        return _ok(get_proxy_pool().pool_stats())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/proxy/list")
def proxy_list(group: Optional[str] = Query(None),
               status: Optional[str] = Query(None)):
    try:
        return _ok(get_proxy_pool().list_proxies(group=group, status=status))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/proxy/add")
def proxy_add(req: ProxyAddReq):
    try:
        return _ok(get_proxy_pool().add_proxy(
            req.host, req.port, req.type, req.username, req.password,
            req.group, req.tags))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.delete("/proxy/{proxy_id}")
def proxy_remove(proxy_id: str):
    try:
        ok = get_proxy_pool().remove_proxy(proxy_id)
        return _ok({"removed": ok, "proxy_id": proxy_id})
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/proxy/{proxy_id}/detect")
def proxy_detect(proxy_id: str):
    try:
        return _ok(get_proxy_pool().detect_proxy(proxy_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/proxy/health-check")
def proxy_health_check():
    try:
        return _ok(get_proxy_pool().health_check_all())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/proxy/policy")
def proxy_policy(req: ProxyPolicyReq):
    try:
        kw = {k: v for k, v in req.model_dump().items() if v is not None}
        return _ok(get_proxy_pool().set_policy(**kw))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/proxy/groups")
def proxy_groups():
    try:
        return _ok(get_proxy_pool().groups)
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/proxy/anti-detect")
def proxy_anti_detect():
    try:
        return _ok({"headers": get_proxy_pool().build_anti_detect_headers()})
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/proxy/acquire")
def proxy_acquire(req: ProxyAcquireReq):
    try:
        return _ok(get_proxy_pool().acquire_proxy(req.target, req.sticky_key))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


# ==================== 4. 断点续扫 / 增量 / 快照 / 分片 / 缓存 ====================

@router.post("/tasks/{task_id}/snapshot/save")
def save_state(task_id: str):
    try:
        return _ok(get_resume_manager().save_state(task_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/tasks/{task_id}/resume")
def resume_task(task_id: str):
    try:
        return _ok(get_resume_manager().recover_task(task_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/incremental/diff")
def incremental_diff(req: IncrementalReq):
    try:
        return _ok(get_resume_manager().incremental_diff(req.assets))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/snapshots/take")
def take_snapshot(task_id: str = Query(...), req: SnapshotTakeReq = SnapshotTakeReq()):
    try:
        return _ok(get_resume_manager().take_snapshot(task_id, req.name))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/snapshots")
def list_snapshots(task_id: Optional[str] = Query(None)):
    try:
        return _ok(get_resume_manager().list_snapshots(task_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/snapshots/{snapshot_id}/rollback")
def rollback_snapshot(snapshot_id: str):
    try:
        return _ok(get_resume_manager().rollback_snapshot(snapshot_id))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/snapshots/compare")
def compare_snapshots(req: SnapshotCompareReq):
    try:
        return _ok(get_resume_manager().compare_snapshots(req.snapshot_a, req.snapshot_b))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/shards")
def shard_targets(req: ShardReq):
    try:
        return _ok(get_resume_manager().shard_targets(req.targets, req.shard_size))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/shards/stats")
def shard_stats():
    try:
        return _ok(get_resume_manager().shard_stats())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/cache/stats")
def cache_stats():
    try:
        return _ok(get_resume_manager().cache_stats())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


# ==================== 5. 资源管理 ====================

@router.get("/resource/realtime")
def resource_realtime():
    try:
        return _ok(get_resource_manager().realtime_metrics())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/resource/trend")
def resource_trend(points: int = Query(30)):
    try:
        return _ok(get_resource_manager().metric_history[-points:])
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/resource/quota")
def set_quota(req: QuotaReq):
    try:
        kw = {k: v for k, v in req.model_dump().items()
              if k != "scope" and v is not None}
        return _ok(get_resource_manager().set_quota(req.scope, **kw))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/resource/quota")
def list_quota():
    try:
        return _ok(get_resource_manager().list_quota())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/resource/schedule-decision")
def schedule_decision():
    try:
        return _ok(get_resource_manager().schedule_decision())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/resource/isolation")
def set_isolation(req: IsolationReq):
    try:
        kw = {k: v for k, v in req.model_dump().items()
              if k != "scope" and v is not None}
        return _ok(get_resource_manager().set_isolation(req.scope, **kw))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/resource/alarms")
def list_alarms(level: Optional[str] = Query(None), limit: int = Query(50)):
    try:
        return _ok(get_resource_manager().list_alarms(level=level, limit=limit))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.post("/resource/alarm-rules")
def add_alarm_rule(req: AlarmRuleReq):
    try:
        return _ok(get_resource_manager().add_alarm_rule(
            req.name, req.metric, req.threshold, req.level))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/resource/alarm-stats")
def alarm_stats():
    try:
        return _ok(get_dashboard().alarm_stats())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/resource/report")
def resource_report():
    try:
        return _ok(get_resource_manager().resource_report())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


# ==================== 6. 控制台 / 系统设置 ====================

@router.get("/settings")
def get_settings():
    try:
        return _ok(get_dashboard().get_settings())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.put("/settings")
def update_settings(req: SettingsReq):
    try:
        return _ok(get_dashboard().update_settings(req.patch))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/audit")
def list_audit(limit: int = 50):
    try:
        return _ok(get_dashboard().list_audit(limit))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/alarm/rules")
def list_alarm_rules():
    try:
        return _ok(get_dashboard().alarm_rules())
    except Exception as e:  # pragma: no cover
        return _fail(str(e))


@router.get("/monitor/trend")
def monitor_trend(points: int = Query(30)):
    try:
        return _ok(get_dashboard().monitoring_trend(points))
    except Exception as e:  # pragma: no cover
        return _fail(str(e))
