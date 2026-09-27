#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式扫描API路由模块，提供任务调度、工作节点管理、结果汇总、代理池管理等分布式功能的REST API接口。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from datetime import datetime

router = APIRouter(prefix="/api/v1/distributed", tags=["分布式扫描"])


# ========== 请求模型 ==========

class TaskSubmitRequest(BaseModel):
    """TaskSubmitRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    task_type: str
    payload: Dict[str, Any]
    priority: int = 5
    max_retries: int = 3
    timeout: int = 300
    dependencies: List[str] = None
    tags: List[str] = None


class WorkerRegisterRequest(BaseModel):
    """WorkerRegisterRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    hostname: str
    ip: str
    port: int
    capabilities: List[str] = None
    max_tasks: int = 10


class WorkerHeartbeatRequest(BaseModel):
    """WorkerHeartbeatRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    worker_id: str
    cpu_usage: float = 0
    memory_usage: float = 0
    current_tasks: int = 0


class ProxyAddRequest(BaseModel):
    """ProxyAddRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    host: str
    port: int
    proxy_type: str = "http"  # http, https, socks4, socks5
    username: str = ""
    password: str = ""
    country: str = ""


class ResultAggregationRequest(BaseModel):
    """ResultAggregationRequest类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    task_id: str
    worker_id: str
    scan_data: Dict[str, Any]


# ========== 任务调度路由 ==========

@router.post("/tasks/submit", summary="提交分布式任务")
async def submit_task(request: TaskSubmitRequest):
    """提交分布式扫描任务"""
    try:
        from distributed.scheduler import distributed_scheduler
        task_id = distributed_scheduler.submit_task(
            task_type=request.task_type,
            payload=request.payload,
            priority=request.priority,
            max_retries=request.max_retries,
            timeout=request.timeout,
            dependencies=request.dependencies,
            tags=request.tags,
        )
        return {
            "status": "success",
            "task_id": task_id,
            "task_type": request.task_type,
            "priority": request.priority,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks", summary="列出所有任务")
async def list_tasks(status: str = ""):
    """列出所有分布式任务"""
    from distributed.scheduler import distributed_scheduler
    tasks = distributed_scheduler.tasks
    task_list = []
    for task_id, task in tasks.items():
        if status and task.status.value != status:
            continue
        task_list.append({
            "task_id": task.task_id,
            "task_type": task.task_type,
            "status": task.status.value,
            "priority": task.priority,
            "assigned_worker": task.assigned_worker,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
            "retries": task.retries,
            "error": task.error,
        })
    return {
        "tasks": task_list,
        "total": len(task_list),
    }


@router.get("/tasks/{task_id}", summary="获取任务详情")
async def get_task(task_id: str):
    """获取指定任务的详细信息"""
    from distributed.scheduler import distributed_scheduler
    task = distributed_scheduler.tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")
    return {
        "task_id": task.task_id,
        "task_type": task.task_type,
        "payload": task.payload,
        "status": task.status.value,
        "priority": task.priority,
        "assigned_worker": task.assigned_worker,
        "created_at": task.created_at,
        "started_at": task.started_at,
        "completed_at": task.completed_at,
        "result": task.result,
        "error": task.error,
        "retries": task.retries,
        "max_retries": task.max_retries,
        "timeout": task.timeout,
        "dependencies": task.dependencies,
        "tags": task.tags,
    }


@router.post("/tasks/{task_id}/cancel", summary="取消任务")
async def cancel_task(task_id: str):
    """取消指定任务"""
    from distributed.scheduler import distributed_scheduler
    task = distributed_scheduler.tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")
    from distributed.scheduler import TaskStatus
    task.status = TaskStatus.CANCELLED
    return {
        "status": "success",
        "task_id": task_id,
        "message": "任务已取消",
    }


# ========== 工作节点路由 ==========

@router.post("/workers/register", summary="注册工作节点")
async def register_worker(request: WorkerRegisterRequest):
    """注册新的工作节点"""
    try:
        from distributed.worker_node import worker_manager
        from internal.port_forward import WorkerNode
        worker = WorkerNode(
            name=request.hostname,
            ip_address=request.ip,
            port=request.port,
            capabilities=request.capabilities or ["*"],
            max_concurrent_tasks=request.max_tasks,
        )
        worker_manager.register_worker(worker)
        return {
            "status": "success",
            "worker_id": worker.worker_id,
            "hostname": request.hostname,
            "ip": request.ip,
            "port": request.port,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/workers/heartbeat", summary="工作节点心跳")
async def worker_heartbeat(request: WorkerHeartbeatRequest):
    """工作节点心跳上报"""
    try:
        from distributed.worker_node import worker_manager, WorkerHeartbeat, WorkerStatus
        heartbeat = WorkerHeartbeat(
            worker_id=request.worker_id,
            status=WorkerStatus.BUSY if request.current_tasks > 0 else WorkerStatus.IDLE,
            cpu_usage=request.cpu_usage,
            memory_usage=request.memory_usage,
            active_tasks=request.current_tasks,
        )
        success = worker_manager.receive_heartbeat(heartbeat)
        return {
            "status": "success" if success else "failed",
            "worker_id": request.worker_id,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/workers", summary="列出工作节点")
async def list_workers(status: str = ""):
    """列出所有工作节点"""
    from distributed.worker_node import worker_manager
    workers = worker_manager.list_workers(status)
    return {
        "workers": [w.to_dict() for w in workers],
        "total": len(workers),
    }


@router.get("/workers/stats", summary="工作节点统计")
async def worker_stats():
    """获取工作节点统计信息"""
    from distributed.worker_node import worker_manager
    return worker_manager.get_statistics()


@router.delete("/workers/{worker_id}", summary="注销工作节点")
async def unregister_worker(worker_id: str):
    """注销指定工作节点"""
    from distributed.worker_node import worker_manager
    success = worker_manager.unregister_worker(worker_id)
    return {
        "status": "success" if success else "failed",
        "worker_id": worker_id,
    }


# ========== 结果汇总路由 ==========

@router.post("/results/aggregate", summary="汇总扫描结果")
async def aggregate_result(request: ResultAggregationRequest):
    """汇总工作节点的扫描结果"""
    try:
        from distributed.result_aggregator import result_aggregator
        if request.task_id not in result_aggregator.results:
            result_aggregator.start_aggregation(request.task_id, request.scan_data.get("target", "unknown"))
        success = result_aggregator.add_scan_result(
            task_id=request.task_id,
            worker_id=request.worker_id,
            scan_data=request.scan_data,
        )
        return {
            "status": "success" if success else "failed",
            "task_id": request.task_id,
            "worker_id": request.worker_id,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results/{task_id}", summary="获取汇总结果")
async def get_aggregated_result(task_id: str):
    """获取指定任务的汇总结果"""
    from distributed.result_aggregator import result_aggregator
    result = result_aggregator.get_result(task_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 的结果不存在")
    return {
        "task_id": task_id,
        "result": result.to_dict(),
    }


@router.get("/results/{task_id}/summary", summary="获取漏洞摘要")
async def get_vulnerability_summary(task_id: str):
    """获取指定任务的漏洞摘要"""
    from distributed.result_aggregator import result_aggregator
    summary = result_aggregator.get_vulnerability_summary(task_id)
    if not summary:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 的结果不存在")
    return summary


@router.get("/results/{task_id}/worker-contributions", summary="获取工作节点贡献")
async def get_worker_contributions(task_id: str):
    """获取各工作节点的贡献统计"""
    from distributed.result_aggregator import result_aggregator
    return result_aggregator.get_worker_contributions(task_id)


@router.get("/results/stats", summary="汇总统计")
async def aggregation_stats():
    """获取结果汇总统计信息"""
    from distributed.result_aggregator import result_aggregator
    return result_aggregator.get_statistics()


# ========== 代理池路由 ==========

@router.post("/proxies/add", summary="添加代理")
async def add_proxy(request: ProxyAddRequest):
    """添加代理到代理池"""
    try:
        from distributed.proxy_pool import proxy_pool, ProxyServer
        proxy = ProxyServer(
            host=request.host,
            port=request.port,
            proxy_type=request.proxy_type,
            username=request.username,
            password=request.password,
            country=request.country,
        )
        success = proxy_pool.add_proxy(proxy)
        return {
            "status": "success" if success else "failed",
            "proxy": f"{request.host}:{request.port}",
            "proxy_type": request.proxy_type,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/proxies", summary="列出代理")
async def list_proxies(proxy_type: str = "", country: str = ""):
    """列出代理池中的代理"""
    from distributed.proxy_pool import proxy_pool
    if proxy_type:
        proxies = proxy_pool.get_proxies_by_type(proxy_type)
    elif country:
        proxies = proxy_pool.get_proxies_by_country(country)
    else:
        proxies = proxy_pool.list_sessions() if hasattr(proxy_pool, 'list_sessions') else proxy_pool.proxies
    return {
        "proxies": [p.to_dict() for p in proxies] if hasattr(proxies, '__iter__') else [],
        "total": len(proxies) if hasattr(proxies, '__len__') else 0,
    }


@router.get("/proxies/get", summary="获取可用代理")
async def get_proxy(target: str = "", strategy: str = ""):
    """获取一个可用代理"""
    from distributed.proxy_pool import proxy_pool
    proxy = proxy_pool.get_proxy(target, strategy)
    if not proxy:
        raise HTTPException(status_code=404, detail="没有可用的代理")
    return {
        "proxy": proxy.get_url(),
        "host": proxy.host,
        "port": proxy.port,
        "proxy_type": proxy.proxy_type,
        "country": proxy.country,
        "latency": proxy.latency,
        "success_rate": proxy.success_rate,
    }


@router.get("/proxies/stats", summary="代理池统计")
async def proxy_stats():
    """获取代理池统计信息"""
    from distributed.proxy_pool import proxy_pool
    return proxy_pool.get_statistics()


@router.delete("/proxies/{host}/{port}", summary="移除代理")
async def remove_proxy(host: str, port: int):
    """从代理池移除指定代理"""
    from distributed.proxy_pool import proxy_pool
    success = proxy_pool.remove_proxy(host, port)
    return {
        "status": "success" if success else "failed",
        "proxy": f"{host}:{port}",
    }


# ========== 分布式扫描总览路由 ==========

@router.get("/overview", summary="分布式扫描模块总览")
async def distributed_overview():
    """获取分布式扫描模块总览信息"""
    from distributed.worker_node import worker_manager
    from distributed.result_aggregator import result_aggregator
    from distributed.proxy_pool import proxy_pool

    worker_stats = worker_manager.get_statistics()
    result_stats = result_aggregator.get_statistics()
    proxy_stats = proxy_pool.get_statistics()

    return {
        "module": "分布式扫描",
        "version": "1.0.0",
        "capabilities": {
            "task_scheduling": "任务调度（优先级队列/依赖管理/失败转移/负载均衡）",
            "worker_management": "工作节点管理（注册/心跳/负载均衡/离线检测）",
            "result_aggregation": "结果汇总（多节点结果合并/漏洞去重/风险评分）",
            "proxy_pool": "代理池（5种轮换策略/健康检查/自动状态更新）",
        },
        "workers": worker_stats,
        "results": result_stats,
        "proxies": proxy_stats,
        "api_endpoints": 22,
        "timestamp": datetime.now().isoformat(),
    }
