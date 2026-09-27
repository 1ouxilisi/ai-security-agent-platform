"""
分布式任务调度器模块，支持优先级队列、依赖管理、失败转移、负载均衡和任务监控。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import json
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from utils.logger import log


class WorkerStatus(Enum):
    """WorkerStatus类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    ONLINE = "online"
    BUSY = "busy"
    OFFLINE = "offline"
    DRAINING = "draining"  # 排空中，不接受新任务


class TaskStatus(Enum):
    """TaskStatus类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    PENDING = "pending"
    QUEUED = "queued"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


@dataclass
class WorkerNode:
    """Worker节点"""
    worker_id: str
    hostname: str
    ip: str
    port: int
    status: WorkerStatus = WorkerStatus.ONLINE
    capabilities: List[str] = field(default_factory=lambda: ["*"])  # 支持的任务类型
    current_tasks: int = 0
    max_tasks: int = 10
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    registered_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    tasks_completed: int = 0
    tasks_failed: int = 0


@dataclass
class DistributedTask:
    """分布式任务"""
    task_id: str
    task_type: str
    payload: Dict[str, Any]
    priority: int = 5  # 1-10，10最高
    status: TaskStatus = TaskStatus.PENDING
    assigned_worker: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Any = None
    error: Optional[str] = None
    retries: int = 0
    max_retries: int = 3
    timeout: int = 300  # 秒
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


class DistributedScheduler:
    """分布式调度器（Master节点）"""

    def __init__(self, heartbeat_timeout: int = 30, load_balancer: str = "least_connections"):
        """初始化DistributedScheduler实例。

        Args:
            self: 类实例。
        """
        self.workers: Dict[str, WorkerNode] = {}
        self.task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.tasks: Dict[str, DistributedTask] = {}
        self.heartbeat_timeout = heartbeat_timeout
        self.load_balancer = load_balancer  # round_robin / least_connections / cpu_aware
        self._round_robin_index = 0
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        log.info(f"分布式调度器初始化，负载均衡: {load_balancer}, 心跳超时: {heartbeat_timeout}s")

    def register_worker(self, hostname: str, ip: str, port: int,
                        capabilities: List[str] = None, max_tasks: int = 10) -> str:
        """注册Worker节点"""
        worker_id = f"worker-{uuid.uuid4().hex[:8]}"
        worker = WorkerNode(
            worker_id=worker_id, hostname=hostname, ip=ip, port=port,
            capabilities=capabilities or ["*"], max_tasks=max_tasks,
        )
        self.workers[worker_id] = worker
        log.info(f"Worker已注册: {worker_id} ({hostname}:{port}), 能力: {capabilities}")
        return worker_id

    def unregister_worker(self, worker_id: str):
        """注销Worker节点"""
        if worker_id in self.workers:
            # 重分配该Worker的任务
            self._reassign_worker_tasks(worker_id)
            del self.workers[worker_id]
            log.info(f"Worker已注销: {worker_id}")

    def heartbeat(self, worker_id: str, cpu_usage: float = 0, memory_usage: float = 0,
                  current_tasks: int = 0) -> bool:
        """Worker心跳"""
        if worker_id not in self.workers:
            return False
        worker = self.workers[worker_id]
        worker.last_heartbeat = time.time()
        worker.cpu_usage = cpu_usage
        worker.memory_usage = memory_usage
        worker.current_tasks = current_tasks
        if worker.status == WorkerStatus.OFFLINE:
            worker.status = WorkerStatus.ONLINE
        return True

    def submit_task(self, task_type: str, payload: Dict, priority: int = 5,
                    max_retries: int = 3, timeout: int = 300,
                    dependencies: List[str] = None, tags: List[str] = None) -> str:
        """提交任务"""
        task_id = f"task-{uuid.uuid4().hex[:8]}"
        task = DistributedTask(
            task_id=task_id, task_type=task_type, payload=payload,
            priority=priority, max_retries=max_retries, timeout=timeout,
            dependencies=dependencies or [], tags=tags or [],
        )
        self.tasks[task_id] = task
        self.task_queue.put_nowait((-priority, task_id, task))
        log.info(f"任务已提交: {task_id} (类型: {task_type}, 优先级: {priority})")
        return task_id

    def _select_worker(self, task: DistributedTask) -> Optional[WorkerNode]:
        """选择Worker（负载均衡）"""
        available_workers = [
            w for w in self.workers.values()
            if w.status in [WorkerStatus.ONLINE, WorkerStatus.BUSY]
            and w.current_tasks < w.max_tasks
            and ("*" in w.capabilities or task.task_type in w.capabilities)
        ]

        if not available_workers:
            return None

        if self.load_balancer == "round_robin":
            worker = available_workers[self._round_robin_index % len(available_workers)]
            self._round_robin_index += 1
            return worker

        elif self.load_balancer == "least_connections":
            return min(available_workers, key=lambda w: w.current_tasks)

        elif self.load_balancer == "cpu_aware":
            return min(available_workers, key=lambda w: (w.cpu_usage, w.current_tasks))

        return available_workers[0]

    async def _dispatch_loop(self):
        """任务分发循环"""
        while self._running:
            try:
                if self.task_queue.empty():
                    await asyncio.sleep(0.5)
                    continue

                # 检查依赖
                _, task_id, task = await self.task_queue.get()
                deps_met = all(
                    self.tasks.get(dep) and self.tasks[dep].status == TaskStatus.COMPLETED
                    for dep in task.dependencies
                )

                if not deps_met:
                    # 依赖未满足，重新入队
                    self.task_queue.put_nowait((-task.priority, task_id, task))
                    await asyncio.sleep(1)
                    continue

                # 选择Worker
                worker = self._select_worker(task)
                if not worker:
                    # 无可用Worker，重新入队
                    self.task_queue.put_nowait((-task.priority, task_id, task))
                    await asyncio.sleep(2)
                    continue

                # 分发任务
                task.status = TaskStatus.DISPATCHED
                task.assigned_worker = worker.worker_id
                task.started_at = time.time()
                worker.current_tasks += 1
                log.info(f"任务已分发: {task_id} -> {worker.worker_id}")

                # 模拟执行（实际应通过网络调用Worker）
                asyncio.create_task(self._execute_task(task, worker))

            except Exception as e:
                log.error(f"分发循环错误: {e}")
                await asyncio.sleep(1)

    async def _execute_task(self, task: DistributedTask, worker: WorkerNode):
        """执行任务（模拟）"""
        try:
            task.status = TaskStatus.RUNNING
            # 实际应通过HTTP/gRPC调用Worker执行
            await asyncio.sleep(0.1)  # 模拟网络延迟

            # 这里应调用Worker的执行接口
            # result = await self._call_worker(worker, task)

            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
            task.result = {"status": "completed", "worker": worker.worker_id}
            worker.tasks_completed += 1
            log.info(f"任务完成: {task.task_id}")

        except Exception as e:
            task.error = str(e)
            if task.retries < task.max_retries:
                task.retries += 1
                task.status = TaskStatus.RETRYING
                self.task_queue.put_nowait((-task.priority, task.task_id, task))
                log.warning(f"任务失败，重试 {task.retries}/{task.max_retries}: {task.task_id}")
            else:
                task.status = TaskStatus.FAILED
                worker.tasks_failed += 1
                log.error(f"任务最终失败: {task.task_id} - {e}")
        finally:
            worker.current_tasks = max(0, worker.current_tasks - 1)

    def _reassign_worker_tasks(self, worker_id: str):
        """重分配Worker的任务"""
        for task in self.tasks.values():
            if task.assigned_worker == worker_id and task.status in [TaskStatus.DISPATCHED, TaskStatus.RUNNING]:
                task.status = TaskStatus.PENDING
                task.assigned_worker = None
                self.task_queue.put_nowait((-task.priority, task.task_id, task))
                log.info(f"任务已重分配: {task.task_id} (原Worker: {worker_id})")

    async def _monitor_workers(self):
        """监控Worker心跳"""
        while self._running:
            try:
                now = time.time()
                for worker_id, worker in list(self.workers.items()):
                    if now - worker.last_heartbeat > self.heartbeat_timeout:
                        if worker.status != WorkerStatus.OFFLINE:
                            worker.status = WorkerStatus.OFFLINE
                            log.warning(f"Worker离线: {worker_id} (最后心跳: {now - worker.last_heartbeat:.0f}s前)")
                            self._reassign_worker_tasks(worker_id)
                await asyncio.sleep(5)
            except Exception as e:
                log.error(f"Worker监控错误: {e}")
                await asyncio.sleep(5)

    async def start(self):
        """启动调度器"""
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_workers())
        asyncio.create_task(self._dispatch_loop())
        log.info("分布式调度器已启动")

    async def stop(self):
        """停止调度器"""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
        log.info("分布式调度器已停止")

    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """获取任务状态"""
        task = self.tasks.get(task_id)
        if not task:
            return None
        return {
            "task_id": task.task_id, "task_type": task.task_type,
            "status": task.status.value, "assigned_worker": task.assigned_worker,
            "priority": task.priority, "retries": task.retries,
            "created_at": task.created_at, "started_at": task.started_at,
            "completed_at": task.completed_at, "error": task.error,
        }

    def get_worker_stats(self) -> Dict:
        """获取Worker统计"""
        online = sum(1 for w in self.workers.values() if w.status != WorkerStatus.OFFLINE)
        total_tasks = sum(w.tasks_completed for w in self.workers.values())
        total_failed = sum(w.tasks_failed for w in self.workers.values())
        return {
            "total_workers": len(self.workers),
            "online_workers": online,
            "offline_workers": len(self.workers) - online,
            "total_tasks_completed": total_tasks,
            "total_tasks_failed": total_failed,
            "pending_tasks": self.task_queue.qsize(),
            "workers": [
                {"id": w.worker_id, "hostname": w.hostname, "status": w.status.value,
                 "current_tasks": w.current_tasks, "max_tasks": w.max_tasks,
                 "cpu": w.cpu_usage, "memory": w.memory_usage,
                 "completed": w.tasks_completed, "failed": w.tasks_failed}
                for w in self.workers.values()
            ],
        }


class WorkerNodeRunner:
    """Worker节点运行器"""

    def __init__(self, scheduler: DistributedScheduler, worker_id: str):
        """初始化WorkerNodeRunner实例。

        Args:
            self: 类实例。
        """
        self.scheduler = scheduler
        self.worker_id = worker_id
        self._running = False

    async def start(self):
        """启动Worker（模拟）"""
        self._running = True
        log.info(f"Worker启动: {self.worker_id}")
        # 实际应启动HTTP/gRPC服务接收任务
        while self._running:
            await asyncio.sleep(1)

    async def stop(self):
        """停止Worker"""
        self._running = False
        log.info(f"Worker停止: {self.worker_id}")


# 全局分布式调度器实例
distributed_scheduler = DistributedScheduler()
