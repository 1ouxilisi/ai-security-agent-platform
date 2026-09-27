"""
分布式扫描架构
- 任务分发（大任务拆分成小任务）
- 节点管理（注册/注销/心跳）
- 任务队列（待处理任务管理）
- 结果聚合（收集合并扫描结果）
- 负载均衡（根据节点负载分配任务）
- 失败重试（任务失败自动重试）

这是一个框架实现，节点间通信基于HTTP API。
"""

import json
import os
import time
import uuid
import threading
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue


class NodeStatus(Enum):
    """节点状态"""
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    IDLE = "idle"
    ERROR = "error"


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"


@dataclass
class ScanNode:
    """扫描节点"""
    node_id: str
    name: str
    endpoint: str  # HTTP API端点
    status: str = NodeStatus.IDLE.value
    capacity: int = 10  # 最大并发任务数
    current_load: int = 0  # 当前负载
    registered_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    avg_response_time: float = 0.0
    capabilities: List[str] = field(default_factory=list)  # 支持的扫描类型


@dataclass
class ScanTask:
    """扫描任务"""
    task_id: str
    job_id: str  # 所属的大任务ID
    target: str
    scan_type: str  # port_scan/vuln_scan/dir_scan等
    parameters: Dict = field(default_factory=dict)
    status: str = TaskStatus.PENDING.value
    assigned_node: Optional[str] = None
    result: Optional[Dict] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retries: int = 0
    max_retries: int = 3
    priority: int = 0  # 优先级，数字越大优先级越高


@dataclass
class ScanJob:
    """扫描作业（大任务，包含多个子任务）"""
    job_id: str
    name: str
    targets: List[str]
    scan_types: List[str]
    parameters: Dict = field(default_factory=dict)
    status: str = TaskStatus.PENDING.value
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    results: Dict = field(default_factory=dict)
    callback_url: Optional[str] = None


class DistributedScanner:
    """分布式扫描器"""

    def __init__(self, max_workers: int = 10):
        self.nodes: Dict[str, ScanNode] = {}
        self.tasks: Dict[str, ScanTask] = {}
        self.jobs: Dict[str, ScanJob] = {}
        self.task_queue: queue.PriorityQueue = queue.PriorityQueue()
        self.max_workers = max_workers
        self._lock = threading.Lock()
        self._running = False
        self._dispatcher_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._local_executor: Optional[ThreadPoolExecutor] = None

        # 本地执行函数（用于单节点模式）
        self.local_executors: Dict[str, Callable] = {}

    def register_local_executor(self, scan_type: str, func: Callable):
        """注册本地执行函数（单节点模式下使用）"""
        self.local_executors[scan_type] = func

    def register_node(self, node_id: str, name: str, endpoint: str, capacity: int = 10, capabilities: List[str] = None) -> ScanNode:
        """注册扫描节点"""
        with self._lock:
            node = ScanNode(
                node_id=node_id,
                name=name,
                endpoint=endpoint,
                capacity=capacity,
                capabilities=capabilities or [],
            )
            self.nodes[node_id] = node
            return node

    def unregister_node(self, node_id: str):
        """注销扫描节点"""
        with self._lock:
            if node_id in self.nodes:
                del self.nodes[node_id]
                # 将该节点的任务重新加入队列
                for task in self.tasks.values():
                    if task.assigned_node == node_id and task.status in [TaskStatus.ASSIGNED.value, TaskStatus.RUNNING.value]:
                        task.status = TaskStatus.PENDING.value
                        task.assigned_node = None
                        self.task_queue.put((-task.priority, task.task_id))

    def heartbeat(self, node_id: str, load: int = 0, status: str = None):
        """节点心跳"""
        with self._lock:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                node.last_heartbeat = time.time()
                node.current_load = load
                if status:
                    node.status = status

    def _check_node_health(self):
        """检查节点健康状态（后台线程）"""
        while self._running:
            with self._lock:
                now = time.time()
                for node_id, node in list(self.nodes.items()):
                    if now - node.last_heartbeat > 30:  # 30秒无心跳视为离线
                        node.status = NodeStatus.OFFLINE.value
                        # 重新分配任务
                        for task in self.tasks.values():
                            if task.assigned_node == node_id and task.status in [TaskStatus.ASSIGNED.value, TaskStatus.RUNNING.value]:
                                task.status = TaskStatus.PENDING.value
                                task.assigned_node = None
                                self.task_queue.put((-task.priority, task.task_id))
            time.sleep(10)

    def create_job(self, name: str, targets: List[str], scan_types: List[str], parameters: Dict = None) -> str:
        """创建扫描作业（自动拆分成子任务）"""
        job_id = f"job_{uuid.uuid4().hex[:12]}"
        job = ScanJob(
            job_id=job_id,
            name=name,
            targets=targets,
            scan_types=scan_types,
            parameters=parameters or {},
        )

        # 拆分任务：每个目标 × 每种扫描类型 = 一个子任务
        tasks = []
        for target in targets:
            for scan_type in scan_types:
                task_id = f"task_{uuid.uuid4().hex[:12]}"
                task = ScanTask(
                    task_id=task_id,
                    job_id=job_id,
                    target=target,
                    scan_type=scan_type,
                    parameters=parameters or {},
                )
                self.tasks[task_id] = task
                tasks.append(task)
                self.task_queue.put((-task.priority, task_id))

        job.total_tasks = len(tasks)
        self.jobs[job_id] = job

        return job_id

    def _dispatch_tasks(self):
        """任务分发（后台线程）"""
        while self._running:
            try:
                # 从队列获取任务
                priority, task_id = self.task_queue.get(timeout=1)

                with self._lock:
                    task = self.tasks.get(task_id)
                    if not task or task.status != TaskStatus.PENDING.value:
                        continue

                    # 选择最合适的节点（负载最低且支持该扫描类型）
                    best_node = None
                    min_load = float('inf')

                    for node in self.nodes.values():
                        if node.status in [NodeStatus.ONLINE.value, NodeStatus.IDLE.value]:
                            if not node.capabilities or task.scan_type in node.capabilities:
                                if node.current_load < node.capacity and node.current_load < min_load:
                                    best_node = node
                                    min_load = node.current_load

                    if best_node:
                        # 分配任务
                        task.assigned_node = best_node.node_id
                        task.status = TaskStatus.ASSIGNED.value
                        best_node.current_load += 1
                        best_node.total_tasks += 1

                        # 异步执行任务
                        threading.Thread(target=self._execute_task, args=(task, best_node), daemon=True).start()
                    else:
                        # 没有可用节点，重新加入队列
                        self.task_queue.put((-task.priority, task_id))
                        time.sleep(1)

            except queue.Empty:
                continue
            except Exception as e:
                print(f"任务分发错误: {e}")
                time.sleep(1)

    def _execute_task(self, task: ScanTask, node: ScanNode):
        """执行任务"""
        task.status = TaskStatus.RUNNING.value
        task.started_at = time.time()

        try:
            result = None

            # 优先使用本地执行函数
            if task.scan_type in self.local_executors:
                func = self.local_executors[task.scan_type]
                result = func(target=task.target, **task.parameters)
            else:
                # 通过HTTP API调用远程节点
                result = self._call_remote_node(node, task)

            task.result = result
            task.status = TaskStatus.COMPLETED.value
            node.completed_tasks += 1

        except Exception as e:
            task.error = str(e)
            task.status = TaskStatus.FAILED.value
            node.failed_tasks += 1

            # 失败重试
            if task.retries < task.max_retries:
                task.retries += 1
                task.status = TaskStatus.RETRYING.value
                self.task_queue.put((-task.priority, task.task_id))

        finally:
            task.completed_at = time.time()
            node.current_load = max(0, node.current_load - 1)

            # 更新作业进度
            self._update_job_progress(task.job_id)

    def _call_remote_node(self, node: ScanNode, task: ScanTask) -> Dict:
        """调用远程节点执行任务"""
        import urllib.request

        url = f"{node.endpoint}/api/v1/scan/execute"
        payload = json.dumps({
            "task_id": task.task_id,
            "target": task.target,
            "scan_type": task.scan_type,
            "parameters": task.parameters,
        }).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())

    def _update_job_progress(self, job_id: str):
        """更新作业进度"""
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return

            completed = 0
            failed = 0
            results = {}

            for task in self.tasks.values():
                if task.job_id == job_id:
                    if task.status == TaskStatus.COMPLETED.value:
                        completed += 1
                        if task.result:
                            results[task.task_id] = task.result
                    elif task.status == TaskStatus.FAILED.value:
                        failed += 1

            job.completed_tasks = completed
            job.failed_tasks = failed
            job.results = results

            if completed + failed >= job.total_tasks:
                job.status = TaskStatus.COMPLETED.value
                job.completed_at = time.time()

    def start(self):
        """启动分布式扫描器"""
        if self._running:
            return

        self._running = True
        self._local_executor = ThreadPoolExecutor(max_workers=self.max_workers)

        # 启动任务分发线程
        self._dispatcher_thread = threading.Thread(target=self._dispatch_tasks, daemon=True)
        self._dispatcher_thread.start()

        # 启动节点健康检查线程
        self._heartbeat_thread = threading.Thread(target=self._check_node_health, daemon=True)
        self._heartbeat_thread.start()

    def stop(self):
        """停止分布式扫描器"""
        self._running = False
        if self._local_executor:
            self._local_executor.shutdown(wait=False)

    def get_job_status(self, job_id: str) -> Optional[Dict]:
        """获取作业状态"""
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return None

            return {
                "job_id": job.job_id,
                "name": job.name,
                "status": job.status,
                "total_tasks": job.total_tasks,
                "completed_tasks": job.completed_tasks,
                "failed_tasks": job.failed_tasks,
                "progress": round(job.completed_tasks / job.total_tasks * 100, 1) if job.total_tasks > 0 else 0,
                "created_at": job.created_at,
                "started_at": job.started_at,
                "completed_at": job.completed_at,
                "duration": round((job.completed_at or time.time()) - job.created_at, 2),
            }

    def get_job_results(self, job_id: str) -> Optional[Dict]:
        """获取作业结果"""
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return None

            # 聚合结果
            aggregated = {
                "job_id": job.job_id,
                "name": job.name,
                "targets": job.targets,
                "scan_types": job.scan_types,
                "summary": {
                    "total_targets": len(job.targets),
                    "total_scan_types": len(job.scan_types),
                    "total_tasks": job.total_tasks,
                    "completed": job.completed_tasks,
                    "failed": job.failed_tasks,
                },
                "results_by_target": {},
                "results_by_type": {},
            }

            for task_id, result in job.results.items():
                task = self.tasks.get(task_id)
                if task:
                    # 按目标分组
                    if task.target not in aggregated["results_by_target"]:
                        aggregated["results_by_target"][task.target] = {}
                    aggregated["results_by_target"][task.target][task.scan_type] = result

                    # 按扫描类型分组
                    if task.scan_type not in aggregated["results_by_type"]:
                        aggregated["results_by_type"][task.scan_type] = {}
                    aggregated["results_by_type"][task.scan_type][task.target] = result

            return aggregated

    def get_node_status(self) -> List[Dict]:
        """获取所有节点状态"""
        with self._lock:
            return [
                {
                    "node_id": node.node_id,
                    "name": node.name,
                    "endpoint": node.endpoint,
                    "status": node.status,
                    "capacity": node.capacity,
                    "current_load": node.current_load,
                    "total_tasks": node.total_tasks,
                    "completed_tasks": node.completed_tasks,
                    "failed_tasks": node.failed_tasks,
                    "capabilities": node.capabilities,
                    "last_heartbeat": node.last_heartbeat,
                    "uptime": round(time.time() - node.registered_at, 1),
                }
                for node in self.nodes.values()
            ]

    def get_statistics(self) -> Dict[str, Any]:
        """获取全局统计"""
        with self._lock:
            total_tasks = len(self.tasks)
            completed = sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETED.value)
            failed = sum(1 for t in self.tasks.values() if t.status == TaskStatus.FAILED.value)
            running = sum(1 for t in self.tasks.values() if t.status == TaskStatus.RUNNING.value)
            pending = sum(1 for t in self.tasks.values() if t.status == TaskStatus.PENDING.value)

            return {
                "nodes": len(self.nodes),
                "online_nodes": sum(1 for n in self.nodes.values() if n.status != NodeStatus.OFFLINE.value),
                "jobs": len(self.jobs),
                "total_tasks": total_tasks,
                "completed_tasks": completed,
                "failed_tasks": failed,
                "running_tasks": running,
                "pending_tasks": pending,
                "success_rate": round(completed / (completed + failed) * 100, 1) if (completed + failed) > 0 else 0,
            }
