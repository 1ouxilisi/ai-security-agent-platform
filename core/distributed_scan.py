#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式扫描架构
Distributed Scan Architecture

功能：多节点协同、任务分发、负载均衡、结果聚合、节点管理、弹性伸缩
"""

import os
import json
import time
import uuid
import threading
import queue
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Tuple, Callable
from enum import Enum
from collections import defaultdict, deque
from loguru import logger


class NodeStatus(str, Enum):
    """节点状态"""
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    IDLE = "idle"
    ERROR = "error"
    MAINTENANCE = "maintenance"


class NodeType(str, Enum):
    """节点类型"""
    MASTER = "master"          # 主节点（任务调度）
    WORKER = "worker"          # 工作节点（执行扫描）
    SCANNER = "scanner"        # 扫描节点（专用扫描）
    EXPLOITER = "exploiter"    # 利用节点（专用利用）
    ANALYZER = "analyzer"      # 分析节点（专用分析）
    REPORTER = "reporter"      # 报告节点（专用报告）


class TaskPriority(str, Enum):
    """任务优先级"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class DistributedTaskStatus(str, Enum):
    """分布式任务状态"""
    PENDING = "pending"
    QUEUED = "queued"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    PARTIAL = "partial"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class ScanNode:
    """扫描节点"""
    node_id: str
    name: str
    node_type: NodeType = NodeType.WORKER
    status: NodeStatus = NodeStatus.OFFLINE
    ip_address: str = ""
    port: int = 0
    api_key: str = ""
    capabilities: List[str] = field(default_factory=list)  # 能力标签
    max_concurrent_tasks: int = 4
    current_tasks: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    total_scans: int = 0
    success_count: int = 0
    fail_count: int = 0
    avg_response_time: float = 0.0
    last_heartbeat: float = 0.0
    registered_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'node_id': self.node_id,
            'name': self.name,
            'node_type': self.node_type.value,
            'status': self.status.value,
            'ip_address': self.ip_address,
            'port': self.port,
            'capabilities': self.capabilities,
            'max_concurrent_tasks': self.max_concurrent_tasks,
            'current_tasks': self.current_tasks,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'total_scans': self.total_scans,
            'success_count': self.success_count,
            'fail_count': self.fail_count,
            'avg_response_time': self.avg_response_time,
            'last_heartbeat': self.last_heartbeat,
            'registered_at': self.registered_at,
            'tags': self.tags,
            'metadata': self.metadata,
        }

    def get_workload(self) -> float:
        """获取工作负载（0-1）"""
        if self.max_concurrent_tasks == 0:
            return 1.0
        return min(1.0, self.current_tasks / self.max_concurrent_tasks)

    def get_performance_score(self) -> float:
        """获取性能评分（0-100）"""
        if self.total_scans == 0:
            return 50.0
        success_rate = self.success_count / self.total_scans * 100
        workload_penalty = self.get_workload() * 20
        return max(0.0, min(100.0, success_rate - workload_penalty))


@dataclass
class DistributedTask:
    """分布式任务"""
    task_id: str
    name: str
    task_type: str  # port_scan, directory_scan, vulnerability_scan, exploit, etc.
    target: str
    status: DistributedTaskStatus = DistributedTaskStatus.PENDING
    priority: TaskPriority = TaskPriority.NORMAL
    assigned_node: Optional[str] = None
    subtasks: List[Dict[str, Any]] = field(default_factory=list)
    completed_subtasks: int = 0
    total_subtasks: int = 0
    progress: float = 0.0
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    duration: Optional[float] = None
    timeout: int = 3600
    retries: int = 0
    max_retries: int = 3
    creator: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'name': self.name,
            'task_type': self.task_type,
            'target': self.target,
            'status': self.status.value,
            'priority': self.priority.value,
            'assigned_node': self.assigned_node,
            'subtasks': self.subtasks,
            'completed_subtasks': self.completed_subtasks,
            'total_subtasks': self.total_subtasks,
            'progress': self.progress,
            'result': self.result,
            'error': self.error,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'duration': self.duration,
            'timeout': self.timeout,
            'retries': self.retries,
            'max_retries': self.max_retries,
            'creator': self.creator,
            'tags': self.tags,
            'metadata': self.metadata,
        }


@dataclass
class ScanResult:
    """扫描结果"""
    result_id: str
    task_id: str
    node_id: str
    target: str
    scan_type: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    duration: float = 0.0
    success: bool = True
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LoadBalancer:
    """负载均衡器"""

    def __init__(self, strategy: str = "least_connections"):
        self.strategy = strategy  # least_connections, round_robin, weighted, performance
        self._round_robin_index = 0

    def select_node(self, nodes: List[ScanNode], task: DistributedTask) -> Optional[ScanNode]:
        """选择最佳节点"""
        # 过滤可用节点
        available_nodes = [
            n for n in nodes
            if n.status in [NodeStatus.ONLINE, NodeStatus.IDLE]
            and n.current_tasks < n.max_concurrent_tasks
            and (not task.tags or any(tag in n.tags for tag in task.tags))
            and (not task.metadata.get('required_capabilities') or
                 all(cap in n.capabilities for cap in task.metadata.get('required_capabilities', [])))
        ]

        if not available_nodes:
            return None

        if self.strategy == "least_connections":
            return min(available_nodes, key=lambda n: n.current_tasks)
        elif self.strategy == "round_robin":
            node = available_nodes[self._round_robin_index % len(available_nodes)]
            self._round_robin_index += 1
            return node
        elif self.strategy == "weighted":
            # 基于性能评分加权选择
            total_score = sum(n.get_performance_score() for n in available_nodes)
            if total_score == 0:
                return available_nodes[0]
            import random
            r = random.uniform(0, total_score)
            cumulative = 0
            for node in available_nodes:
                cumulative += node.get_performance_score()
                if r <= cumulative:
                    return node
            return available_nodes[-1]
        elif self.strategy == "performance":
            return max(available_nodes, key=lambda n: n.get_performance_score())
        else:
            return available_nodes[0]


class TaskDistributor:
    """任务分发器"""

    def __init__(self):
        self._task_queue: queue.PriorityQueue = queue.PriorityQueue()
        self._lock = threading.Lock()

    def add_task(self, task: DistributedTask):
        """添加任务"""
        priority_map = {
            TaskPriority.LOW: 1,
            TaskPriority.NORMAL: 2,
            TaskPriority.HIGH: 3,
            TaskPriority.CRITICAL: 4,
        }
        priority = priority_map.get(task.priority, 2)
        self._task_queue.put((-priority, task.task_id, task))

    def get_next_task(self) -> Optional[DistributedTask]:
        """获取下一个任务"""
        try:
            _, _, task = self._task_queue.get_nowait()
            return task
        except queue.Empty:
            return None

    def get_queue_size(self) -> int:
        """获取队列大小"""
        return self._task_queue.qsize()


class ResultAggregator:
    """结果聚合器"""

    def __init__(self):
        self._results: Dict[str, List[ScanResult]] = defaultdict(list)
        self._lock = threading.Lock()

    def add_result(self, result: ScanResult):
        """添加结果"""
        with self._lock:
            self._results[result.task_id].append(result)

    def get_results(self, task_id: str) -> List[ScanResult]:
        """获取任务结果"""
        return self._results.get(task_id, [])

    def aggregate_results(self, task_id: str) -> Dict[str, Any]:
        """聚合结果"""
        results = self.get_results(task_id)
        if not results:
            return {}

        all_findings = []
        total_duration = 0.0
        success_count = 0
        node_results = {}

        for result in results:
            all_findings.extend(result.findings)
            total_duration += result.duration
            if result.success:
                success_count += 1
            node_results[result.node_id] = {
                'findings_count': len(result.findings),
                'duration': result.duration,
                'success': result.success,
            }

        # 去重
        unique_findings = []
        seen = set()
        for finding in all_findings:
            key = hashlib.md5(json.dumps(finding, sort_keys=True).encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        # 风险统计
        risk_summary = defaultdict(int)
        for finding in unique_findings:
            risk = finding.get('severity', 'info').lower()
            risk_summary[risk] += 1

        return {
            'task_id': task_id,
            'total_results': len(results),
            'success_rate': round(success_count / len(results) * 100, 1) if results else 0,
            'total_findings': len(unique_findings),
            'risk_summary': dict(risk_summary),
            'total_duration': round(total_duration, 2),
            'node_results': node_results,
            'findings': unique_findings,
        }


class DistributedScanManager:
    """分布式扫描管理器"""

    def __init__(self, data_dir: str = "data/distributed"):
        self.data_dir = data_dir
        self.nodes_file = os.path.join(data_dir, "nodes.json")
        self.tasks_file = os.path.join(data_dir, "tasks.json")

        self._nodes: Dict[str, ScanNode] = {}
        self._tasks: Dict[str, DistributedTask] = {}
        self._load_balancer = LoadBalancer(strategy="least_connections")
        self._task_distributor = TaskDistributor()
        self._result_aggregator = ResultAggregator()

        self._dispatcher_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._running = False

        os.makedirs(data_dir, exist_ok=True)
        self._load_nodes()
        self._load_tasks()

        # 注册本地节点
        self._register_local_node()

        logger.info("分布式扫描管理器初始化完成")

    def _register_local_node(self):
        """注册本地节点"""
        local_id = "local_master"
        if local_id not in self._nodes:
            node = ScanNode(
                node_id=local_id,
                name="本地主节点",
                node_type=NodeType.MASTER,
                status=NodeStatus.ONLINE,
                ip_address="127.0.0.1",
                port=8000,
                capabilities=["port_scan", "directory_scan", "vulnerability_scan", "exploit", "report"],
                max_concurrent_tasks=10,
                tags=["local", "master"],
            )
            self._nodes[local_id] = node
            self._save_nodes()
            logger.info("本地主节点已注册")

    # ============== 节点管理 ==============

    def register_node(self, name: str, node_type: NodeType = NodeType.WORKER,
                      ip_address: str = "", port: int = 0,
                      capabilities: List[str] = None,
                      max_concurrent_tasks: int = 4,
                      tags: List[str] = None) -> ScanNode:
        """注册节点"""
        node_id = str(uuid.uuid4())
        node = ScanNode(
            node_id=node_id,
            name=name,
            node_type=node_type,
            status=NodeStatus.ONLINE,
            ip_address=ip_address,
            port=port,
            capabilities=capabilities or [],
            max_concurrent_tasks=max_concurrent_tasks,
            tags=tags or [],
            last_heartbeat=time.time(),
        )
        self._nodes[node_id] = node
        self._save_nodes()
        logger.info(f"注册节点: {name} ({node_id})")
        return node

    def unregister_node(self, node_id: str) -> bool:
        """注销节点"""
        if node_id in self._nodes:
            node = self._nodes.pop(node_id)
            self._save_nodes()
            logger.info(f"注销节点: {node.name} ({node_id})")
            return True
        return False

    def update_node_status(self, node_id: str, status: NodeStatus) -> bool:
        """更新节点状态"""
        node = self._nodes.get(node_id)
        if node:
            node.status = status
            node.last_heartbeat = time.time()
            self._save_nodes()
            return True
        return False

    def heartbeat(self, node_id: str, cpu_usage: float = 0.0,
                  memory_usage: float = 0.0, current_tasks: int = 0) -> bool:
        """节点心跳"""
        node = self._nodes.get(node_id)
        if node:
            node.cpu_usage = cpu_usage
            node.memory_usage = memory_usage
            node.current_tasks = current_tasks
            node.last_heartbeat = time.time()
            if node.status == NodeStatus.OFFLINE:
                node.status = NodeStatus.ONLINE
            return True
        return False

    def list_nodes(self, node_type: NodeType = None,
                   status: NodeStatus = None) -> List[ScanNode]:
        """列出节点"""
        nodes = list(self._nodes.values())
        if node_type:
            nodes = [n for n in nodes if n.node_type == node_type]
        if status:
            nodes = [n for n in nodes if n.status == status]
        return sorted(nodes, key=lambda n: n.registered_at)

    def get_node(self, node_id: str) -> Optional[ScanNode]:
        """获取节点"""
        return self._nodes.get(node_id)

    # ============== 任务管理 ==============

    def create_task(self, name: str, task_type: str, target: str,
                    priority: TaskPriority = TaskPriority.NORMAL,
                    timeout: int = 3600, tags: List[str] = None,
                    metadata: Dict[str, Any] = None) -> DistributedTask:
        """创建分布式任务"""
        task_id = str(uuid.uuid4())
        task = DistributedTask(
            task_id=task_id,
            name=name,
            task_type=task_type,
            target=target,
            priority=priority,
            timeout=timeout,
            tags=tags or [],
            metadata=metadata or {},
        )

        # 拆分子任务
        self._split_task(task)

        self._tasks[task_id] = task
        self._task_distributor.add_task(task)
        self._save_tasks()

        logger.info(f"创建分布式任务: {name} ({task_id}), {task.total_subtasks}个子任务")
        return task

    def _split_task(self, task: DistributedTask):
        """拆分子任务"""
        if task.task_type == "port_scan":
            # 端口扫描按端口范围拆分
            ports = task.metadata.get('ports', list(range(1, 10001)))
            chunk_size = max(1, len(ports) // max(1, len(self._nodes)))
            for i in range(0, len(ports), chunk_size):
                chunk = ports[i:i + chunk_size]
                task.subtasks.append({
                    'subtask_id': f"{task.task_id}_{len(task.subtasks)}",
                    'type': 'port_scan',
                    'target': task.target,
                    'ports': chunk,
                    'status': 'pending',
                })
        elif task.task_type == "directory_scan":
            # 目录扫描按字典拆分
            wordlist = task.metadata.get('wordlist', ['admin', 'login', 'backup'])
            chunk_size = max(1, len(wordlist) // max(1, len(self._nodes)))
            for i in range(0, len(wordlist), chunk_size):
                chunk = wordlist[i:i + chunk_size]
                task.subtasks.append({
                    'subtask_id': f"{task.task_id}_{len(task.subtasks)}",
                    'type': 'directory_scan',
                    'target': task.target,
                    'wordlist': chunk,
                    'status': 'pending',
                })
        else:
            # 默认：不拆分，单个任务
            task.subtasks.append({
                'subtask_id': f"{task.task_id}_0",
                'type': task.task_type,
                'target': task.target,
                'status': 'pending',
            })

        task.total_subtasks = len(task.subtasks)

    def dispatch_task(self, task_id: str) -> Tuple[bool, str]:
        """分发任务"""
        task = self._tasks.get(task_id)
        if not task:
            return False, "任务不存在"

        if task.status not in [DistributedTaskStatus.PENDING, DistributedTaskStatus.QUEUED]:
            return False, f"任务状态不允许分发: {task.status.value}"

        # 选择节点
        nodes = self.list_nodes(status=NodeStatus.ONLINE)
        selected_node = self._load_balancer.select_node(nodes, task)

        if not selected_node:
            return False, "没有可用节点"

        # 分配任务
        task.assigned_node = selected_node.node_id
        task.status = DistributedTaskStatus.DISPATCHED
        task.started_at = time.time()
        selected_node.current_tasks += 1
        selected_node.status = NodeStatus.BUSY

        self._save_tasks()
        self._save_nodes()

        logger.info(f"任务已分发: {task.name} -> {selected_node.name}")
        return True, f"已分配到节点 {selected_node.name}"

    def complete_task(self, task_id: str, result: Dict[str, Any] = None,
                      success: bool = True, error: str = "") -> bool:
        """完成任务"""
        task = self._tasks.get(task_id)
        if not task:
            return False

        task.status = DistributedTaskStatus.COMPLETED if success else DistributedTaskStatus.FAILED
        task.result = result
        task.error = error
        task.completed_at = time.time()
        if task.started_at:
            task.duration = task.completed_at - task.started_at
        task.progress = 100.0 if success else task.progress

        # 释放节点
        if task.assigned_node:
            node = self._nodes.get(task.assigned_node)
            if node:
                node.current_tasks = max(0, node.current_tasks - 1)
                if node.current_tasks == 0:
                    node.status = NodeStatus.IDLE
                node.total_scans += 1
                if success:
                    node.success_count += 1
                else:
                    node.fail_count += 1

        self._save_tasks()
        self._save_nodes()

        logger.info(f"任务完成: {task.name}, 成功: {success}")
        return True

    def list_tasks(self, status: DistributedTaskStatus = None,
                   node_id: str = None, limit: int = 50) -> List[DistributedTask]:
        """列出任务"""
        tasks = list(self._tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        if node_id:
            tasks = [t for t in tasks if t.assigned_node == node_id]
        tasks.sort(key=lambda t: t.created_at, reverse=True)
        return tasks[:limit]

    def get_task(self, task_id: str) -> Optional[DistributedTask]:
        """获取任务"""
        return self._tasks.get(task_id)

    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        task = self._tasks.get(task_id)
        if task and task.status in [DistributedTaskStatus.PENDING, DistributedTaskStatus.QUEUED]:
            task.status = DistributedTaskStatus.CANCELLED
            self._save_tasks()
            return True
        return False

    # ============== 结果管理 ==============

    def submit_result(self, task_id: str, node_id: str, findings: List[Dict],
                      success: bool = True, error: str = "",
                      raw_output: str = "") -> ScanResult:
        """提交扫描结果"""
        result = ScanResult(
            result_id=str(uuid.uuid4()),
            task_id=task_id,
            node_id=node_id,
            target="",
            scan_type="",
            findings=findings,
            success=success,
            error=error,
            raw_output=raw_output,
            started_at=time.time() - 10,
            completed_at=time.time(),
            duration=10.0,
        )
        self._result_aggregator.add_result(result)
        return result

    def get_aggregated_result(self, task_id: str) -> Dict[str, Any]:
        """获取聚合结果"""
        return self._result_aggregator.aggregate_results(task_id)

    # ============== 调度器 ==============

    def start_dispatcher(self):
        """启动任务调度器"""
        if self._running:
            return

        self._running = True
        self._dispatcher_thread = threading.Thread(target=self._dispatch_loop, daemon=True)
        self._dispatcher_thread.start()
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_check_loop, daemon=True)
        self._heartbeat_thread.start()
        logger.info("分布式调度器已启动")

    def stop_dispatcher(self):
        """停止任务调度器"""
        self._running = False
        if self._dispatcher_thread:
            self._dispatcher_thread.join(timeout=5)
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
        logger.info("分布式调度器已停止")

    def _dispatch_loop(self):
        """调度循环"""
        while self._running:
            try:
                task = self._task_distributor.get_next_task()
                if task:
                    success, message = self.dispatch_task(task.task_id)
                    if not success:
                        # 分发失败，重新入队
                        self._task_distributor.add_task(task)
                        time.sleep(1)
            except Exception as e:
                logger.error(f"调度循环异常: {e}")
            time.sleep(0.5)

    def _heartbeat_check_loop(self):
        """心跳检查循环"""
        while self._running:
            try:
                now = time.time()
                for node in self._nodes.values():
                    if node.status == NodeStatus.ONLINE and now - node.last_heartbeat > 60:
                        node.status = NodeStatus.OFFLINE
                        logger.warning(f"节点离线: {node.name}")
                self._save_nodes()
            except Exception as e:
                logger.error(f"心跳检查异常: {e}")
            time.sleep(30)

    # ============== 统计 ==============

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        online_nodes = len([n for n in self._nodes.values() if n.status == NodeStatus.ONLINE])
        busy_nodes = len([n for n in self._nodes.values() if n.status == NodeStatus.BUSY])
        total_tasks = len(self._tasks)
        completed_tasks = len([t for t in self._tasks.values() if t.status == DistributedTaskStatus.COMPLETED])
        failed_tasks = len([t for t in self._tasks.values() if t.status == DistributedTaskStatus.FAILED])
        running_tasks = len([t for t in self._tasks.values() if t.status == DistributedTaskStatus.RUNNING])
        pending_tasks = len([t for t in self._tasks.values() if t.status in [DistributedTaskStatus.PENDING, DistributedTaskStatus.QUEUED]])

        return {
            'total_nodes': len(self._nodes),
            'online_nodes': online_nodes,
            'busy_nodes': busy_nodes,
            'offline_nodes': len(self._nodes) - online_nodes,
            'total_tasks': total_tasks,
            'completed_tasks': completed_tasks,
            'failed_tasks': failed_tasks,
            'running_tasks': running_tasks,
            'pending_tasks': pending_tasks,
            'queue_size': self._task_distributor.get_queue_size(),
            'dispatcher_running': self._running,
            'load_balancer_strategy': self._load_balancer.strategy,
            'node_types': {
                nt.value: len([n for n in self._nodes.values() if n.node_type == nt])
                for nt in NodeType
            },
        }

    # ============== 持久化 ==============

    def _load_nodes(self):
        if os.path.exists(self.nodes_file):
            try:
                with open(self.nodes_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        node = ScanNode(**{k: v for k, v in data.items() if k in ScanNode.__dataclass_fields__})
                        if isinstance(node.node_type, str):
                            node.node_type = NodeType(node.node_type)
                        if isinstance(node.status, str):
                            node.status = NodeStatus(node.status)
                        self._nodes[node.node_id] = node
            except Exception as e:
                logger.warning(f"加载节点数据失败: {e}")

    def _load_tasks(self):
        if os.path.exists(self.tasks_file):
            try:
                with open(self.tasks_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        task = DistributedTask(**{k: v for k, v in data.items() if k in DistributedTask.__dataclass_fields__})
                        if isinstance(task.status, str):
                            task.status = DistributedTaskStatus(task.status)
                        if isinstance(task.priority, str):
                            task.priority = TaskPriority(task.priority)
                        self._tasks[task.task_id] = task
            except Exception as e:
                logger.warning(f"加载任务数据失败: {e}")

    def _save_nodes(self):
        try:
            with open(self.nodes_file, 'w', encoding='utf-8') as f:
                json.dump([n.to_dict() for n in self._nodes.values()], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存节点数据失败: {e}")

    def _save_tasks(self):
        try:
            with open(self.tasks_file, 'w', encoding='utf-8') as f:
                json.dump([t.to_dict() for t in self._tasks.values()], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存任务数据失败: {e}")


# 全局分布式扫描管理器实例
_global_distributed_manager: Optional[DistributedScanManager] = None


def get_distributed_manager() -> DistributedScanManager:
    """获取全局分布式扫描管理器实例"""
    global _global_distributed_manager
    if _global_distributed_manager is None:
        _global_distributed_manager = DistributedScanManager()
    return _global_distributed_manager
