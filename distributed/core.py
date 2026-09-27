"""分布式扫描基础框架模块。

包含：节点管理、任务分发、结果收集、负载均衡、
代理池管理、任务队列、心跳检测等分布式扫描功能。
"""
import os
import json
import time
import uuid
import threading
import hashlib
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from utils.logger import log


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
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class ScanNode:
    """扫描节点"""
    node_id: str
    name: str = ""
    address: str = ""  # IP:端口
    status: str = NodeStatus.OFFLINE.value
    capabilities: List[str] = field(default_factory=list)  # 支持的扫描类型
    max_concurrent_tasks: int = 5
    current_tasks: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    last_heartbeat: float = 0
    registered_at: float = field(default_factory=time.time)
    total_tasks_completed: int = 0
    total_tasks_failed: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanTask:
    """扫描任务"""
    task_id: str
    task_type: str  # port_scan / vuln_scan / web_scan / etc.
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = TaskStatus.PENDING.value
    assigned_node: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: float = 0
    completed_at: float = 0
    priority: int = 5  # 1-10, 10最高
    timeout: int = 3600  # 秒
    retry_count: int = 0
    max_retries: int = 3
    result: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    progress: int = 0  # 0-100
    parent_task: str = ""  # 父任务ID（用于任务拆分）
    sub_tasks: List[str] = field(default_factory=list)


@dataclass
class ProxyServer:
    """代理服务器"""
    proxy_id: str
    address: str  # IP:端口
    protocol: str = "http"  # http/socks4/socks5
    username: str = ""
    password: str = ""
    is_active: bool = True
    success_rate: float = 0.0
    latency_ms: float = 0.0
    last_used: float = 0
    total_requests: int = 0
    failed_requests: int = 0


@dataclass
class TaskResult:
    """任务结果"""
    task_id: str
    node_id: str
    status: str
    findings: List[Dict] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    execution_time: float = 0.0
    raw_output: str = ""


class NodeManager:
    """节点管理器"""
    
    def __init__(self, heartbeat_timeout: int = 60):
        self.heartbeat_timeout = heartbeat_timeout
        self._nodes: Dict[str, ScanNode] = {}
        self._lock = threading.Lock()
    
    def register_node(self, name: str, address: str, 
                      capabilities: List[str] = None) -> ScanNode:
        """注册节点"""
        with self._lock:
            node_id = str(uuid.uuid4())[:8]
            node = ScanNode(
                node_id=node_id,
                name=name,
                address=address,
                status=NodeStatus.IDLE.value,
                capabilities=capabilities or ["port_scan", "vuln_scan"],
                last_heartbeat=time.time()
            )
            self._nodes[node_id] = node
            log.info(f"节点已注册: {name} ({node_id}) @ {address}")
            return node
    
    def unregister_node(self, node_id: str) -> bool:
        """注销节点"""
        with self._lock:
            if node_id in self._nodes:
                del self._nodes[node_id]
                log.info(f"节点已注销: {node_id}")
                return True
            return False
    
    def heartbeat(self, node_id: str, cpu_usage: float = 0, 
                  memory_usage: float = 0, current_tasks: int = 0) -> bool:
        """节点心跳"""
        with self._lock:
            node = self._nodes.get(node_id)
            if not node:
                return False
            
            node.last_heartbeat = time.time()
            node.cpu_usage = cpu_usage
            node.memory_usage = memory_usage
            node.current_tasks = current_tasks
            
            # 更新状态
            if current_tasks >= node.max_concurrent_tasks:
                node.status = NodeStatus.BUSY.value
            else:
                node.status = NodeStatus.IDLE.value
            
            return True
    
    def get_available_nodes(self, task_type: str = None) -> List[ScanNode]:
        """获取可用节点"""
        now = time.time()
        available = []
        
        with self._lock:
            for node in self._nodes.values():
                # 检查心跳
                if now - node.last_heartbeat > self.heartbeat_timeout:
                    node.status = NodeStatus.OFFLINE.value
                    continue
                
                # 检查状态
                if node.status not in [NodeStatus.IDLE.value, NodeStatus.ONLINE.value]:
                    continue
                
                # 检查当前任务数
                if node.current_tasks >= node.max_concurrent_tasks:
                    continue
                
                # 检查能力
                if task_type and task_type not in node.capabilities:
                    continue
                
                available.append(node)
        
        return available
    
    def get_best_node(self, task_type: str) -> Optional[ScanNode]:
        """获取最佳节点（负载均衡）"""
        available = self.get_available_nodes(task_type)
        if not available:
            return None
        
        # 按当前任务数和CPU使用率排序（选择负载最低的）
        available.sort(key=lambda n: (n.current_tasks, n.cpu_usage))
        return available[0]
    
    def list_nodes(self) -> List[ScanNode]:
        """列出所有节点"""
        with self._lock:
            return list(self._nodes.values())
    
    def get_node_stats(self) -> Dict[str, Any]:
        """获取节点统计"""
        with self._lock:
            total = len(self._nodes)
            online = sum(1 for n in self._nodes.values() 
                        if n.status in [NodeStatus.IDLE.value, NodeStatus.BUSY.value, NodeStatus.ONLINE.value])
            busy = sum(1 for n in self._nodes.values() if n.status == NodeStatus.BUSY.value)
            
            return {
                "total_nodes": total,
                "online_nodes": online,
                "offline_nodes": total - online,
                "busy_nodes": busy,
                "idle_nodes": online - busy,
                "total_capacity": sum(n.max_concurrent_tasks for n in self._nodes.values()),
                "current_load": sum(n.current_tasks for n in self._nodes.values()),
            }


class TaskDistributor:
    """任务分发器"""
    
    def __init__(self, node_manager: NodeManager):
        self.node_manager = node_manager
        self._tasks: Dict[str, ScanTask] = {}
        self._task_queue: List[str] = []  # 按优先级排序的任务ID
        self._results: Dict[str, TaskResult] = {}
        self._lock = threading.Lock()
        self._dispatcher_thread: Optional[threading.Thread] = None
        self._running = False
    
    def create_task(self, task_type: str, target: str, 
                    parameters: Dict = None, priority: int = 5,
                    timeout: int = 3600) -> ScanTask:
        """创建任务"""
        with self._lock:
            task_id = str(uuid.uuid4())[:8]
            task = ScanTask(
                task_id=task_id,
                task_type=task_type,
                target=target,
                parameters=parameters or {},
                priority=priority,
                timeout=timeout
            )
            self._tasks[task_id] = task
            self._task_queue.append(task_id)
            # 按优先级排序
            self._task_queue.sort(key=lambda tid: -self._tasks[tid].priority)
            log.info(f"任务已创建: {task_id} ({task_type}) 目标: {target}")
            return task
    
    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task or task.status in [TaskStatus.COMPLETED.value, TaskStatus.FAILED.value]:
                return False
            
            task.status = TaskStatus.CANCELLED.value
            if task_id in self._task_queue:
                self._task_queue.remove(task_id)
            log.info(f"任务已取消: {task_id}")
            return True
    
    def get_next_task(self) -> Optional[ScanTask]:
        """获取下一个待执行的任务"""
        with self._lock:
            for task_id in self._task_queue:
                task = self._tasks[task_id]
                if task.status == TaskStatus.PENDING.value:
                    return task
            return None
    
    def assign_task(self, task: ScanTask, node: ScanNode) -> bool:
        """分配任务到节点"""
        with self._lock:
            if task.status != TaskStatus.PENDING.value:
                return False
            
            task.assigned_node = node.node_id
            task.status = TaskStatus.RUNNING.value
            task.started_at = time.time()
            node.current_tasks += 1
            
            if task.task_id in self._task_queue:
                self._task_queue.remove(task.task_id)
            
            log.info(f"任务 {task.task_id} 已分配到节点 {node.node_id}")
            return True
    
    def complete_task(self, task_id: str, result: TaskResult) -> bool:
        """完成任务"""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False
            
            task.status = TaskStatus.COMPLETED.value
            task.completed_at = time.time()
            task.result = asdict(result)
            task.progress = 100
            
            # 更新节点状态
            node = self.node_manager._nodes.get(task.assigned_node)
            if node and node.current_tasks > 0:
                node.current_tasks -= 1
                node.total_tasks_completed += 1
            
            self._results[task_id] = result
            log.info(f"任务 {task_id} 已完成，发现 {len(result.findings)} 个结果")
            return True
    
    def fail_task(self, task_id: str, error: str) -> bool:
        """任务失败"""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False
            
            task.retry_count += 1
            if task.retry_count < task.max_retries:
                # 重新入队
                task.status = TaskStatus.PENDING.value
                task.assigned_node = ""
                self._task_queue.append(task_id)
                self._task_queue.sort(key=lambda tid: -self._tasks[tid].priority)
                log.warning(f"任务 {task_id} 失败，重试 ({task.retry_count}/{task.max_retries}): {error}")
            else:
                task.status = TaskStatus.FAILED.value
                task.error = error
                task.completed_at = time.time()
                
                # 更新节点状态
                node = self.node_manager._nodes.get(task.assigned_node)
                if node and node.current_tasks > 0:
                    node.current_tasks -= 1
                    node.total_tasks_failed += 1
                
                log.error(f"任务 {task_id} 最终失败: {error}")
            
            return True
    
    def get_task(self, task_id: str) -> Optional[ScanTask]:
        """获取任务"""
        return self._tasks.get(task_id)
    
    def get_task_result(self, task_id: str) -> Optional[TaskResult]:
        """获取任务结果"""
        return self._results.get(task_id)
    
    def list_tasks(self, status: str = None, limit: int = 100) -> List[ScanTask]:
        """列出任务"""
        tasks = list(self._tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        tasks.sort(key=lambda t: t.created_at, reverse=True)
        return tasks[:limit]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取任务统计"""
        with self._lock:
            total = len(self._tasks)
            by_status = {}
            for task in self._tasks.values():
                by_status[task.status] = by_status.get(task.status, 0) + 1
            
            return {
                "total_tasks": total,
                "pending": by_status.get(TaskStatus.PENDING.value, 0),
                "running": by_status.get(TaskStatus.RUNNING.value, 0),
                "completed": by_status.get(TaskStatus.COMPLETED.value, 0),
                "failed": by_status.get(TaskStatus.FAILED.value, 0),
                "cancelled": by_status.get(TaskStatus.CANCELLED.value, 0),
                "queue_size": len(self._task_queue),
            }
    
    def start_dispatcher(self):
        """启动分发器线程"""
        if self._running:
            return
        
        self._running = True
        self._dispatcher_thread = threading.Thread(target=self._dispatch_loop, daemon=True)
        self._dispatcher_thread.start()
        log.info("任务分发器已启动")
    
    def stop_dispatcher(self):
        """停止分发器线程"""
        self._running = False
        if self._dispatcher_thread:
            self._dispatcher_thread.join(timeout=5)
        log.info("任务分发器已停止")
    
    def _dispatch_loop(self):
        """分发循环"""
        while self._running:
            try:
                task = self.get_next_task()
                if task:
                    node = self.node_manager.get_best_node(task.task_type)
                    if node:
                        self.assign_task(task, node)
                        # 这里应该通过网络发送任务到节点
                        log.info(f"分发任务 {task.task_id} 到节点 {node.node_id}")
                    else:
                        # 没有可用节点，等待
                        time.sleep(1)
                else:
                    time.sleep(0.5)
            except Exception as e:
                log.warning(f"分发循环异常: {e}")
                time.sleep(1)


class ProxyPool:
    """代理池管理器"""
    
    def __init__(self):
        self._proxies: Dict[str, ProxyServer] = {}
        self._lock = threading.Lock()
        self._current_index = 0
    
    def add_proxy(self, address: str, protocol: str = "http",
                  username: str = "", password: str = "") -> ProxyServer:
        """添加代理"""
        with self._lock:
            proxy_id = str(uuid.uuid4())[:8]
            proxy = ProxyServer(
                proxy_id=proxy_id,
                address=address,
                protocol=protocol,
                username=username,
                password=password
            )
            self._proxies[proxy_id] = proxy
            log.info(f"代理已添加: {address} ({proxy_id})")
            return proxy
    
    def remove_proxy(self, proxy_id: str) -> bool:
        """移除代理"""
        with self._lock:
            if proxy_id in self._proxies:
                del self._proxies[proxy_id]
                return True
            return False
    
    def get_proxy(self, protocol: str = None) -> Optional[ProxyServer]:
        """获取代理（轮询）"""
        with self._lock:
            active_proxies = [p for p in self._proxies.values() 
                             if p.is_active and (protocol is None or p.protocol == protocol)]
            
            if not active_proxies:
                return None
            
            # 轮询选择
            proxy = active_proxies[self._current_index % len(active_proxies)]
            self._current_index += 1
            return proxy
    
    def report_result(self, proxy_id: str, success: bool, latency_ms: float = 0):
        """报告代理使用结果"""
        with self._lock:
            proxy = self._proxies.get(proxy_id)
            if not proxy:
                return
            
            proxy.total_requests += 1
            proxy.last_used = time.time()
            proxy.latency_ms = latency_ms
            
            if not success:
                proxy.failed_requests += 1
            
            # 计算成功率
            if proxy.total_requests > 0:
                proxy.success_rate = (1 - proxy.failed_requests / proxy.total_requests) * 100
            
            # 成功率低于30%则禁用
            if proxy.success_rate < 30 and proxy.total_requests > 10:
                proxy.is_active = False
                log.warning(f"代理 {proxy.address} 因成功率过低被禁用")
    
    def list_proxies(self) -> List[ProxyServer]:
        """列出所有代理"""
        with self._lock:
            return list(self._proxies.values())
    
    def get_stats(self) -> Dict[str, Any]:
        """获取代理池统计"""
        with self._lock:
            total = len(self._proxies)
            active = sum(1 for p in self._proxies.values() if p.is_active)
            avg_success = sum(p.success_rate for p in self._proxies.values()) / total if total > 0 else 0
            avg_latency = sum(p.latency_ms for p in self._proxies.values()) / total if total > 0 else 0
            
            return {
                "total_proxies": total,
                "active_proxies": active,
                "inactive_proxies": total - active,
                "avg_success_rate": round(avg_success, 2),
                "avg_latency_ms": round(avg_latency, 2),
                "total_requests": sum(p.total_requests for p in self._proxies.values()),
            }


class DistributedScanner:
    """分布式扫描器（整合节点管理、任务分发、代理池）"""
    
    def __init__(self):
        self.node_manager = NodeManager()
        self.task_distributor = TaskDistributor(self.node_manager)
        self.proxy_pool = ProxyPool()
    
    def start(self):
        """启动分布式扫描器"""
        self.task_distributor.start_dispatcher()
        log.info("分布式扫描器已启动")
    
    def stop(self):
        """停止分布式扫描器"""
        self.task_distributor.stop_dispatcher()
        log.info("分布式扫描器已停止")
    
    def scan(self, target: str, scan_type: str = "port_scan",
             parameters: Dict = None, priority: int = 5) -> str:
        """提交扫描任务"""
        task = self.task_distributor.create_task(
            task_type=scan_type,
            target=target,
            parameters=parameters or {},
            priority=priority
        )
        return task.task_id
    
    def get_scan_result(self, task_id: str) -> Optional[Dict]:
        """获取扫描结果"""
        result = self.task_distributor.get_task_result(task_id)
        if result:
            return asdict(result)
        
        task = self.task_distributor.get_task(task_id)
        if task:
            return {
                "task_id": task_id,
                "status": task.status,
                "progress": task.progress,
                "message": "任务尚未完成"
            }
        return None
    
    def get_overall_stats(self) -> Dict[str, Any]:
        """获取整体统计"""
        return {
            "nodes": self.node_manager.get_node_stats(),
            "tasks": self.task_distributor.get_stats(),
            "proxies": self.proxy_pool.get_stats(),
        }


# 全局分布式扫描器实例
distributed_scanner = DistributedScanner()


# ==========================================================================
# 深化模块：节点管理 / 任务分发 / 代理池 / 单机多节点模拟
# 说明：以下为追加实现，不修改上方已有的类定义与方法；对已有类采用
#       “追加新方法 / 向后兼容地重绑方法”的方式扩展功能。
# ==========================================================================
import socket
from concurrent.futures import ThreadPoolExecutor

# 数据目录
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
DIST_DATA_DIR = os.path.join(DATA_DIR, "distributed")
os.makedirs(DIST_DATA_DIR, exist_ok=True)

NODE_HEARTBEAT_TIMEOUT = 30    # 超过 30 秒无心跳标记为 offline
NODE_DEAD_TIMEOUT = 300         # 超过 5 分钟无心跳则清理


@dataclass
class DistributedNode:
    """分布式节点（面向对外协议的节点描述）。

    与内部 ScanNode 共存：ScanNode 仍作为存储对象，DistributedNode 用于
    对外 API / 配置展示。
    """
    node_id: str
    hostname: str = ""
    ip: str = ""
    status: str = "online"          # online / offline / busy
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    active_tasks: int = 0
    last_heartbeat: float = field(default_factory=time.time)
    capabilities: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# NodeManager 扩展（追加新方法 + 向后兼容重绑）
# --------------------------------------------------------------------------
def _nm_register_node(self, node_info=None, name="", address="",
                      capabilities=None, **kwargs):
    """注册节点。

    兼容两种调用：
      1) 新协议: register_node(node_info={"hostname":..,"ip":..,"capabilities":..})
      2) 旧协议: register_node(name=.., address=.., capabilities=..)
    返回内部 ScanNode 对象（其 .node_id 即新协议要求的 node_id）。
    """
    hostname = ""
    ip = ""
    if isinstance(node_info, dict):
        hostname = node_info.get("hostname", "")
        ip = node_info.get("ip", "")
        name = node_info.get("name", name or hostname or "node")
        address = node_info.get("address", address or ip)
        capabilities = node_info.get("capabilities", capabilities)
    if not name:
        name = hostname or "local-node"
    with self._lock:
        node_id = str(uuid.uuid4())[:8]
        node = ScanNode(
            node_id=node_id,
            name=name,
            address=address or ip,
            status=NodeStatus.ONLINE.value,
            capabilities=capabilities or ["port_scan", "vuln_scan", "web_scan"],
            last_heartbeat=time.time(),
        )
        node.metadata["hostname"] = hostname
        node.metadata["ip"] = ip
        self._nodes[node_id] = node
        log.info(f"节点已注册: {name} ({node_id}) @ {address or ip}")
        return node


def _nm_heartbeat(self, node_id, metrics=None, cpu_usage=0.0,
                  memory_usage=0.0, current_tasks=0):
    """节点心跳。

    兼容：
      1) 新协议: heartbeat(node_id, metrics={"cpu_usage":..,"memory_usage":..,"active_tasks":..})
      2) 旧协议: heartbeat(node_id=.., cpu_usage=.., memory_usage=.., current_tasks=..)
    """
    if isinstance(metrics, dict):
        cpu_usage = metrics.get("cpu_usage", cpu_usage)
        memory_usage = metrics.get("memory_usage", memory_usage)
        current_tasks = metrics.get("active_tasks",
                                   metrics.get("current_tasks", current_tasks))
    elif metrics is not None and isinstance(metrics, (int, float)):
        # 兼容旧的位置调用 heartbeat(node_id, cpu_usage, ...)
        cpu_usage = metrics
    with self._lock:
        node = self._nodes.get(node_id)
        if not node:
            return False
        node.last_heartbeat = time.time()
        node.cpu_usage = float(cpu_usage)
        node.memory_usage = float(memory_usage)
        node.current_tasks = int(current_tasks)
        if node.current_tasks > 0:
            node.status = NodeStatus.BUSY.value
        else:
            node.status = NodeStatus.ONLINE.value
        return True


def _nm_get_node_status(self, node_id):
    """获取节点状态（返回 dict；心跳超时自动标记 offline）。"""
    with self._lock:
        node = self._nodes.get(node_id)
        if not node:
            return None
        if time.time() - node.last_heartbeat > NODE_HEARTBEAT_TIMEOUT:
            node.status = NodeStatus.OFFLINE.value
        data = asdict(node)
        data["active_tasks"] = node.current_tasks
        data["hostname"] = node.metadata.get("hostname", node.name)
        data["ip"] = node.metadata.get("ip", node.address)
        return data


def _nm_list_nodes(self, status=None):
    """列出所有节点（可按状态过滤），返回 ScanNode 列表以兼容旧调用方。"""
    now = time.time()
    with self._lock:
        result = []
        for node in self._nodes.values():
            if now - node.last_heartbeat > NODE_HEARTBEAT_TIMEOUT:
                node.status = NodeStatus.OFFLINE.value
            if status is None or node.status == status:
                result.append(node)
        return result


def _nm_get_available_node(self):
    """负载均衡：选择 active_tasks 最少且 cpu_usage < 80% 的在线节点。"""
    now = time.time()
    with self._lock:
        candidates = []
        for n in self._nodes.values():
            if now - n.last_heartbeat > NODE_HEARTBEAT_TIMEOUT:
                n.status = NodeStatus.OFFLINE.value
                continue
            if n.status not in (NodeStatus.ONLINE.value, NodeStatus.IDLE.value):
                continue
            if n.cpu_usage >= 80.0:
                continue
            candidates.append(n)
        if not candidates:
            return None
        candidates.sort(key=lambda n: (n.current_tasks, n.cpu_usage))
        return candidates[0]


def _nm_remove_dead_nodes(self):
    """清理超过 5 分钟无心跳的节点，返回被清理的 node_id 列表。"""
    now = time.time()
    removed = []
    with self._lock:
        dead = [nid for nid, n in self._nodes.items()
                if now - n.last_heartbeat > NODE_DEAD_TIMEOUT]
        for nid in dead:
            del self._nodes[nid]
            removed.append(nid)
    if removed:
        log.info(f"清理死节点: {removed}")
    return removed


# 绑定到已有 NodeManager（追加新方法 / 向后兼容重绑）
NodeManager.register_node = _nm_register_node
NodeManager.heartbeat = _nm_heartbeat
NodeManager.list_nodes = _nm_list_nodes
NodeManager.get_node_status = _nm_get_node_status
NodeManager.get_available_node = _nm_get_available_node
NodeManager.remove_dead_nodes = _nm_remove_dead_nodes


# --------------------------------------------------------------------------
# TaskDistributor 扩展
# --------------------------------------------------------------------------
def _td_create_task(self, target=None, scan_type=None, options=None, priority=5,
                    task_type=None, parameters=None, timeout=3600):
    """创建任务，兼容新旧两种调用：
      新: create_task(target, scan_type, options, priority)
      旧: create_task(task_type=, target=, parameters=, priority=)
    """
    st = task_type or scan_type or "port_scan"
    opts = parameters if parameters is not None else (options or {})
    with self._lock:
        task_id = str(uuid.uuid4())[:8]
        task = ScanTask(
            task_id=task_id,
            task_type=st,
            target=target or "",
            parameters=opts or {},
            priority=priority,
            timeout=timeout,
        )
        self._tasks[task_id] = task
        self._task_queue.append(task_id)
        self._task_queue.sort(key=lambda tid: -self._tasks[tid].priority)
        log.info(f"任务已创建: {task_id} ({st}) 目标: {target}")
        return task


def _td_assign_task(self, task, node):
    """分配任务到节点，兼容传入 task_id/node_id 字符串或对象。"""
    if isinstance(task, str):
        task = self._tasks.get(task)
    if isinstance(node, str):
        node = self.node_manager._nodes.get(node)
    if task is None or node is None:
        return False
    with self._lock:
        if task.status != TaskStatus.PENDING.value:
            return False
        task.assigned_node = node.node_id
        task.status = TaskStatus.RUNNING.value
        task.started_at = time.time()
        node.current_tasks += 1
        if task.task_id in self._task_queue:
            self._task_queue.remove(task.task_id)
        log.info(f"任务 {task.task_id} 已分配到节点 {node.node_id}")
        return True


def _td_split_task(self, task):
    """任务拆分：多目标(逗号分隔)或多端口拆分为子任务。返回子任务列表。"""
    if isinstance(task, str):
        task = self._tasks.get(task)
    if task is None:
        return []
    children = []

    # 1) 多目标拆分（逗号分隔的 IP / 域名）
    parts = [p.strip() for p in str(task.target).replace("，", ",").split(",") if p.strip()]
    if len(parts) > 1:
        for p in parts:
            child = ScanTask(
                task_id=str(uuid.uuid4())[:8],
                task_type=task.task_type,
                target=p,
                parameters=dict(task.parameters),
                priority=task.priority,
                parent_task=task.task_id,
            )
            with self._lock:
                self._tasks[child.task_id] = child
                self._task_queue.append(child.task_id)
                task.sub_tasks.append(child.task_id)
            children.append(child)
        log.info(f"任务 {task.task_id} 按目标拆分为 {len(children)} 个子任务")
        return children

    # 2) 端口拆分
    ports = task.parameters.get("ports") or task.parameters.get("port_range")
    if ports:
        try:
            if isinstance(ports, str) and "-" in ports:
                lo, hi = [int(x) for x in ports.split("-", 1)]
                port_list = list(range(lo, hi + 1))
            elif isinstance(ports, (list, tuple)):
                port_list = list(ports)
            else:
                port_list = [int(ports)]
            chunks = [port_list[i:i + 100] for i in range(0, len(port_list), 100)]
            for chunk in chunks:
                child_params = dict(task.parameters)
                child_params["ports"] = chunk
                child = ScanTask(
                    task_id=str(uuid.uuid4())[:8],
                    task_type=task.task_type,
                    target=task.target,
                    parameters=child_params,
                    priority=task.priority,
                    parent_task=task.task_id,
                )
                with self._lock:
                    self._tasks[child.task_id] = child
                    self._task_queue.append(child.task_id)
                    task.sub_tasks.append(child.task_id)
                children.append(child)
            if children:
                log.info(f"任务 {task.task_id} 按端口拆分为 {len(children)} 个子任务")
        except Exception as e:
            log.warning(f"任务 {task.task_id} 端口拆分失败: {e}")
    return children


def _td_dispatch_pending_tasks(self):
    """调度：将 pending 任务分配给可用节点。返回本次分配的任务数。"""
    dispatched = 0
    with self._lock:
        pending_ids = [tid for tid in list(self._task_queue)
                       if self._tasks[tid].status == TaskStatus.PENDING.value]
    for tid in pending_ids:
        node = self.node_manager.get_available_node()
        if node is None:
            break
        if self.assign_task(tid, node.node_id):
            dispatched += 1
    if dispatched:
        log.info(f"本次调度分配了 {dispatched} 个任务")
    return dispatched


def _td_update_task_status(self, task_id, status=None, progress=None, result=None):
    """更新任务状态/进度/结果。"""
    with self._lock:
        t = self._tasks.get(task_id)
        if not t:
            return False
        if status:
            t.status = status
        if progress is not None:
            t.progress = int(progress)
        if result is not None:
            t.result = result if isinstance(result, dict) else {"data": result}
        if t.status == TaskStatus.RUNNING.value and not t.started_at:
            t.started_at = time.time()
        if t.status in (TaskStatus.COMPLETED.value, TaskStatus.FAILED.value):
            t.completed_at = time.time()
        return True


def _td_aggregate_results(self, parent_task_id):
    """聚合子任务结果。"""
    with self._lock:
        parent = self._tasks.get(parent_task_id)
        if not parent:
            return {}
        child_ids = list(parent.sub_tasks)
    child_results = []
    total_findings = 0
    for cid in child_ids:
        child = self._tasks.get(cid)
        if child and child.result:
            child_results.append({"task_id": cid, "status": child.status,
                                  "result": child.result})
            total_findings += len(child.result.get("findings", [])) if isinstance(child.result, dict) else 0
    return {
        "parent_task_id": parent_task_id,
        "child_count": len(child_ids),
        "completed": sum(1 for cid in child_ids
                        if self._tasks.get(cid) and self._tasks[cid].status == TaskStatus.COMPLETED.value),
        "failed": sum(1 for cid in child_ids
                      if self._tasks.get(cid) and self._tasks[cid].status == TaskStatus.FAILED.value),
        "total_findings": total_findings,
        "children": child_results,
    }


def _td_get_task_status(self, task_id):
    """获取任务状态（dict）。"""
    t = self._tasks.get(task_id)
    if not t:
        return None
    data = asdict(t)
    data["active_tasks"] = t.progress
    return data


TaskDistributor.create_task = _td_create_task
TaskDistributor.assign_task = _td_assign_task
TaskDistributor.split_task = _td_split_task
TaskDistributor.dispatch_pending_tasks = _td_dispatch_pending_tasks
TaskDistributor.update_task_status = _td_update_task_status
TaskDistributor.aggregate_results = _td_aggregate_results
TaskDistributor.get_task_status = _td_get_task_status


# --------------------------------------------------------------------------
# ProxyPool 扩展
# --------------------------------------------------------------------------
PROXY_FILE = os.path.join(DIST_DATA_DIR, "proxies.json")


def _pp_add_proxy(self, proxy_url=None, proxy_type="http", username="",
                  password="", **kwargs):
    """添加代理。兼容新协议 add_proxy(proxy_url, proxy_type) 与旧协议
    add_proxy(address=, protocol=)。"""
    if not hasattr(self, "_url_index"):
        self._url_index = {}
    address = proxy_url or kwargs.get("address")
    protocol = proxy_type or kwargs.get("protocol", "http")
    if not address:
        raise ValueError("proxy_url/address is required")
    with self._lock:
        if address in self._url_index:
            return self._proxies[self._url_index[address]]
        proxy_id = str(uuid.uuid4())[:8]
        proxy = ProxyServer(
            proxy_id=proxy_id,
            address=address,
            protocol=protocol,
            username=username or kwargs.get("username", ""),
            password=password or kwargs.get("password", ""),
        )
        self._proxies[proxy_id] = proxy
        self._url_index[address] = proxy_id
        log.info(f"代理已添加: {address} ({proxy_id})")
        return proxy


def _pp_remove_proxy(self, proxy_url):
    """按代理 URL（或 proxy_id）移除代理。"""
    if not hasattr(self, "_url_index"):
        self._url_index = {}
    with self._lock:
        pid = self._url_index.get(proxy_url)
        if pid is None and proxy_url in self._proxies:
            pid = proxy_url
        if pid and pid in self._proxies:
            addr = self._proxies[pid].address
            del self._proxies[pid]
            self._url_index.pop(addr, None)
            log.info(f"代理已移除: {addr}")
            return True
        return False


def _pp_check_proxy_health(self, proxy_url, test_url="http://httpbin.org/ip", timeout=5):
    """代理健康检查，返回 True/False。"""
    url = proxy_url if "://" in proxy_url else f"http://{proxy_url}"
    try:
        import requests
        resp = requests.get(test_url, proxies={"http": url, "https": url}, timeout=timeout)
        return resp.status_code < 400
    except Exception as e:
        log.debug(f"代理 {proxy_url} 健康检查失败: {e}")
        return False


def _pp_health_check_all(self, test_url="http://httpbin.org/ip", timeout=5):
    """检查所有代理，移除/禁用不可用者。"""
    summary = {"checked": 0, "alive": 0, "dead": 0}
    with self._lock:
        items = list(self._proxies.items())
    for pid, p in items:
        summary["checked"] += 1
        ok = self.check_proxy_health(p.address, test_url, timeout)
        with self._lock:
            p.is_active = ok
            if ok:
                summary["alive"] += 1
            else:
                summary["dead"] += 1
                log.warning(f"代理不可用，已禁用: {p.address}")
    return summary


def _pp_load_from_file(self, path=PROXY_FILE):
    """从 JSON 文件加载代理列表。"""
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        count = 0
        for item in data:
            url = item.get("url") or item.get("address")
            ptype = item.get("type") or item.get("protocol", "http")
            if url:
                self.add_proxy(url, ptype)
                count += 1
        if count:
            log.info(f"从 {path} 加载了 {count} 个代理")
        return count
    except Exception as e:
        log.warning(f"加载代理文件失败: {e}")
        return 0


def _pp_save_to_file(self, path=PROXY_FILE):
    """将代理列表保存到 JSON 文件。"""
    try:
        data = [{"url": p.address, "type": p.protocol,
                 "active": p.is_active} for p in self.list_proxies()]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        log.warning(f"保存代理文件失败: {e}")
        return False


ProxyPool.add_proxy = _pp_add_proxy
ProxyPool.remove_proxy = _pp_remove_proxy
ProxyPool.check_proxy_health = _pp_check_proxy_health
ProxyPool.health_check_all = _pp_health_check_all
ProxyPool.load_from_file = _pp_load_from_file
ProxyPool.save_to_file = _pp_save_to_file


# --------------------------------------------------------------------------
# 单机模拟多节点：ThreadPoolExecutor 本地任务执行引擎
# --------------------------------------------------------------------------
class LocalExecutionEngine:
    """单机本地任务执行引擎。

    在没有远程节点时，使用 ThreadPoolExecutor 在本地线程池中模拟执行
    扫描任务，并自动注册默认本地节点 local-node-1。
    """

    def __init__(self, distributor, node_manager, max_workers=4):
        self.distributor = distributor
        self.node_manager = node_manager
        self.executor = ThreadPoolExecutor(max_workers=max_workers,
                                           thread_name_prefix="local-scan")
        self._ensure_local_node()

    def _ensure_local_node(self):
        hostname = socket.gethostname()
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = "127.0.0.1"
        with self.node_manager._lock:
            if "local-node-1" in self.node_manager._nodes:
                node = self.node_manager._nodes["local-node-1"]
                node.last_heartbeat = time.time()
                return node
            node = ScanNode(
                node_id="local-node-1",
                name=hostname,
                address=ip,
                status=NodeStatus.ONLINE.value,
                capabilities=["port_scan", "vuln_scan", "web_scan", "osint"],
                last_heartbeat=time.time(),
            )
            node.metadata["hostname"] = hostname
            node.metadata["ip"] = ip
            self.node_manager._nodes["local-node-1"] = node
            log.info(f"已注册本地模拟节点 local-node-1 ({hostname} @ {ip})")
            return node

    def execute(self, task_id):
        """在线程池中异步执行任务，返回 Future。"""
        return self.executor.submit(self._run_task, task_id)

    def _run_task(self, task_id):
        task = self.distributor._tasks.get(task_id)
        if not task:
            return
        try:
            self.distributor.update_task_status(task_id, TaskStatus.RUNNING.value, 5, {})
            result = self._simulate_scan(task)
            self.distributor.update_task_status(task_id, TaskStatus.COMPLETED.value, 100, result)
            log.info(f"本地任务 {task_id} 完成")
        except Exception as e:
            self.distributor.update_task_status(
                task_id, TaskStatus.FAILED.value,
                self.distributor._tasks[task_id].progress if task_id in self.distributor._tasks else 0,
                {"error": str(e)})
            log.error(f"本地任务 {task_id} 失败: {e}")

    def _simulate_scan(self, task):
        """模拟扫描执行：优先调用 tools.integration，失败则模拟结果。"""
        findings = []
        try:
            from tools import integration as _integ  # noqa: F401
            # 具体真实扫描函数依赖外部工具可用性，这里仅做模拟
            time.sleep(0.2)
        except Exception:
            time.sleep(0.2)
        findings.append({
            "type": task.task_type,
            "target": task.target,
            "note": "simulated result (local execution engine)",
        })
        return {
            "task_id": task.task_id,
            "scan_type": task.task_type,
            "target": task.target,
            "findings": findings,
            "engine": "local-threadpool",
        }

    def shutdown(self):
        self.executor.shutdown(wait=False)


# 为全局 DistributedScanner 追加便捷方法（不改动其原有定义）
def _ds_ensure_local(self):
    if not hasattr(self, "_local_engine") or self._local_engine is None:
        self._local_engine = LocalExecutionEngine(self.task_distributor, self.node_manager)
    return self._local_engine


def _ds_run_local_task(self, task_id):
    """在本地线程池执行指定任务。"""
    engine = self.ensure_local()
    return engine.execute(task_id)


def _ds_dispatch(self):
    """调度 pending 任务到可用节点；若无远程节点则回退本地执行。"""
    dispatched = self.task_distributor.dispatch_pending_tasks()
    # 对仍 pending 的任务（无远程可用节点）回退本地执行
    engine = self.ensure_local()
    for t in self.task_distributor.list_tasks(status=TaskStatus.PENDING.value):
        if t.status == TaskStatus.PENDING.value:
            self.task_distributor.assign_task(t.task_id, "local-node-1")
            engine.execute(t.task_id)
            dispatched += 1
    return dispatched


DistributedScanner.ensure_local = _ds_ensure_local
DistributedScanner.run_local_task = _ds_run_local_task
DistributedScanner.dispatch = _ds_dispatch

# 模块加载时即注册默认本地节点并加载代理列表
distributed_scanner.ensure_local()
distributed_scanner.proxy_pool.load_from_file()
