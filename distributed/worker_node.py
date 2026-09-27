#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式工作节点管理模块，支持节点注册、心跳监控、负载分配和节点状态管理。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import uuid
import socket
import platform
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class WorkerStatus:
    """工作节点状态"""
    IDLE = "idle"
    BUSY = "busy"
    OFFLINE = "offline"
    ERROR = "error"
    MAINTENANCE = "maintenance"


@dataclass
class WorkerHeartbeat:
    """工作节点心跳"""
    worker_id: str
    status: str
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_usage: float = 0.0
    active_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    uptime: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "worker_id": self.worker_id,
            "status": self.status,
            "cpu_usage": self.cpu_usage,
            "memory_usage": self.memory_usage,
            "disk_usage": self.disk_usage,
            "network_usage": self.network_usage,
            "active_tasks": self.active_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "uptime": self.uptime,
            "timestamp": self.timestamp,
        }


@dataclass
class WorkerNode:
    """工作节点"""
    worker_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ip_address: str = ""
    port: int = 0
    status: str = WorkerStatus.IDLE
    os_type: str = ""
    os_version: str = ""
    cpu_cores: int = 0
    memory_gb: float = 0.0
    disk_gb: float = 0.0
    network_speed: str = ""
    location: str = ""
    tags: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    max_concurrent_tasks: int = 4
    current_tasks: List[str] = field(default_factory=list)
    completed_tasks: int = 0
    failed_tasks: int = 0
    total_scans: int = 0
    total_ports_scanned: int = 0
    total_vulnerabilities_found: int = 0
    last_heartbeat: str = ""
    registered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_active: str = ""
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "worker_id": self.worker_id,
            "name": self.name,
            "ip_address": self.ip_address,
            "port": self.port,
            "status": self.status,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "cpu_cores": self.cpu_cores,
            "memory_gb": self.memory_gb,
            "disk_gb": self.disk_gb,
            "network_speed": self.network_speed,
            "location": self.location,
            "tags": self.tags,
            "capabilities": self.capabilities,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "current_tasks": self.current_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "total_scans": self.total_scans,
            "total_ports_scanned": self.total_ports_scanned,
            "total_vulnerabilities_found": self.total_vulnerabilities_found,
            "last_heartbeat": self.last_heartbeat,
            "registered_at": self.registered_at,
            "last_active": self.last_active,
            "error_message": self.error_message,
        }

    def is_available(self) -> bool:
        """检查节点是否可用"""
        return (self.status == WorkerStatus.IDLE and
                len(self.current_tasks) < self.max_concurrent_tasks)

    def can_handle_task(self, task_type: str) -> bool:
        """检查节点是否能处理指定类型的任务"""
        return self.is_available() and (not self.capabilities or task_type in self.capabilities)

    def assign_task(self, task_id: str) -> bool:
        """分配任务"""
        if len(self.current_tasks) >= self.max_concurrent_tasks:
            return False
        self.current_tasks.append(task_id)
        self.status = WorkerStatus.BUSY
        self.last_active = datetime.now().isoformat()
        return True

    def complete_task(self, task_id: str, success: bool = True):
        """完成任务"""
        if task_id in self.current_tasks:
            self.current_tasks.remove(task_id)
        if success:
            self.completed_tasks += 1
        else:
            self.failed_tasks += 1
        if not self.current_tasks:
            self.status = WorkerStatus.IDLE
        self.last_active = datetime.now().isoformat()

    def update_heartbeat(self, heartbeat: WorkerHeartbeat):
        """更新心跳"""
        self.last_heartbeat = heartbeat.timestamp
        self.status = heartbeat.status
        self.completed_tasks = heartbeat.completed_tasks
        self.failed_tasks = heartbeat.failed_tasks


class WorkerManager:
    """工作节点管理器"""

    def __init__(self, heartbeat_timeout: int = 60):
        """初始化WorkerManager实例。

        Args:
            self: 类实例。
        """
        self.workers: Dict[str, WorkerNode] = {}
        self.heartbeat_timeout = heartbeat_timeout
        self.heartbeats: List[WorkerHeartbeat] = []

    def register_worker(self, worker: WorkerNode) -> bool:
        """注册工作节点"""
        if worker.worker_id in self.workers:
            logger.warning(f"工作节点 {worker.worker_id} 已存在，将被更新")
        self.workers[worker.worker_id] = worker
        logger.info(f"工作节点注册成功: {worker.name} ({worker.ip_address})")
        return True

    def unregister_worker(self, worker_id: str) -> bool:
        """注销工作节点"""
        if worker_id in self.workers:
            worker = self.workers[worker_id]
            worker.status = WorkerStatus.OFFLINE
            del self.workers[worker_id]
            logger.info(f"工作节点注销: {worker_id}")
            return True
        return False

    def get_worker(self, worker_id: str) -> Optional[WorkerNode]:
        """获取工作节点"""
        return self.workers.get(worker_id)

    def list_workers(self, status: str = "") -> List[WorkerNode]:
        """列出工作节点"""
        if status:
            return [w for w in self.workers.values() if w.status == status]
        return list(self.workers.values())

    def get_available_workers(self) -> List[WorkerNode]:
        """获取可用工作节点"""
        return [w for w in self.workers.values() if w.is_available()]

    def get_best_worker(self, task_type: str = "") -> Optional[WorkerNode]:
        """获取最佳工作节点（负载最低）"""
        available = [w for w in self.workers.values() if w.can_handle_task(task_type)]
        if not available:
            return None
        # 按当前任务数排序，选择负载最低的
        available.sort(key=lambda w: len(w.current_tasks))
        return available[0]

    def assign_task_to_worker(self, task_id: str, task_type: str = "", worker_id: str = "") -> Optional[WorkerNode]:
        """分配任务给工作节点"""
        if worker_id:
            worker = self.get_worker(worker_id)
            if worker and worker.assign_task(task_id):
                return worker
            return None

        worker = self.get_best_worker(task_type)
        if worker and worker.assign_task(task_id):
            return worker
        return None

    def receive_heartbeat(self, heartbeat: WorkerHeartbeat) -> bool:
        """接收心跳"""
        self.heartbeats.append(heartbeat)
        if heartbeat.worker_id in self.workers:
            self.workers[heartbeat.worker_id].update_heartbeat(heartbeat)
            return True
        return False

    def check_offline_workers(self) -> List[WorkerNode]:
        """检查离线工作节点"""
        now = datetime.now()
        offline = []
        for worker in self.workers.values():
            if worker.last_heartbeat:
                last_hb = datetime.fromisoformat(worker.last_heartbeat)
                if (now - last_hb).total_seconds() > self.heartbeat_timeout:
                    if worker.status != WorkerStatus.OFFLINE:
                        worker.status = WorkerStatus.OFFLINE
                        worker.error_message = "心跳超时"
                        offline.append(worker)
        return offline

    def remove_offline_workers(self) -> int:
        """移除离线工作节点"""
        offline = [w.worker_id for w in self.workers.values() if w.status == WorkerStatus.OFFLINE]
        for worker_id in offline:
            del self.workers[worker_id]
        return len(offline)

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self.workers)
        idle = sum(1 for w in self.workers.values() if w.status == WorkerStatus.IDLE)
        busy = sum(1 for w in self.workers.values() if w.status == WorkerStatus.BUSY)
        offline = sum(1 for w in self.workers.values() if w.status == WorkerStatus.OFFLINE)
        error = sum(1 for w in self.workers.values() if w.status == WorkerStatus.ERROR)

        total_completed = sum(w.completed_tasks for w in self.workers.values())
        total_failed = sum(w.failed_tasks for w in self.workers.values())
        total_scans = sum(w.total_scans for w in self.workers.values())
        total_vulns = sum(w.total_vulnerabilities_found for w in self.workers.values())

        return {
            "total_workers": total,
            "idle": idle,
            "busy": busy,
            "offline": offline,
            "error": error,
            "available_workers": idle,
            "total_capacity": sum(w.max_concurrent_tasks for w in self.workers.values()),
            "current_load": sum(len(w.current_tasks) for w in self.workers.values()),
            "total_completed_tasks": total_completed,
            "total_failed_tasks": total_failed,
            "total_scans": total_scans,
            "total_vulnerabilities_found": total_vulns,
            "success_rate": f"{total_completed/(total_completed+total_failed)*100:.1f}%" if (total_completed + total_failed) > 0 else "0%",
        }

    def create_local_worker(self, name: str = "local-worker") -> WorkerNode:
        """创建本地工作节点"""
        worker = WorkerNode(
            name=name,
            ip_address="127.0.0.1",
            port=8080,
            status=WorkerStatus.IDLE,
            os_type=platform.system(),
            os_version=platform.version(),
            cpu_cores=os.cpu_count() if (os := __import__('os')) else 4,
            memory_gb=16.0,
            disk_gb=500.0,
            network_speed="1Gbps",
            location="local",
            tags=["local", "primary"],
            capabilities=["nmap", "nuclei", "sqlmap", "dirsearch", "hydra"],
            max_concurrent_tasks=4,
        )
        self.register_worker(worker)
        return worker


# 全局实例
worker_manager = WorkerManager()
