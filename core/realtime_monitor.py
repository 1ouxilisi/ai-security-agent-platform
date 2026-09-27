#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实时监控系统
Real-time Monitoring System

功能：WebSocket实时推送、任务进度监控、系统状态监控、告警通知、实时日志
"""

import os
import json
import time
import uuid
import asyncio
import threading
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Set, Callable
from enum import Enum
from collections import defaultdict, deque
from loguru import logger


class AlertLevel(str, Enum):
    """告警级别"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MonitorType(str, Enum):
    """监控类型"""
    SYSTEM = "system"          # 系统资源
    TASK = "task"              # 任务进度
    SCAN = "scan"              # 扫描进度
    NETWORK = "network"        # 网络状态
    SECURITY = "security"      # 安全事件
    CUSTOM = "custom"          # 自定义


@dataclass
class SystemMetrics:
    """系统指标"""
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    memory_total: float = 0.0
    memory_used: float = 0.0
    disk_usage: float = 0.0
    disk_total: float = 0.0
    disk_used: float = 0.0
    network_in: float = 0.0
    network_out: float = 0.0
    active_connections: int = 0
    process_count: int = 0
    uptime: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TaskProgress:
    """任务进度"""
    task_id: str
    name: str
    status: str = "pending"  # pending/running/completed/failed
    progress: float = 0.0
    current_step: str = ""
    total_steps: int = 0
    completed_steps: int = 0
    started_at: Optional[float] = None
    estimated_completion: Optional[float] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    """告警"""
    alert_id: str
    level: AlertLevel
    type: MonitorType
    title: str
    message: str = ""
    source: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    acknowledged: bool = False
    acknowledged_at: Optional[float] = None
    acknowledged_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'level': self.level.value,
            'type': self.type.value,
            'title': self.title,
            'message': self.message,
            'source': self.source,
            'details': self.details,
            'created_at': self.created_at,
            'acknowledged': self.acknowledged,
            'acknowledged_at': self.acknowledged_at,
            'acknowledged_by': self.acknowledged_by,
        }


@dataclass
class LogEntry:
    """日志条目"""
    log_id: str
    level: str  # debug/info/warning/error/critical
    source: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RealTimeMonitor:
    """实时监控器"""

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history

        # 系统指标历史
        self._metrics_history: deque = deque(maxlen=max_history)
        self._current_metrics: SystemMetrics = SystemMetrics()

        # 任务进度
        self._tasks: Dict[str, TaskProgress] = {}

        # 告警
        self._alerts: List[Alert] = []
        self._alert_callbacks: List[Callable] = []

        # 日志
        self._logs: deque = deque(maxlen=max_history)

        # WebSocket连接
        self._connections: Set[Any] = set()
        self._subscriptions: Dict[str, Set[Any]] = defaultdict(set)

        # 监控线程
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = False
        self._monitor_interval = 5  # 秒

        # 统计
        self._stats = {
            'total_alerts': 0,
            'total_tasks_monitored': 0,
            'total_logs': 0,
            'uptime': 0.0,
            'start_time': time.time(),
        }

        logger.info("实时监控器初始化完成")

    # ============== 系统指标 ==============

    def collect_metrics(self) -> SystemMetrics:
        """收集系统指标"""
        metrics = SystemMetrics()

        try:
            import psutil
            metrics.cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            metrics.memory_usage = memory.percent
            metrics.memory_total = memory.total / (1024 ** 3)
            metrics.memory_used = memory.used / (1024 ** 3)
            disk = psutil.disk_usage('/')
            metrics.disk_usage = disk.percent
            metrics.disk_total = disk.total / (1024 ** 3)
            metrics.disk_used = disk.used / (1024 ** 3)
            network = psutil.net_io_counters()
            metrics.network_in = network.bytes_recv / (1024 ** 2)
            metrics.network_out = network.bytes_sent / (1024 ** 2)
            metrics.active_connections = len(psutil.net_connections())
            metrics.process_count = len(psutil.pids())
        except ImportError:
            # psutil未安装，使用模拟数据
            metrics.cpu_usage = 25.0 + (time.time() % 10)
            metrics.memory_usage = 45.0
            metrics.memory_total = 16.0
            metrics.memory_used = 7.2
            metrics.disk_usage = 60.0
            metrics.disk_total = 500.0
            metrics.disk_used = 300.0
            metrics.process_count = 150

        metrics.uptime = time.time() - self._stats['start_time']
        metrics.timestamp = time.time()

        self._current_metrics = metrics
        self._metrics_history.append(metrics)

        # 检查告警阈值
        self._check_metric_alerts(metrics)

        return metrics

    def _check_metric_alerts(self, metrics: SystemMetrics):
        """检查指标告警"""
        if metrics.cpu_usage > 90:
            self.create_alert(
                level=AlertLevel.CRITICAL,
                type=MonitorType.SYSTEM,
                title="CPU使用率过高",
                message=f"CPU使用率达到 {metrics.cpu_usage:.1f}%",
                source="system_monitor",
            )
        elif metrics.cpu_usage > 75:
            self.create_alert(
                level=AlertLevel.WARNING,
                type=MonitorType.SYSTEM,
                title="CPU使用率偏高",
                message=f"CPU使用率达到 {metrics.cpu_usage:.1f}%",
                source="system_monitor",
            )

        if metrics.memory_usage > 90:
            self.create_alert(
                level=AlertLevel.CRITICAL,
                type=MonitorType.SYSTEM,
                title="内存使用率过高",
                message=f"内存使用率达到 {metrics.memory_usage:.1f}%",
                source="system_monitor",
            )

        if metrics.disk_usage > 90:
            self.create_alert(
                level=AlertLevel.ERROR,
                type=MonitorType.SYSTEM,
                title="磁盘空间不足",
                message=f"磁盘使用率达到 {metrics.disk_usage:.1f}%",
                source="system_monitor",
            )

    def get_current_metrics(self) -> SystemMetrics:
        """获取当前指标"""
        return self._current_metrics

    def get_metrics_history(self, limit: int = 100) -> List[SystemMetrics]:
        """获取指标历史"""
        return list(self._metrics_history)[-limit:]

    # ============== 任务进度 ==============

    def register_task(self, task_id: str, name: str, total_steps: int = 0) -> TaskProgress:
        """注册任务"""
        task = TaskProgress(
            task_id=task_id,
            name=name,
            total_steps=total_steps,
            started_at=time.time(),
        )
        self._tasks[task_id] = task
        self._stats['total_tasks_monitored'] += 1
        self._broadcast('task_update', task.to_dict())
        return task

    def update_task_progress(self, task_id: str, progress: float = None,
                              current_step: str = None, status: str = None,
                              completed_steps: int = None, error: str = None,
                              metadata: Dict[str, Any] = None) -> Optional[TaskProgress]:
        """更新任务进度"""
        task = self._tasks.get(task_id)
        if not task:
            return None

        if progress is not None:
            task.progress = min(100.0, max(0.0, progress))
        if current_step is not None:
            task.current_step = current_step
        if status is not None:
            task.status = status
            if status == 'completed':
                task.progress = 100.0
        if completed_steps is not None:
            task.completed_steps = completed_steps
            if task.total_steps > 0:
                task.progress = (completed_steps / task.total_steps) * 100
        if error is not None:
            task.error = error
            task.status = 'failed'
        if metadata is not None:
            task.metadata.update(metadata)

        task.updated_at = time.time()
        self._broadcast('task_update', task.to_dict())

        # 任务完成或失败时创建告警
        if status == 'completed':
            self.create_alert(
                level=AlertLevel.INFO,
                type=MonitorType.TASK,
                title="任务完成",
                message=f"任务 '{task.name}' 已完成",
                source="task_monitor",
                details={'task_id': task_id},
            )
        elif status == 'failed':
            self.create_alert(
                level=AlertLevel.ERROR,
                type=MonitorType.TASK,
                title="任务失败",
                message=f"任务 '{task.name}' 失败: {error}",
                source="task_monitor",
                details={'task_id': task_id, 'error': error},
            )

        return task

    def get_task(self, task_id: str) -> Optional[TaskProgress]:
        """获取任务"""
        return self._tasks.get(task_id)

    def list_tasks(self, status: str = None, limit: int = 50) -> List[TaskProgress]:
        """列出任务"""
        tasks = list(self._tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        tasks.sort(key=lambda t: t.updated_at, reverse=True)
        return tasks[:limit]

    def remove_task(self, task_id: str) -> bool:
        """移除任务"""
        if task_id in self._tasks:
            del self._tasks[task_id]
            return True
        return False

    # ============== 告警管理 ==============

    def create_alert(self, level: AlertLevel, type: MonitorType, title: str,
                     message: str = "", source: str = "",
                     details: Dict[str, Any] = None) -> Alert:
        """创建告警"""
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            level=level,
            type=type,
            title=title,
            message=message,
            source=source,
            details=details or {},
        )
        self._alerts.append(alert)
        if len(self._alerts) > self.max_history:
            self._alerts = self._alerts[-self.max_history:]
        self._stats['total_alerts'] += 1

        # 触发回调
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"告警回调失败: {e}")

        # 广播
        self._broadcast('alert', alert.to_dict())

        logger.log(level.value.upper() if level.value != 'critical' else 'CRITICAL',
                   f"[{level.value}] {title}: {message}")

        return alert

    def acknowledge_alert(self, alert_id: str, user_id: str = None) -> bool:
        """确认告警"""
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                alert.acknowledged_at = time.time()
                alert.acknowledged_by = user_id
                self._broadcast('alert_update', alert.to_dict())
                return True
        return False

    def list_alerts(self, level: AlertLevel = None, type: MonitorType = None,
                    acknowledged: bool = None, limit: int = 100) -> List[Alert]:
        """列出告警"""
        alerts = list(self._alerts)
        if level:
            alerts = [a for a in alerts if a.level == level]
        if type:
            alerts = [a for a in alerts if a.type == type]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        return alerts[:limit]

    def get_unacknowledged_count(self) -> Dict[str, int]:
        """获取未确认告警数"""
        counts = {level.value: 0 for level in AlertLevel}
        for alert in self._alerts:
            if not alert.acknowledged:
                counts[alert.level.value] += 1
        return counts

    def register_alert_callback(self, callback: Callable):
        """注册告警回调"""
        self._alert_callbacks.append(callback)

    # ============== 日志管理 ==============

    def add_log(self, level: str, source: str, message: str,
                details: Dict[str, Any] = None) -> LogEntry:
        """添加日志"""
        log = LogEntry(
            log_id=str(uuid.uuid4()),
            level=level,
            source=source,
            message=message,
            details=details or {},
        )
        self._logs.append(log)
        self._stats['total_logs'] += 1
        self._broadcast('log', log.to_dict())
        return log

    def list_logs(self, level: str = None, source: str = None,
                  limit: int = 100) -> List[LogEntry]:
        """列出日志"""
        logs = list(self._logs)
        if level:
            logs = [l for l in logs if l.level == level]
        if source:
            logs = [l for l in logs if l.source == source]
        logs.sort(key=lambda l: l.timestamp, reverse=True)
        return logs[:limit]

    # ============== WebSocket ==============

    def register_connection(self, websocket):
        """注册WebSocket连接"""
        self._connections.add(websocket)
        logger.info(f"WebSocket连接已注册，当前连接数: {len(self._connections)}")

    def unregister_connection(self, websocket):
        """注销WebSocket连接"""
        self._connections.discard(websocket)
        # 从所有订阅中移除
        for subscribers in self._subscriptions.values():
            subscribers.discard(websocket)
        logger.info(f"WebSocket连接已注销，当前连接数: {len(self._connections)}")

    def subscribe(self, channel: str, websocket):
        """订阅频道"""
        self._subscriptions[channel].add(websocket)

    def unsubscribe(self, channel: str, websocket):
        """取消订阅"""
        self._subscriptions[channel].discard(websocket)

    def _broadcast(self, channel: str, data: Dict[str, Any]):
        """广播消息"""
        message = json.dumps({
            'channel': channel,
            'data': data,
            'timestamp': time.time(),
        }, ensure_ascii=False)

        # 发送给频道订阅者
        for websocket in self._subscriptions.get(channel, set()):
            try:
                asyncio.ensure_future(websocket.send_text(message))
            except Exception:
                pass

        # 发送给所有连接（如果没有特定订阅）
        if not self._subscriptions.get(channel):
            for websocket in list(self._connections):
                try:
                    asyncio.ensure_future(websocket.send_text(message))
                except Exception:
                    pass

    # ============== 监控线程 ==============

    def start(self, interval: int = 5):
        """启动监控"""
        if self._running:
            return

        self._running = True
        self._monitor_interval = interval
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info(f"实时监控已启动，间隔: {interval}秒")

    def stop(self):
        """停止监控"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("实时监控已停止")

    def _monitor_loop(self):
        """监控循环"""
        while self._running:
            try:
                # 收集系统指标
                metrics = self.collect_metrics()
                self._broadcast('metrics', metrics.to_dict())

                # 更新统计
                self._stats['uptime'] = time.time() - self._stats['start_time']

            except Exception as e:
                logger.error(f"监控循环异常: {e}")

            time.sleep(self._monitor_interval)

    # ============== 统计 ==============

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self._stats,
            'active_connections': len(self._connections),
            'active_tasks': len([t for t in self._tasks.values() if t.status == 'running']),
            'total_tasks': len(self._tasks),
            'metrics_history_size': len(self._metrics_history),
            'logs_size': len(self._logs),
            'alerts_size': len(self._alerts),
            'unacknowledged_alerts': self.get_unacknowledged_count(),
            'current_metrics': self._current_metrics.to_dict(),
            'is_running': self._running,
            'monitor_interval': self._monitor_interval,
        }


# 全局实时监控器实例
_global_monitor: Optional[RealTimeMonitor] = None


def get_monitor() -> RealTimeMonitor:
    """获取全局实时监控器实例"""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = RealTimeMonitor()
    return _global_monitor
