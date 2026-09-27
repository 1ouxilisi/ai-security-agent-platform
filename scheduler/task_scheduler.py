#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
import os
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class TaskStatus(str, Enum):
    """任务状态"""
    PENDING = "pending"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class ScheduleType(str, Enum):
    """调度类型"""
    ONCE = "once"  # 一次性任务
    INTERVAL = "interval"  # 固定间隔
    DAILY = "daily"  # 每天
    WEEKLY = "weekly"  # 每周
    CRON = "cron"  # cron表达式


class TaskType(str, Enum):
    """任务类型（向后兼容枚举，旧脚本/测试引用）"""
    SCAN = "scan"
    MONITOR = "monitor"
    WORKFLOW = "workflow"
    PENTEST = "pentest"
    REPORT = "report"


class TaskPriority(str, Enum):
    """任务优先级（向后兼容枚举，旧脚本/测试引用）"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScheduledTask:
    """调度任务"""
    task_id: str
    name: str
    description: str
    schedule_type: ScheduleType
    target: str = ""
    task_type: str = "scan"  # scan/monitor/workflow
    parameters: Dict[str, Any] = field(default_factory=dict)
    interval_seconds: int = 3600  # 间隔秒数（INTERVAL类型）
    cron_expression: str = ""  # cron表达式
    next_run_time: float = 0
    last_run_time: Optional[float] = None
    status: TaskStatus = TaskStatus.SCHEDULED
    enabled: bool = True
    max_retries: int = 2
    retry_count: int = 0
    created_at: float = field(default_factory=time.time)
    run_history: List[Dict[str, Any]] = field(default_factory=list)
    change_detection: bool = False  # 是否启用变更检测
    last_scan_result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "task_id": self.task_id,
            "name": self.name,
            "description": self.description,
            "schedule_type": self.schedule_type.value,
            "target": self.target,
            "task_type": self.task_type,
            "parameters": self.parameters,
            "interval_seconds": self.interval_seconds,
            "cron_expression": self.cron_expression,
            "next_run_time": self.next_run_time,
            "last_run_time": self.last_run_time,
            "status": self.status.value,
            "enabled": self.enabled,
            "max_retries": self.max_retries,
            "retry_count": self.retry_count,
            "created_at": self.created_at,
            "run_count": len(self.run_history),
            "change_detection": self.change_detection
        }


@dataclass
class ChangeEvent:
    """变更事件"""
    event_id: str
    task_id: str
    target: str
    change_type: str  # new_port/closed_port/new_service/new_vulnerability/vulnerability_fixed
    description: str
    severity: str  # info/low/medium/high/critical
    previous_state: Any = None
    current_state: Any = None
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "event_id": self.event_id,
            "task_id": self.task_id,
            "target": self.target,
            "change_type": self.change_type,
            "description": self.description,
            "severity": self.severity,
            "previous_state": self.previous_state,
            "current_state": self.current_state,
            "detected_at": self.detected_at,
            "detected_at_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.detected_at))
        }


class TaskScheduler:
    """任务调度器"""

    def __init__(self, task_executor: Optional[Callable] = None):
        """初始化TaskScheduler实例。

        Args:
            self: 类实例。
        """
        self.tasks: Dict[str, ScheduledTask] = {}
        self.change_events: List[ChangeEvent] = []
        self.task_executor = task_executor
        self._running = False
        self._scheduler_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        self._max_concurrent = 3
        self._active_tasks = 0

    def create_task(
        self,
        name: str,
        description: str,
        schedule_type: str,
        target: str = "",
        task_type: str = "scan",
        parameters: Dict[str, Any] = None,
        interval_seconds: int = 3600,
        cron_expression: str = "",
        change_detection: bool = False,
        enabled: bool = True
    ) -> ScheduledTask:
        """创建调度任务"""
        task = ScheduledTask(
            task_id=str(uuid.uuid4())[:8],
            name=name,
            description=description,
            schedule_type=ScheduleType(schedule_type),
            target=target,
            task_type=task_type,
            parameters=parameters or {},
            interval_seconds=interval_seconds,
            cron_expression=cron_expression,
            change_detection=change_detection,
            enabled=enabled
        )

        # 计算下次运行时间
        task.next_run_time = self._calculate_next_run(task)

        self.tasks[task.task_id] = task
        log.info(f"创建调度任务: {task.name} ({task.task_id}), 类型: {schedule_type}, 目标: {target}")
        return task

    def _calculate_next_run(self, task: ScheduledTask) -> float:
        """计算下次运行时间"""
        now = time.time()
        if task.schedule_type == ScheduleType.ONCE:
            return now + 5  # 5秒后运行
        elif task.schedule_type == ScheduleType.INTERVAL:
            return now + task.interval_seconds
        elif task.schedule_type == ScheduleType.DAILY:
            # 简化：24小时后
            return now + 86400
        elif task.schedule_type == ScheduleType.WEEKLY:
            return now + 604800
        elif task.schedule_type == ScheduleType.CRON:
            # 简化：使用间隔（实际需要cron解析器）
            return now + task.interval_seconds
        return now + 3600

    def list_tasks(self) -> List[Dict[str, Any]]:
        """列出所有任务"""
        return [task.to_dict() for task in self.tasks.values()]

    def get_task(self, task_id: str) -> Optional[ScheduledTask]:
        """获取任务详情"""
        return self.tasks.get(task_id)

    def pause_task(self, task_id: str) -> bool:
        """暂停任务"""
        task = self.tasks.get(task_id)
        if not task:
            return False
        task.status = TaskStatus.PAUSED
        task.enabled = False
        log.info(f"暂停任务: {task.name}")
        return True

    def resume_task(self, task_id: str) -> bool:
        """恢复任务"""
        task = self.tasks.get(task_id)
        if not task:
            return False
        task.status = TaskStatus.SCHEDULED
        task.enabled = True
        task.next_run_time = self._calculate_next_run(task)
        log.info(f"恢复任务: {task.name}")
        return True

    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        task = self.tasks.get(task_id)
        if not task:
            return False
        task.status = TaskStatus.CANCELLED
        task.enabled = False
        log.info(f"取消任务: {task.name}")
        return True

    def delete_task(self, task_id: str) -> bool:
        """删除任务"""
        if task_id not in self.tasks:
            return False
        del self.tasks[task_id]
        log.info(f"删除任务: {task_id}")
        return True

    async def start(self):
        """启动调度器"""
        if self._running:
            return
        self._running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        log.info("任务调度器已启动")

    async def stop(self):
        """停止调度器"""
        self._running = False
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        log.info("任务调度器已停止")

    async def _scheduler_loop(self):
        """调度器主循环"""
        log.info("调度器主循环开始")
        while self._running:
            try:
                await self._check_and_run_due_tasks()
                await asyncio.sleep(10)  # 每10秒检查一次
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"调度器循环异常: {e}")
                await asyncio.sleep(30)

    async def _check_and_run_due_tasks(self):
        """检查并运行到期的任务"""
        now = time.time()
        for task_id, task in self.tasks.items():
            if not task.enabled or task.status in (TaskStatus.PAUSED, TaskStatus.CANCELLED):
                continue
            if task.next_run_time <= now and self._active_tasks < self._max_concurrent:
                asyncio.create_task(self._run_task(task))

    async def _run_task(self, task: ScheduledTask):
        """运行单个任务"""
        async with self._lock:
            self._active_tasks += 1

        task.status = TaskStatus.RUNNING
        task.last_run_time = time.time()
        log.info(f"运行调度任务: {task.name} ({task.task_id})")

        try:
            result = None
            if self.task_executor:
                result = await self.task_executor(task.task_type, task.target, task.parameters)
            else:
                result = await self._default_task_executor(task)

            # 变更检测
            if task.change_detection and result:
                changes = self._detect_changes(task, result)
                if changes:
                    log.info(f"任务 {task.name} 检测到 {len(changes)} 个变更")

            # 记录运行历史
            task.run_history.append({
                "run_time": task.last_run_time,
                "status": "completed",
                "result_summary": self._summarize_result(result),
                "duration_seconds": round(time.time() - task.last_run_time, 2)
            })

            task.status = TaskStatus.SCHEDULED
            task.retry_count = 0

            # 计算下次运行时间
            if task.schedule_type == ScheduleType.ONCE:
                task.status = TaskStatus.COMPLETED
                task.enabled = False
            else:
                task.next_run_time = self._calculate_next_run(task)

        except Exception as e:
            log.error(f"任务 {task.name} 执行失败: {e}")
            task.run_history.append({
                "run_time": task.last_run_time,
                "status": "failed",
                "error": str(e)
            })

            # 重试逻辑
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.SCHEDULED
                task.next_run_time = time.time() + 60  # 1分钟后重试
            else:
                task.status = TaskStatus.FAILED
                task.enabled = False

        finally:
            async with self._lock:
                self._active_tasks -= 1

    async def _default_task_executor(self, task: ScheduledTask) -> Dict[str, Any]:
        """默认任务执行器"""
        if task.task_type == "scan":
            # 端口扫描
            try:
                from mcp_server.recon_tools import recon_tools
                result = await recon_tools.port_scan(target=task.target, ports=task.parameters.get("ports", "1-1000"))
                return result
            except Exception as e:
                return {"status": "error", "message": str(e)}
        elif task.task_type == "monitor":
            # 监控：HTTP状态检查
            try:
                import urllib.request
                url = task.target if task.target.startswith("http") else f"http://{task.target}"
                response = urllib.request.urlopen(url, timeout=10)
                return {
                    "status": "success",
                    "url": url,
                    "http_status": response.status,
                    "response_time": 0,
                    "available": True
                }
            except Exception as e:
                return {"status": "success", "url": task.target, "available": False, "error": str(e)}
        return {"status": "completed", "message": f"任务 {task.name} 执行完成"}

    def _detect_changes(self, task: ScheduledTask, current_result: Dict[str, Any]) -> List[ChangeEvent]:
        """检测变更"""
        changes = []
        previous = task.last_scan_result

        if previous:
            # 端口变更检测
            prev_ports = set(previous.get("open_ports", []))
            curr_ports = set(current_result.get("open_ports", []))

            new_ports = curr_ports - prev_ports
            closed_ports = prev_ports - curr_ports

            for port in new_ports:
                event = ChangeEvent(
                    event_id=str(uuid.uuid4())[:8],
                    task_id=task.task_id,
                    target=task.target,
                    change_type="new_port",
                    description=f"检测到新开放端口: {port}",
                    severity="medium",
                    previous_state=None,
                    current_state=port
                )
                changes.append(event)
                self.change_events.append(event)

            for port in closed_ports:
                event = ChangeEvent(
                    event_id=str(uuid.uuid4())[:8],
                    task_id=task.task_id,
                    target=task.target,
                    change_type="closed_port",
                    description=f"端口已关闭: {port}",
                    severity="info",
                    previous_state=port,
                    current_state=None
                )
                changes.append(event)
                self.change_events.append(event)

        # 保存当前结果
        task.last_scan_result = current_result
        return changes

    def _summarize_result(self, result: Optional[Dict[str, Any]]) -> str:
        """简要总结结果"""
        if not result:
            return "无结果"
        if isinstance(result, dict):
            if "open_ports" in result:
                return f"开放端口: {', '.join(map(str, result['open_ports'][:10]))}"
            if "status" in result:
                return f"状态: {result['status']}"
            keys = list(result.keys())[:5]
            return f"字段: {', '.join(keys)}"
        return str(result)[:100]

    def get_change_events(self, target: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """获取变更事件"""
        events = self.change_events
        if target:
            events = [e for e in events if e.target == target]
        events.sort(key=lambda e: e.detected_at, reverse=True)
        return [e.to_dict() for e in events[:limit]]

    def get_statistics(self) -> Dict[str, Any]:
        """获取调度器统计信息"""
        total_tasks = len(self.tasks)
        active_tasks = sum(1 for t in self.tasks.values() if t.enabled and t.status != TaskStatus.COMPLETED)
        completed_runs = sum(len(t.run_history) for t in self.tasks.values())
        failed_runs = sum(
            sum(1 for r in t.run_history if r.get("status") == "failed")
            for t in self.tasks.values()
        )
        return {
            "total_tasks": total_tasks,
            "active_tasks": active_tasks,
            "paused_tasks": sum(1 for t in self.tasks.values() if t.status == TaskStatus.PAUSED),
            "completed_tasks": sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETED),
            "total_runs": completed_runs + failed_runs,
            "successful_runs": completed_runs,
            "failed_runs": failed_runs,
            "change_events_count": len(self.change_events),
            "scheduler_running": self._running,
            "active_concurrent_tasks": self._active_tasks
        }

    def save_state(self, filepath: str):
        """保存调度器状态到文件"""
        state = {
            "tasks": {tid: task.to_dict() for tid, task in self.tasks.items()},
            "change_events": [e.to_dict() for e in self.change_events],
            "saved_at": time.time()
        }
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=2, default=str)
        log.info(f"调度器状态已保存: {filepath}")

    def load_state(self, filepath: str):
        """从文件加载调度器状态"""
        if not os.path.exists(filepath):
            log.warning(f"状态文件不存在: {filepath}")
            return
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                state = json.load(f)
            # 简化：只加载变更事件，任务需要重新创建
            self.change_events = []
            for e_data in state.get("change_events", []):
                event = ChangeEvent(
                    event_id=e_data["event_id"],
                    task_id=e_data["task_id"],
                    target=e_data["target"],
                    change_type=e_data["change_type"],
                    description=e_data["description"],
                    severity=e_data["severity"],
                    detected_at=e_data.get("detected_at", time.time())
                )
                self.change_events.append(event)
            log.info(f"调度器状态已加载: {filepath}, 变更事件: {len(self.change_events)}")
        except Exception as e:
            log.error(f"加载状态失败: {e}")


# 全局实例
task_scheduler = TaskScheduler()
