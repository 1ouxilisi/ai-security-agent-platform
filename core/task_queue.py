#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
任务队列系统
Task Queue System

功能：异步任务处理、任务优先级、失败重试、任务状态跟踪
"""

import os
import json
import time
import uuid
import threading
import queue
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Callable
from enum import Enum
from loguru import logger


class TaskStatus(str, Enum):
    """任务状态"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskPriority(int, Enum):
    """任务优先级"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Task:
    """任务"""
    task_id: str
    name: str
    task_type: str
    params: Dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.NORMAL
    progress: float = 0.0
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    duration: Optional[float] = None
    retries: int = 0
    max_retries: int = 3
    timeout: int = 3600  # 秒
    callback_url: Optional[str] = None
    created_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'name': self.name,
            'task_type': self.task_type,
            'params': self.params,
            'status': self.status.value,
            'priority': self.priority.value,
            'progress': self.progress,
            'result': self.result,
            'error': self.error,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'duration': self.duration,
            'retries': self.retries,
            'max_retries': self.max_retries,
            'timeout': self.timeout,
            'created_by': self.created_by,
        }


class TaskQueue:
    """任务队列"""

    def __init__(self, max_workers: int = 4, max_queue_size: int = 1000):
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        self._queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=max_queue_size)
        self._tasks: Dict[str, Task] = {}
        self._workers: List[threading.Thread] = []
        self._running = False
        self._lock = threading.Lock()
        self._task_handlers: Dict[str, Callable] = {}
        self._persistence_file = "data/task_queue.json"

        # 确保数据目录存在
        os.makedirs("data", exist_ok=True)

        logger.info(f"任务队列初始化完成: max_workers={max_workers}, max_queue_size={max_queue_size}")

    def register_handler(self, task_type: str, handler: Callable):
        """注册任务处理器"""
        self._task_handlers[task_type] = handler
        logger.info(f"注册任务处理器: {task_type}")

    def submit(self, name: str, task_type: str, params: Dict[str, Any] = None,
               priority: TaskPriority = TaskPriority.NORMAL,
               max_retries: int = 3, timeout: int = 3600,
               callback_url: str = None, created_by: str = None) -> Task:
        """提交任务"""
        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            name=name,
            task_type=task_type,
            params=params or {},
            priority=priority,
            max_retries=max_retries,
            timeout=timeout,
            callback_url=callback_url,
            created_by=created_by,
        )

        with self._lock:
            self._tasks[task_id] = task
            task.status = TaskStatus.QUEUED
            # 优先级队列使用负优先级（数值越大优先级越高）
            self._queue.put((-priority.value, task_id, task))

        logger.info(f"任务已提交: {task_id} ({name}), 优先级={priority.value}")
        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        """获取任务状态"""
        with self._lock:
            return self._tasks.get(task_id)

    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        with self._lock:
            task = self._tasks.get(task_id)
            if task and task.status in [TaskStatus.PENDING, TaskStatus.QUEUED]:
                task.status = TaskStatus.CANCELLED
                logger.info(f"任务已取消: {task_id}")
                return True
        return False

    def list_tasks(self, status: TaskStatus = None, limit: int = 50,
                    offset: int = 0) -> List[Task]:
        """列出任务"""
        with self._lock:
            tasks = list(self._tasks.values())
            if status:
                tasks = [t for t in tasks if t.status == status]
            tasks.sort(key=lambda t: t.created_at, reverse=True)
            return tasks[offset:offset + limit]

    def get_stats(self) -> Dict[str, Any]:
        """获取队列统计"""
        with self._lock:
            total = len(self._tasks)
            pending = len([t for t in self._tasks.values() if t.status == TaskStatus.PENDING])
            queued = len([t for t in self._tasks.values() if t.status == TaskStatus.QUEUED])
            running = len([t for t in self._tasks.values() if t.status == TaskStatus.RUNNING])
            success = len([t for t in self._tasks.values() if t.status == TaskStatus.SUCCESS])
            failed = len([t for t in self._tasks.values() if t.status == TaskStatus.FAILED])

            return {
                'total': total,
                'pending': pending,
                'queued': queued,
                'running': running,
                'success': success,
                'failed': failed,
                'queue_size': self._queue.qsize(),
                'workers': len(self._workers),
                'is_running': self._running,
            }

    def start(self):
        """启动Worker"""
        if self._running:
            logger.warning("任务队列已在运行")
            return

        self._running = True
        for i in range(self.max_workers):
            worker = threading.Thread(target=self._worker_loop, args=(i,), daemon=True)
            worker.start()
            self._workers.append(worker)

        logger.info(f"任务队列已启动: {self.max_workers}个Worker")

    def stop(self, wait: bool = True):
        """停止Worker"""
        self._running = False
        if wait:
            for worker in self._workers:
                worker.join(timeout=10)
        self._workers.clear()
        logger.info("任务队列已停止")

    def _worker_loop(self, worker_id: int):
        """Worker循环"""
        logger.debug(f"Worker {worker_id} 启动")

        while self._running:
            try:
                # 从队列获取任务（带超时，便于检查_running标志）
                try:
                    _, task_id, task = self._queue.get(timeout=1)
                except queue.Empty:
                    continue

                # 执行任务
                self._execute_task(task, worker_id)

            except Exception as e:
                logger.error(f"Worker {worker_id} 异常: {e}")

        logger.debug(f"Worker {worker_id} 停止")

    def _execute_task(self, task: Task, worker_id: int):
        """执行任务"""
        with self._lock:
            if task.status != TaskStatus.QUEUED:
                return
            task.status = TaskStatus.RUNNING
            task.started_at = time.time()

        logger.info(f"Worker {worker_id} 开始执行任务: {task.task_id} ({task.name})")

        try:
            # 查找处理器
            handler = self._task_handlers.get(task.task_type)
            if not handler:
                raise ValueError(f"未找到任务处理器: {task.task_type}")

            # 执行任务
            result = handler(task.params)
            task.result = result if isinstance(result, dict) else {'result': str(result)}
            task.status = TaskStatus.SUCCESS
            task.progress = 100.0
            logger.info(f"任务执行成功: {task.task_id}")

        except Exception as e:
            task.error = str(e)
            logger.error(f"任务执行失败: {task.task_id}: {e}")

            # 重试逻辑
            if task.retries < task.max_retries:
                task.retries += 1
                task.status = TaskStatus.QUEUED
                task.error = None
                with self._lock:
                    self._queue.put((-task.priority.value, task.task_id, task))
                logger.info(f"任务重试 ({task.retries}/{task.max_retries}): {task.task_id}")
            else:
                task.status = TaskStatus.FAILED

        finally:
            task.completed_at = time.time()
            if task.started_at:
                task.duration = task.completed_at - task.started_at

            # 持久化
            self._persist()

            # 回调
            if task.callback_url and task.status == TaskStatus.SUCCESS:
                self._execute_callback(task)

    def _execute_callback(self, task: Task):
        """执行回调"""
        try:
            import requests
            requests.post(task.callback_url, json=task.to_dict(), timeout=10)
        except Exception as e:
            logger.warning(f"回调执行失败: {e}")

    def _persist(self):
        """持久化任务状态"""
        try:
            with self._lock:
                tasks_data = [t.to_dict() for t in list(self._tasks.values())[-1000:]]  # 只保留最近1000个
            with open(self._persistence_file, 'w', encoding='utf-8') as f:
                json.dump(tasks_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"任务状态持久化失败: {e}")

    def load_persistence(self):
        """加载持久化的任务状态"""
        try:
            if os.path.exists(self._persistence_file):
                with open(self._persistence_file, 'r', encoding='utf-8') as f:
                    tasks_data = json.load(f)
                with self._lock:
                    for data in tasks_data:
                        # 只恢复非运行中的任务
                        if data.get('status') != 'running':
                            task = Task(**{k: v for k, v in data.items() if k in Task.__dataclass_fields__})
                            self._tasks[task.task_id] = task
                logger.info(f"加载了 {len(tasks_data)} 个历史任务")
        except Exception as e:
            logger.warning(f"加载任务状态失败: {e}")


# 全局任务队列实例
_global_task_queue: Optional[TaskQueue] = None


def get_task_queue() -> TaskQueue:
    """获取全局任务队列实例"""
    global _global_task_queue
    if _global_task_queue is None:
        _global_task_queue = TaskQueue(max_workers=4)
        _global_task_queue.load_persistence()
        _global_task_queue.start()
    return _global_task_queue


def submit_task(name: str, task_type: str, params: Dict[str, Any] = None,
                priority: TaskPriority = TaskPriority.NORMAL, **kwargs) -> Task:
    """提交任务（便捷函数）"""
    queue = get_task_queue()
    return queue.submit(name=name, task_type=task_type, params=params, priority=priority, **kwargs)


def get_task_status(task_id: str) -> Optional[Dict[str, Any]]:
    """获取任务状态（便捷函数）"""
    queue = get_task_queue()
    task = queue.get_task(task_id)
    return task.to_dict() if task else None
