"""
scan_engine安全工具集成模块，提供相关安全工具的封装和调用。

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
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from utils.logger import log


@dataclass
class ScanTask:
    """扫描任务"""
    task_id: str
    name: str
    func: Callable[..., Coroutine]
    args: Tuple = ()
    kwargs: Dict = field(default_factory=dict)
    priority: int = 5  # 1-10, 10最高
    max_retries: int = 3
    timeout: int = 30
    status: str = "pending"  # pending/running/completed/failed/skipped
    result: Any = None
    error: Optional[str] = None
    retries: int = 0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    duration: float = 0


@dataclass
class ScanResult:
    """扫描结果聚合"""
    scan_id: str
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    skipped_tasks: int = 0
    results: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    started_at: float = 0
    completed_at: float = 0
    duration: float = 0

    @property
    def success_rate(self) -> float:
        """执行相关操作。

        Returns:
            操作结果。
        """
        if self.total_tasks == 0:
            return 0.0
        return round(self.completed_tasks / self.total_tasks * 100, 2)

    @property
    def progress(self) -> float:
        """执行相关操作。

        Returns:
            操作结果。
        """
        if self.total_tasks == 0:
            return 100.0
        return round((self.completed_tasks + self.failed_tasks + self.skipped_tasks) / self.total_tasks * 100, 2)


class ScanEngine:
    """
    企业级扫描引擎
    支持：并发控制、超时管理、指数退避重试、速率限制、进度跟踪、结果聚合
    """

    def __init__(self, max_concurrent: int = 10, rate_limit: float = 0.1,
                 default_timeout: int = 30, default_retries: int = 3):
        """
        初始化扫描引擎
        :param max_concurrent: 最大并发数
        :param rate_limit: 速率限制（秒/请求）
        :param default_timeout: 默认超时（秒）
        :param default_retries: 默认重试次数
        """
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.default_timeout = default_timeout
        self.default_retries = default_retries
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._last_request_time = 0
        self._active_scans: Dict[str, ScanResult] = {}
        self._task_queue: List[ScanTask] = []
        log.info(f"扫描引擎初始化: 并发={max_concurrent}, 速率限制={rate_limit}s, 超时={default_timeout}s")

    async def _rate_limit_wait(self):
        """速率限制等待"""
        if self.rate_limit > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit:
                await asyncio.sleep(self.rate_limit - elapsed)
            self._last_request_time = time.time()

    async def _execute_task(self, task: ScanTask, scan_result: ScanResult) -> ScanTask:
        """
        执行单个扫描任务（含重试和超时）
        """
        async with self._semaphore:
            task.status = "running"
            task.started_at = time.time()

            for attempt in range(task.max_retries + 1):
                task.retries = attempt
                try:
                    await self._rate_limit_wait()

                    # 执行任务，带超时
                    coro = task.func(*task.args, **task.kwargs)
                    task.result = await asyncio.wait_for(coro, timeout=task.timeout)

                    task.status = "completed"
                    task.completed_at = time.time()
                    task.duration = round(task.completed_at - task.started_at, 2)
                    scan_result.completed_tasks += 1
                    scan_result.results[task.task_id] = task.result

                    log.debug(f"任务完成: {task.name}, 耗时: {task.duration}s, 重试: {attempt}")
                    return task

                except asyncio.TimeoutError:
                    task.error = f"超时（{task.timeout}秒）"
                    if attempt < task.max_retries:
                        wait_time = min(2 ** attempt, 10)  # 指数退避，最大10秒
                        log.warning(f"任务超时，{wait_time}秒后重试 ({attempt+1}/{task.max_retries}): {task.name}")
                        await asyncio.sleep(wait_time)
                        continue
                    break

                except Exception as e:
                    task.error = str(e)
                    if attempt < task.max_retries:
                        wait_time = min(2 ** attempt, 10)
                        log.warning(f"任务失败，{wait_time}秒后重试 ({attempt+1}/{task.max_retries}): {task.name} - {e}")
                        await asyncio.sleep(wait_time)
                        continue
                    break

            # 所有重试都失败
            task.status = "failed"
            task.completed_at = time.time()
            task.duration = round(task.completed_at - task.started_at, 2)
            scan_result.failed_tasks += 1
            scan_result.errors[task.task_id] = task.error or "未知错误"
            log.error(f"任务最终失败: {task.name}, 错误: {task.error}")
            return task

    async def scan(self, tasks: List[ScanTask], scan_id: Optional[str] = None) -> ScanResult:
        """
        执行批量扫描
        :param tasks: 扫描任务列表
        :param scan_id: 扫描ID（可选，自动生成）
        :return: 扫描结果聚合
        """
        if not tasks:
            log.warning("没有扫描任务")
            return ScanResult(scan_id=scan_id or "empty")

        scan_id = scan_id or f"scan_{int(time.time())}"
        scan_result = ScanResult(
            scan_id=scan_id,
            total_tasks=len(tasks),
            started_at=time.time(),
        )
        self._active_scans[scan_id] = scan_result

        log.info(f"开始扫描: {scan_id}, 任务数: {len(tasks)}, 并发: {self.max_concurrent}")

        # 按优先级排序（高优先级先执行）
        sorted_tasks = sorted(tasks, key=lambda t: t.priority, reverse=True)

        # 并发执行所有任务
        coroutines = [self._execute_task(task, scan_result) for task in sorted_tasks]
        await asyncio.gather(*coroutines, return_exceptions=True)

        scan_result.completed_at = time.time()
        scan_result.duration = round(scan_result.completed_at - scan_result.started_at, 2)

        log.info(f"扫描完成: {scan_id}, 成功: {scan_result.completed_tasks}, "
                 f"失败: {scan_result.failed_tasks}, 成功率: {scan_result.success_rate}%, "
                 f"耗时: {scan_result.duration}s")

        # 清理活跃扫描
        del self._active_scans[scan_id]

        return scan_result

    def create_task(self, name: str, func: Callable[..., Coroutine],
                    args: Tuple = (), kwargs: Optional[Dict] = None,
                    priority: int = 5, timeout: Optional[int] = None,
                    max_retries: Optional[int] = None) -> ScanTask:
        """创建扫描任务"""
        import uuid
        return ScanTask(
            task_id=str(uuid.uuid4())[:8],
            name=name,
            func=func,
            args=args,
            kwargs=kwargs or {},
            priority=priority,
            timeout=timeout or self.default_timeout,
            max_retries=max_retries if max_retries is not None else self.default_retries,
        )

    def get_scan_status(self, scan_id: str) -> Optional[ScanResult]:
        """获取扫描状态"""
        return self._active_scans.get(scan_id)

    def get_all_active_scans(self) -> Dict[str, ScanResult]:
        """获取所有活跃扫描"""
        return dict(self._active_scans)

    async def port_scan_batch(self, target: str, ports: List[int],
                               scan_func: Callable, max_concurrent: int = 50,
                               timeout: int = 2) -> ScanResult:
        """
        批量端口扫描（便捷方法）
        :param target: 目标地址
        :param ports: 端口列表
        :param scan_func: 单个端口扫描函数
        :param max_concurrent: 最大并发
        :param timeout: 超时
        :return: 扫描结果
        """
        original_concurrent = self.max_concurrent
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

        tasks = [
            self.create_task(
                name=f"port_{port}",
                func=scan_func,
                args=(target, port),
                priority=5,
                timeout=timeout,
                max_retries=1,
            )
            for port in ports
        ]

        try:
            result = await self.scan(tasks, scan_id=f"port_scan_{target}")
            return result
        finally:
            self.max_concurrent = original_concurrent
            self._semaphore = asyncio.Semaphore(original_concurrent)

    async def directory_bruteforce(self, base_url: str, paths: List[str],
                                    request_func: Callable, max_concurrent: int = 20,
                                    timeout: int = 5) -> ScanResult:
        """
        目录爆破（便捷方法）
        """
        original_concurrent = self.max_concurrent
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

        tasks = [
            self.create_task(
                name=f"path_{path}",
                func=request_func,
                args=(f"{base_url}/{path}",),
                priority=5,
                timeout=timeout,
                max_retries=2,
            )
            for path in paths
        ]

        try:
            result = await self.scan(tasks, scan_id=f"dir_brute_{base_url}")
            return result
        finally:
            self.max_concurrent = original_concurrent
            self._semaphore = asyncio.Semaphore(original_concurrent)

    def get_engine_stats(self) -> Dict:
        """获取引擎统计"""
        return {
            "max_concurrent": self.max_concurrent,
            "rate_limit": self.rate_limit,
            "default_timeout": self.default_timeout,
            "default_retries": self.default_retries,
            "active_scans": len(self._active_scans),
            "active_scan_ids": list(self._active_scans.keys()),
        }


# 全局单例
scan_engine = ScanEngine(max_concurrent=10, rate_limit=0.1)
