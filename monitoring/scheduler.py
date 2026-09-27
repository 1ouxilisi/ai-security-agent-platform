"""定时任务调度器模块。

提供：
- ScheduledTask: 定时任务描述
- TaskScheduler: 后台线程调度，支持 cron / interval 两种调度方式，
  并发控制（最多同时运行 3 个任务）、失败重试（最多 3 次）、执行历史落盘。

cron 表达式为标准 5 段（分 时 日 月 周），未安装 croniter 时使用内置简易解析，
支持 ``*`` 与具体数字（如 ``*/5`` 暂不支持，按数字精确匹配）。
"""
import os
import json
import time
import uuid
import threading
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Any

from utils.logger import log

try:
    from croniter import croniter  # type: ignore
    _HAS_CRONITER = True
except Exception:  # pragma: no cover - croniter 可能未安装
    _HAS_CRONITER = False


# 数据目录
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
MONITORING_DIR = os.path.join(DATA_DIR, "monitoring")
os.makedirs(MONITORING_DIR, exist_ok=True)

HISTORY_FILE = os.path.join(MONITORING_DIR, "scheduler_history.json")
SCHEDULED_FILE = os.path.join(MONITORING_DIR, "scheduled_tasks.json")

MAX_CONCURRENT_RUNS = 3
MAX_RETRIES = 3


# --------------------------------------------------------------------------
# 简易 cron 解析（5 段：分 时 日 月 周）
# --------------------------------------------------------------------------
def _field_matches(field: str, value: int) -> bool:
    """单个 cron 字段匹配。支持 ``*``、``数字``、``数字,数字``、``a-b``。"""
    field = field.strip()
    if field == "*":
        return True
    # 列表
    if "," in field:
        return any(_field_matches(part, value) for part in field.split(","))
    # 范围
    if "-" in field and not field.startswith("*/"):
        try:
            lo, hi = field.split("-", 1)
            return int(lo) <= value <= int(hi)
        except ValueError:
            return False
    # 步进（如 */5）按整除近似处理
    if field.startswith("*/"):
        try:
            step = int(field[2:])
            return value % step == 0
        except ValueError:
            return False
    try:
        return int(field) == value
    except ValueError:
        return False


def cron_matches(cron_expr: str, dt: datetime) -> bool:
    """判断给定时间是否匹配 5 段 cron 表达式。"""
    parts = cron_expr.split()
    if len(parts) != 5:
        log.warning(f"非法 cron 表达式(需5段): {cron_expr}")
        return False
    minute, hour, dom, month, dow = parts
    # datetime.weekday(): 周一=0 ... 周日=6；cron 中 0/7 表示周日
    wd = dt.weekday()
    dow_val = 6 if wd == 6 else wd  # 内部统一: 周一=0..周六=5..周日=6
    # cron 周字段：0/7=周日,1=周一...6=周六
    dow_map = {6: "0,7", 0: "1", 1: "2", 2: "3", 3: "4", 4: "5", 5: "6"}
    return (_field_matches(minute, dt.minute)
            and _field_matches(hour, dt.hour)
            and _field_matches(dom, dt.day)
            and _field_matches(month, dt.month)
            and _field_matches(dow, dow_map[dow_val]))


def compute_next_run(schedule_type: str, cron_expression: Optional[str],
                     interval_seconds: Optional[int], now: float) -> float:
    """计算下一次运行时间（epoch 秒）。"""
    from datetime import timedelta
    if schedule_type == "interval":
        iv = int(interval_seconds or 60)
        return now + iv
    # cron：逐分钟向前找下一个匹配（最多扫描 ~31 天）
    cur = datetime.fromtimestamp(now).replace(second=0, microsecond=0)
    for _ in range(60 * 24 * 31):
        cur = cur + timedelta(minutes=1)
        if cron_matches(cron_expression, cur):
            return cur.timestamp()
    return now + 3600


# --------------------------------------------------------------------------
# 数据类
# --------------------------------------------------------------------------
class ScheduledTask:
    """定时任务。"""

    def __init__(self, task_id: str, name: str, target: str, scan_type: str,
                 schedule_type: str = "interval",
                 cron_expression: Optional[str] = None,
                 interval_seconds: Optional[int] = None,
                 options: Optional[Dict[str, Any]] = None,
                 enabled: bool = True):
        self.task_id = task_id
        self.name = name
        self.target = target
        self.scan_type = scan_type
        self.schedule_type = schedule_type          # cron / interval
        self.cron_expression = cron_expression
        self.interval_seconds = interval_seconds
        self.options = options or {}
        self.enabled = enabled
        self.last_run_at: float = 0
        self.next_run_at: float = compute_next_run(
            schedule_type, cron_expression, interval_seconds, time.time())
        self.run_count = 0
        self.status = "idle"                          # idle / running / success / failed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "target": self.target,
            "scan_type": self.scan_type,
            "schedule_type": self.schedule_type,
            "cron_expression": self.cron_expression,
            "interval_seconds": self.interval_seconds,
            "options": self.options,
            "enabled": self.enabled,
            "last_run_at": self.last_run_at,
            "next_run_at": self.next_run_at,
            "run_count": self.run_count,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScheduledTask":
        t = cls(
            task_id=data["task_id"],
            name=data.get("name", ""),
            target=data.get("target", ""),
            scan_type=data.get("scan_type", "port_scan"),
            schedule_type=data.get("schedule_type", "interval"),
            cron_expression=data.get("cron_expression"),
            interval_seconds=data.get("interval_seconds"),
            options=data.get("options", {}),
            enabled=data.get("enabled", True),
        )
        t.last_run_at = data.get("last_run_at", 0)
        t.next_run_at = data.get("next_run_at", t.next_run_at)
        t.run_count = data.get("run_count", 0)
        t.status = data.get("status", "idle")
        return t


class TaskScheduler:
    """定时任务调度器。"""

    def __init__(self):
        self._tasks: Dict[str, ScheduledTask] = {}
        self._history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._active_runs = 0          # 当前并发运行数
        self._run_cond = threading.Condition(self._lock)
        self._load()
        self._load_history()
        self.start()

    # ---------------- 持久化 ----------------
    def _load(self):
        if not os.path.exists(SCHEDULED_FILE):
            return
        try:
            with open(SCHEDULED_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                t = ScheduledTask.from_dict(item)
                self._tasks[t.task_id] = t
            log.info(f"加载定时任务 {len(data)} 个")
        except Exception as e:
            log.warning(f"加载定时任务失败: {e}")

    def _save(self):
        try:
            with open(SCHEDULED_FILE, "w", encoding="utf-8") as f:
                json.dump([t.to_dict() for t in self._tasks.values()],
                          f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.warning(f"保存定时任务失败: {e}")

    def _load_history(self):
        if not os.path.exists(HISTORY_FILE):
            return
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                self._history = json.load(f)
        except Exception as e:
            log.warning(f"加载调度历史失败: {e}")

    def _save_history(self):
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self._history[-500:], f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.warning(f"保存调度历史失败: {e}")

    # ---------------- 生命周期 ----------------
    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._scheduler_loop, daemon=True,
                                        name="task-scheduler")
        self._thread.start()
        log.info("定时任务调度器已启动")

    def stop(self):
        self._running = False
        with self._run_cond:
            self._run_cond.notify_all()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("定时任务调度器已停止")

    # ---------------- CRUD ----------------
    def add_task(self, name: str, target: str, scan_type: str,
                 schedule_type: str = "interval",
                 cron_expression: Optional[str] = None,
                 interval_seconds: Optional[int] = None,
                 options: Optional[Dict[str, Any]] = None) -> ScheduledTask:
        task = ScheduledTask(
            task_id=str(uuid.uuid4())[:8],
            name=name, target=target, scan_type=scan_type,
            schedule_type=schedule_type, cron_expression=cron_expression,
            interval_seconds=interval_seconds, options=options or {},
        )
        with self._lock:
            self._tasks[task.task_id] = task
        self._save()
        log.info(f"添加定时任务: {name} ({task.task_id})")
        return task

    def remove_task(self, task_id: str) -> bool:
        with self._lock:
            if task_id in self._tasks:
                del self._tasks[task_id]
                self._save()
                return True
            return False

    def update_task(self, task_id: str, **kwargs) -> bool:
        with self._lock:
            t = self._tasks.get(task_id)
            if not t:
                return False
            for k, v in kwargs.items():
                if hasattr(t, k):
                    setattr(t, k, v)
            # 调度参数变化时重算 next_run
            if k in ("schedule_type", "cron_expression", "interval_seconds"):
                t.next_run_at = compute_next_run(
                    t.schedule_type, t.cron_expression, t.interval_seconds, time.time())
            self._save()
            return True

    def list_tasks(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._tasks.values())
        if enabled_only:
            items = [t for t in items if t.enabled]
        return [t.to_dict() for t in items]

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            t = self._tasks.get(task_id)
            return t.to_dict() if t else None

    def enable_task(self, task_id: str) -> bool:
        return self.update_task(task_id, enabled=True)

    def disable_task(self, task_id: str) -> bool:
        return self.update_task(task_id, enabled=False)

    def get_task_history(self, task_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            rows = [h for h in self._history if h.get("task_id") == task_id]
        rows.sort(key=lambda h: h.get("started_at", 0), reverse=True)
        return rows[:limit]

    def run_task_now(self, task_id: str) -> bool:
        """立即触发一次任务执行（异步线程）。"""
        with self._lock:
            t = self._tasks.get(task_id)
            if not t:
                return False
        threading.Thread(target=self._execute_task, args=(t,), daemon=True,
                         name=f"run-{task_id}").start()
        return True

    # ---------------- 核心循环 ----------------
    def _scheduler_loop(self):
        while self._running:
            try:
                now = time.time()
                due: List[ScheduledTask] = []
                with self._lock:
                    for t in self._tasks.values():
                        if t.enabled and t.status != "running" and t.next_run_at <= now:
                            due.append(t)
                for t in due:
                    # 并发控制：等待可用槽位
                    with self._run_cond:
                        while self._running and self._active_runs >= MAX_CONCURRENT_RUNS:
                            self._run_cond.wait(timeout=1)
                        if not self._running:
                            break
                        self._active_runs += 1
                        t.status = "running"
                    threading.Thread(target=self._execute_task, args=(t,),
                                     daemon=True, name=f"sched-{t.task_id}").start()
                time.sleep(1)
            except Exception as e:
                log.warning(f"调度循环异常: {e}")
                time.sleep(1)

    def _execute_task(self, scheduled_task: ScheduledTask):
        """执行任务，记录历史，失败重试最多 MAX_RETRIES 次。"""
        started = time.time()
        success = False
        error = ""
        try:
            for attempt in range(1, MAX_RETRIES + 1):
                try:
                    self._do_scan(scheduled_task)
                    success = True
                    break
                except Exception as e:
                    error = f"第{attempt}次尝试失败: {e}"
                    log.warning(f"任务 {scheduled_task.task_id} {error}")
                    if attempt < MAX_RETRIES:
                        time.sleep(1)
        finally:
            elapsed = time.time() - started
            with self._lock:
                scheduled_task.last_run_at = started
                scheduled_task.run_count += 1
                scheduled_task.status = "success" if success else "failed"
                # 计算下次运行时间
                scheduled_task.next_run_at = compute_next_run(
                    scheduled_task.schedule_type,
                    scheduled_task.cron_expression,
                    scheduled_task.interval_seconds,
                    time.time())
                self._history.append({
                    "history_id": str(uuid.uuid4())[:8],
                    "task_id": scheduled_task.task_id,
                    "name": scheduled_task.name,
                    "target": scheduled_task.target,
                    "scan_type": scheduled_task.scan_type,
                    "started_at": started,
                    "finished_at": time.time(),
                    "elapsed_seconds": round(elapsed, 2),
                    "success": success,
                    "error": error,
                    "attempts": MAX_RETRIES,
                })
                self._save_history()
                self._save()
                # 释放并发槽位
                self._active_runs = max(0, self._active_runs - 1)
                with self._run_cond:
                    self._run_cond.notify_all()

    def _do_scan(self, task: ScheduledTask):
        """实际执行扫描：优先调用 tools.integration，不可用则模拟。"""
        try:
            from tools import integration  # type: ignore
            func = getattr(integration, task.scan_type, None)
            if callable(func):
                func(task.target, **(task.options or {}))
                return
        except Exception as e:
            log.debug(f"tools.integration 不可用，使用模拟执行: {e}")
        # 模拟执行
        time.sleep(0.2)
        log.info(f"[模拟执行] 任务 {task.task_id} 对 {task.target} 执行 {task.scan_type}")


# 模块级单例
_scheduler_instance: Optional[TaskScheduler] = None


def get_scheduler() -> TaskScheduler:
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = TaskScheduler()
    return _scheduler_instance
