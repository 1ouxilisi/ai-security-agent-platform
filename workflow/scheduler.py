#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
workflow/scheduler.py — Round 7 新增：工作流调度器。

功能：
    - 支持 cron / interval 两种调度方式
    - 后台线程每 15 秒扫描到期任务，调用 dag_engine 异步执行
    - 并发限制：最多同时执行 3 个工作流
    - 执行历史记录与重跑

仅用于授权安全评估场景的自动化排程。
"""
import time
import uuid
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional


def _parse_cron_field(field: str, max_val: int) -> List[int]:
    """解析单个 cron 字段（支持 *, a,b, a-b, */n）。"""
    field = field.strip()
    vals: List[int] = []
    if field == "*":
        return list(range(max_val))
    for part in field.split(","):
        part = part.strip()
        if part.startswith("*/"):
            step = int(part[2:])
            vals.extend(range(0, max_val, step))
        elif "-" in part:
            lo, hi = part.split("-", 1)
            vals.extend(range(int(lo), int(hi) + 1))
        else:
            vals.append(int(part))
    return sorted(set(v for v in vals if 0 <= v < max_val))


def _match_cron(cron_expr: str, dt: datetime) -> bool:
    """简易 cron 匹配：分 时 日 月 周。"""
    try:
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return False
        minute, hour, dom, month, dow = parts
        return (
            dt.minute in _parse_cron_field(minute, 60)
            and dt.hour in _parse_cron_field(hour, 24)
            and dt.day in _parse_cron_field(dom, 32)
            and dt.month in _parse_cron_field(month, 13)
            and dt.weekday() in _parse_cron_field(dow, 7)
        )
    except Exception:
        return False


class WorkflowScheduler:
    """工作流调度器"""

    MAX_CONCURRENCY = 3
    TICK_SECONDS = 15

    def __init__(self):
        self._lock = threading.RLock()
        self._schedules: Dict[str, Dict[str, Any]] = {}
        self._history: List[Dict[str, Any]] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running_count = 0

    # ---------- 调度管理 ----------
    def add_schedule(self, workflow_template_id: str, target: str,
                     schedule_type: str = "interval",
                     cron_expr: Optional[str] = None,
                     interval_minutes: Optional[int] = None,
                     params: Optional[Dict[str, Any]] = None) -> str:
        """创建定时任务。schedule_type: cron / interval。"""
        schedule_id = str(uuid.uuid4())[:8]
        now = time.time()
        sched = {
            "schedule_id": schedule_id,
            "workflow_template_id": workflow_template_id,
            "target": target,
            "schedule_type": schedule_type,
            "cron_expr": cron_expr,
            "interval_minutes": interval_minutes,
            "params": params or {},
            "enabled": True,
            "created_at": datetime.now().isoformat(),
            "last_run": None,
            "next_run_hint": None,
            "run_count": 0,
        }
        with self._lock:
            self._schedules[schedule_id] = sched
        return schedule_id

    def remove_schedule(self, schedule_id: str) -> bool:
        with self._lock:
            if schedule_id in self._schedules:
                del self._schedules[schedule_id]
                return True
            return False

    def list_schedules(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._schedules.values())

    def enable_schedule(self, schedule_id: str) -> bool:
        with self._lock:
            s = self._schedules.get(schedule_id)
            if s:
                s["enabled"] = True
                return True
            return False

    def disable_schedule(self, schedule_id: str) -> bool:
        with self._lock:
            s = self._schedules.get(schedule_id)
            if s:
                s["enabled"] = False
                return True
            return False

    # ---------- 执行 ----------
    def _trigger(self, sched: Dict[str, Any]):
        """触发一次执行（在调度线程中调用）。"""
        try:
            from workflow.engine import dag_engine
            from workflow.templates import instantiate_template
        except Exception as e:
            self._history.append({
                "execution_id": str(uuid.uuid4())[:8],
                "schedule_id": sched["schedule_id"],
                "template": sched["workflow_template_id"],
                "target": sched["target"],
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
                "status": "failed",
                "result_summary": f"模块导入失败: {e}",
            })
            return

        if self._running_count >= self.MAX_CONCURRENCY:
            return

        try:
            wf_def = instantiate_template(
                sched["workflow_template_id"],
                sched["target"],
                sched["params"],
            )
        except Exception as e:
            self._history.append({
                "execution_id": str(uuid.uuid4())[:8],
                "schedule_id": sched["schedule_id"],
                "template": sched["workflow_template_id"],
                "target": sched["target"],
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
                "status": "failed",
                "result_summary": f"模板实例化失败: {e}",
            })
            return

        inst = dag_engine.create_instance(
            name=wf_def["name"],
            target=wf_def["target"],
            steps_def=wf_def["steps"],
            description=wf_def.get("description", ""),
            params=wf_def.get("params", {}),
        )
        self._running_count += 1

        record = {
            "execution_id": inst.instance_id,
            "schedule_id": sched["schedule_id"],
            "template": sched["workflow_template_id"],
            "target": sched["target"],
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "status": "running",
            "result_summary": None,
        }
        with self._lock:
            self._history.append(record)
            sched["last_run"] = record["start_time"]
            sched["run_count"] += 1

        def _done():
            try:
                inst_holder = dag_engine.get_instance(inst.instance_id)
                # 等待后台线程完成
                for _ in range(600):  # 最多等 10 分钟
                    if inst_holder and inst_holder.status.value in (
                        "completed", "failed", "cancelled"
                    ):
                        break
                    time.sleep(1)
                    inst_holder = dag_engine.get_instance(inst.instance_id)
                agg = (inst_holder.aggregated_result or {}) if inst_holder else {}
                record["end_time"] = datetime.now().isoformat()
                record["status"] = (inst_holder.status.value if inst_holder else "unknown")
                summary = agg.get("summary", {})
                record["result_summary"] = (
                    f"步骤{summary.get('completed',0)}/{summary.get('total_steps',0)}, "
                    f"漏洞{summary.get('vulnerabilities_count',0)}, "
                    f"风险分{agg.get('risk_score','-')}"
                )
            finally:
                self._running_count -= 1

        threading.Thread(target=_done, daemon=True).start()
        dag_engine.start_async(inst.instance_id)

    # ---------- 调度主循环 ----------
    def _loop(self):
        last_minute_key: Dict[str, float] = {}
        while not self._stop_event.is_set():
            try:
                now = datetime.now()
                with self._lock:
                    scheds = list(self._schedules.values())
                for s in scheds:
                    if not s.get("enabled", True):
                        continue
                    if self._running_count >= self.MAX_CONCURRENCY:
                        continue
                    due = False
                    if s["schedule_type"] == "interval" and s.get("interval_minutes"):
                        key = s["schedule_id"]
                        last = last_minute_key.get(key, 0)
                        if time.time() - last >= int(s["interval_minutes"]) * 60:
                            due = True
                            last_minute_key[key] = time.time()
                    elif s["schedule_type"] == "cron" and s.get("cron_expr"):
                        if _match_cron(s["cron_expr"], now):
                            key = f"{s['schedule_id']}_{now.strftime('%Y%m%d%H%M')}"
                            if last_minute_key.get(key, 0) == 0:
                                due = True
                                last_minute_key[key] = time.time()
                                last_minute_key[s["schedule_id"]] = time.time()
                    if due:
                        self._trigger(s)
            except Exception:
                pass
            self._stop_event.wait(self.TICK_SECONDS)

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._stop_event.set()

    # ---------- 历史 ----------
    def get_history(self, limit: int = 50, offset: int = 0,
                    status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(reversed(self._history))
        if status:
            items = [x for x in items if x.get("status") == status]
        return items[offset:offset + limit]

    def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for x in self._history:
                if x.get("execution_id") == execution_id:
                    return dict(x)
        return None

    def rerun_execution(self, execution_id: str) -> Optional[str]:
        """按历史记录重跑一次（重新创建实例）。返回新的 instance_id。"""
        rec = self.get_execution(execution_id)
        if not rec:
            return None
        try:
            from workflow.engine import dag_engine
            from workflow.templates import instantiate_template
            wf_def = instantiate_template(rec["template"], rec["target"], {})
            inst = dag_engine.create_instance(
                name=wf_def["name"] + "(重跑)",
                target=wf_def["target"],
                steps_def=wf_def["steps"],
                description=wf_def.get("description", ""),
                params=wf_def.get("params", {}),
            )
            dag_engine.start_async(inst.instance_id)
            return inst.instance_id
        except Exception:
            return None


# 全局单例
scheduler = WorkflowScheduler()


__all__ = ["WorkflowScheduler", "scheduler"]
