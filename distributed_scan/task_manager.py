# -*- coding: utf-8 -*-
"""
task_manager.py — 扫描任务管理器（第23轮升级 · 方向2）。

职责：
- 任务创建：目标配置 / 扫描配置 / 调度配置 / 通知配置 / 资源配置
- 任务状态：待执行/排队中/执行中/暂停/完成/失败/取消/超时
- 任务控制：启动/暂停/继续/取消/重试/优先级调整/资源调整
- 任务监控：实时进度/当前阶段/已发现漏洞/已扫描端口/扫描速度/预计完成时间
- 任务历史：历史列表/搜索/对比/导出/归档
- 任务模板：常用配置模板/模板管理/模板分享/模板版本

底层复用 cluster_arch 的集群运行时，本模块面向"任务"这一领域对象做封装。
"""

from __future__ import annotations

import copy
import json
import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .cluster_arch import get_cluster_state


# ==================== 任务状态机 ====================

TASK_STATES = [
    "pending", "queued", "running", "paused",
    "completed", "failed", "canceled", "timeout",
]

STATE_CN = {
    "pending": "待执行", "queued": "排队中", "running": "执行中",
    "paused": "已暂停", "completed": "已完成", "failed": "失败",
    "canceled": "已取消", "timeout": "已超时", "dead_letter": "死信",
}


class TaskManager:
    """扫描任务的领域管理：CRUD + 控制 + 监控 + 历史 + 模板。"""

    def __init__(self) -> None:
        self.templates: Dict[str, Dict[str, Any]] = {}
        self.archives: List[Dict[str, Any]] = []
        self.notifications: Dict[str, Dict[str, Any]] = {}
        self._seed_templates()

    # ---------- 模板 ----------
    def _seed_templates(self) -> None:
        seeds = [
            {"name": "快速端口扫描", "desc": "1-1000 常用端口快速探测",
             "scan_config": {"ports": "1-1000", "speed": "fast", "threads": 200,
                             "service_detection": False, "vuln_scan": False}},
            {"name": "全端口服务识别", "desc": "全端口+服务版本识别",
             "scan_config": {"ports": "1-65535", "speed": "normal", "threads": 400,
                             "service_detection": True, "vuln_scan": False}},
            {"name": "Web漏洞扫描", "desc": "Web 服务 + 常见漏洞POC",
             "scan_config": {"ports": "80,443,8080,8443", "speed": "normal",
                             "threads": 200, "service_detection": True,
                             "vuln_scan": True, "poc_library": "community"}},
            {"name": "深度合规扫描", "desc": "全端口+服务+漏洞+合规基线",
             "scan_config": {"ports": "1-65535", "speed": "deep", "threads": 300,
                             "service_detection": True, "vuln_scan": True,
                             "poc_library": "enterprise", "compliance": True}},
        ]
        for t in seeds:
            tid = f"tpl-{uuid.uuid4().hex[:8]}"
            self.templates[tid] = {
                "template_id": tid, **t,
                "version": "1.0", "shared": False, "usage_count": 0,
                "created_at": datetime.now().isoformat(),
            }

    def list_templates(self) -> List[Dict[str, Any]]:
        return sorted(self.templates.values(),
                      key=lambda x: x["created_at"], reverse=True)

    def create_template(self, name: str, desc: str,
                        scan_config: Dict[str, Any]) -> Dict[str, Any]:
        tid = f"tpl-{uuid.uuid4().hex[:8]}"
        tpl = {"template_id": tid, "name": name, "desc": desc,
               "scan_config": scan_config, "version": "1.0",
               "shared": False, "usage_count": 0,
               "created_at": datetime.now().isoformat()}
        self.templates[tid] = tpl
        return tpl

    def share_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        t = self.templates.get(template_id)
        if not t:
            return None
        t["shared"] = not t["shared"]
        return t

    # ---------- 任务创建 ----------
    def create_scan_task(self, name: str, targets: List[str],
                         scan_config: Optional[Dict[str, Any]] = None,
                         schedule_config: Optional[Dict[str, Any]] = None,
                         notification_config: Optional[Dict[str, Any]] = None,
                         resource_config: Optional[Dict[str, Any]] = None,
                         priority: int = 5) -> Dict[str, Any]:
        state = get_cluster_state()
        schedule_config = schedule_config or {}
        notification_config = notification_config or {}
        resource_config = resource_config or {}
        delay = float(schedule_config.get("delay_seconds", 0) or 0)
        requires = list(resource_config.get("requires", ["scan"]))
        task = state.create_task(
            name=name, targets=targets,
            scan_config=scan_config or {},
            priority=priority, requires=requires,
            delay_seconds=delay,
            shard_size=int(resource_config.get("shard_size", 50)),
        )
        # 附加配置
        task["schedule_config"] = schedule_config
        task["notification_config"] = notification_config
        task["resource_config"] = resource_config
        if notification_config:
            self.notifications[task["task_id"]] = notification_config
        return task

    # ---------- 任务控制 ----------
    def control_task(self, task_id: str, action: str,
                     priority: Optional[int] = None) -> Dict[str, Any]:
        state = get_cluster_state()
        task = state.tasks.get(task_id)
        if not task:
            raise KeyError(f"任务不存在: {task_id}")

        if action == "pause":
            task["status"] = "paused"
            task["current_stage"] = "已暂停"
        elif action == "resume":
            task["status"] = "queued"
            task["current_stage"] = "排队中"
            state.enqueue_task(task_id, priority=task["priority"])
        elif action == "cancel":
            state.cancel_task(task_id)
        elif action == "retry":
            task["retries"] = 0
            task["status"] = "queued"
            task["error"] = None
            task["current_stage"] = "排队中"
            state.enqueue_task(task_id, priority=task["priority"])
        elif action == "set_priority":
            if priority is not None:
                state.set_priority(task_id, priority)
        elif action == "adjust_resource":
            if priority is not None:
                task["resource_config"] = task.get("resource_config", {})
                task["resource_config"]["priority"] = priority
        else:
            raise ValueError(f"未知操作: {action}")
        return dict(task)

    # ---------- 任务监控 ----------
    def task_monitor(self, task_id: str) -> Dict[str, Any]:
        state = get_cluster_state()
        task = state.tasks.get(task_id)
        if not task:
            raise KeyError(f"任务不存在: {task_id}")
        speed = task["stats"]["speed"] or round(random.uniform(120, 240), 1)
        task["stats"]["speed"] = speed
        remaining = max(0, task["stats"]["total"] - task["stats"]["scanned"])
        eta = round(remaining / max(1.0, speed / 10), 1)
        return {
            "task_id": task_id,
            "name": task["name"],
            "status": task["status"],
            "status_cn": STATE_CN.get(task["status"], task["status"]),
            "progress": task["progress"],
            "current_stage": task["current_stage"],
            "assigned_node": task["assigned_node"],
            "ports_found": task["stats"]["ports_found"],
            "vulns_found": task["stats"]["vulns_found"],
            "scan_speed": speed,
            "scanned": task["stats"]["scanned"],
            "total": task["stats"]["total"],
            "eta_seconds": eta,
            "retries": task["retries"],
            "priority": task["priority"],
            "created_at": task["created_at"],
            "started_at": task["started_at"],
            "finished_at": task["finished_at"],
        }

    def list_tasks(self, status: Optional[str] = None,
                   keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        state = get_cluster_state()
        out = []
        for t in state.tasks.values():
            if status and t["status"] != status:
                continue
            if keyword and keyword.lower() not in t["name"].lower():
                continue
            out.append({
                "task_id": t["task_id"], "name": t["name"],
                "status": t["status"], "status_cn": STATE_CN.get(t["status"], t["status"]),
                "progress": t["progress"], "priority": t["priority"],
                "assigned_node": t["assigned_node"],
                "ports_found": t["stats"]["ports_found"],
                "vulns_found": t["stats"]["vulns_found"],
                "created_at": t["created_at"],
            })
        out.sort(key=lambda x: x["created_at"], reverse=True)
        return out

    # ---------- 历史 / 对比 / 导出 / 归档 ----------
    def task_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.list_tasks()[:limit]

    def search_tasks(self, keyword: str) -> List[Dict[str, Any]]:
        return self.list_tasks(keyword=keyword)

    def compare_tasks(self, task_ids: List[str]) -> Dict[str, Any]:
        state = get_cluster_state()
        rows = []
        for tid in task_ids:
            t = state.tasks.get(tid)
            if not t:
                continue
            rows.append({
                "task_id": tid, "name": t["name"], "status": t["status"],
                "progress": t["progress"], "ports_found": t["stats"]["ports_found"],
                "vulns_found": t["stats"]["vulns_found"],
                "duration_sec": self._duration(t),
            })
        return {"compare": rows, "task_count": len(rows)}

    def _duration(self, t: Dict[str, Any]) -> Optional[float]:
        if not t.get("started_at"):
            return None
        end = t.get("finished_at") or datetime.now().isoformat()
        try:
            s = datetime.fromisoformat(t["started_at"])
            e = datetime.fromisoformat(end)
            return round((e - s).total_seconds(), 1)
        except Exception:
            return None

    def export_task(self, task_id: str) -> Dict[str, Any]:
        state = get_cluster_state()
        t = state.tasks.get(task_id)
        if not t:
            raise KeyError(f"任务不存在: {task_id}")
        return {
            "task_id": task_id,
            "exported_at": datetime.now().isoformat(),
            "task": copy.deepcopy(t),
            "report": state.aggregate_results(task_id),
            "format": "json",
        }

    def archive_task(self, task_id: str) -> bool:
        state = get_cluster_state()
        t = state.tasks.get(task_id)
        if not t or t["status"] not in ("completed", "failed", "canceled", "dead_letter"):
            return False
        self.archives.append({
            "task_id": task_id, "name": t["name"], "status": t["status"],
            "archived_at": datetime.now().isoformat(),
            "summary": t.get("results_summary"),
        })
        return True

    def list_archives(self) -> List[Dict[str, Any]]:
        return sorted(self.archives, key=lambda x: x["archived_at"], reverse=True)


# ==================== 单例 ====================

_MGR: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    global _MGR
    if _MGR is None:
        _MGR = TaskManager()
    return _MGR


__all__ = ["TaskManager", "get_task_manager", "TASK_STATES", "STATE_CN"]
