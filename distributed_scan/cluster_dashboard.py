# -*- coding: utf-8 -*-
"""
cluster_dashboard.py — 分布式管理控制台聚合层（第23轮升级 · 方向2）。

职责：
- 集群总览：节点数/在线节点/任务数/扫描速度/资源使用率/队列深度
- 节点管理：列表/详情/状态/配置/标签/启停/移除
- 任务管理：列表/详情/状态/控制/进度/结果/日志
- 代理管理：列表/状态/检测/分组/池配置/轮换策略
- 监控告警：实时监控/历史趋势/告警规则/通知/历史/统计
- 系统设置：集群配置/调度策略/资源配额/重试/超时/日志/审计

本模块把其它 5 个子域聚合为控制台视图。
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Dict, List, Optional

from .cluster_arch import get_cluster_state, simulate_worker_run
from .task_manager import get_task_manager, STATE_CN
from .proxy_pool import get_proxy_pool
from .resume_scan import get_resume_manager
from .resource_manager import get_resource_manager


# 通知渠道模拟
NOTIFY_CHANNELS: List[Dict[str, Any]] = [
    {"id": "ch-email", "type": "email", "target": "soc@example.com", "enabled": True},
    {"id": "ch-webhook", "type": "webhook", "target": "https://oapi.example.com/hook",
     "enabled": True},
    {"id": "ch-sms", "type": "sms", "target": "+86****0000", "enabled": False},
]

# 系统设置默认值
SYSTEM_SETTINGS: Dict[str, Any] = {
    "cluster_name": "AI-Hacking 分布式扫描集群",
    "schedule_strategy": "priority",
    "max_retries": 3,
    "retry_backoff_base": 2.0,
    "heartbeat_timeout": 30.0,
    "task_timeout_minutes": 120,
    "log_level": "INFO",
    "audit_enabled": True,
    "auto_recover": True,
    "default_shard_size": 50,
}


class ClusterDashboard:
    """控制台聚合视图。"""

    def __init__(self) -> None:
        self.state = get_cluster_state()
        self.tm = get_task_manager()
        self.pp = get_proxy_pool()
        self.rs = get_resume_manager()
        self.rm = get_resource_manager()
        self.audit_log: List[Dict[str, Any]] = []

    # ---------- 集群总览 ----------
    def overview(self) -> Dict[str, Any]:
        ov = self.state.cluster_overview()
        rm = self.rm.realtime_metrics()
        return {
            **ov,
            "resource": {"cpu_pct": rm["host"]["cpu_pct"],
                         "mem_pct": rm["host"]["mem_pct"],
                         "disk_pct": rm["host"]["disk_pct"]},
            "proxy": self.pp.pool_stats(),
            "settings": dict(SYSTEM_SETTINGS),
        }

    # ---------- 节点 ----------
    def node_list(self) -> List[Dict[str, Any]]:
        return self.state.list_nodes()

    def node_detail(self, node_id: str) -> Dict[str, Any]:
        n = self.state.nodes.get(node_id)
        if not n:
            raise KeyError(f"节点不存在: {node_id}")
        item = dict(n)
        item.pop("auth_token", None)
        item["heartbeat_age"] = round(self.state._now() - n["last_heartbeat"], 1)
        return item

    def node_register(self, node_id: str, capabilities: List[str],
                      resources: Optional[Dict[str, float]] = None,
                      tags: Optional[Dict[str, str]] = None,
                      auth_token: str = "") -> Dict[str, Any]:
        return self.state.register_node(
            node_id, capabilities=capabilities,
            resources=resources or {"cpu": 10, "mem": 20, "disk": 10, "net": 5},
            auth_token=auth_token, tags=tags)

    def node_heartbeat(self, node_id: str,
                       resources: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        return self.state.heartbeat(node_id, resources=resources)

    def node_remove(self, node_id: str) -> bool:
        return self.state.remove_node(node_id)

    # ---------- 任务 ----------
    def task_list(self, status: Optional[str] = None,
                  keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.tm.list_tasks(status=status, keyword=keyword)

    def task_detail(self, task_id: str) -> Dict[str, Any]:
        return self.tm.task_monitor(task_id)

    def task_control(self, task_id: str, action: str,
                     priority: Optional[int] = None) -> Dict[str, Any]:
        return self.tm.control_task(task_id, action, priority=priority)

    def task_logs(self, task_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        return [e for e in self.state.event_log
                if e.get("task_id") == task_id][-limit:]

    def task_result(self, task_id: str) -> Dict[str, Any]:
        return self.state.aggregate_results(task_id)

    # ---------- 代理 ----------
    def proxy_list(self, **kw: Any) -> List[Dict[str, Any]]:
        return self.pp.list_proxies(**kw)

    def proxy_detect(self, pid: str) -> Dict[str, Any]:
        return self.pp.detect_proxy(pid)

    def proxy_health_check(self) -> Dict[str, Any]:
        return self.pp.health_check_all()

    def proxy_groups(self) -> Dict[str, int]:
        return {g: len(ids) for g, ids in self.pp.groups.items()}

    def proxy_policy(self, **kw: Any) -> Dict[str, Any]:
        return self.pp.set_policy(**kw)

    # ---------- 监控告警 ----------
    def monitoring_realtime(self) -> Dict[str, Any]:
        return self.rm.realtime_metrics()

    def monitoring_trend(self, points: int = 30) -> List[Dict[str, Any]]:
        return self.rm.metric_history[-points:]

    def alarm_rules(self) -> List[Dict[str, Any]]:
        return list(self.rm.alarm_rules)

    def alarm_history(self, level: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.rm.list_alarms(level=level)

    def alarm_stats(self) -> Dict[str, int]:
        stats: Dict[str, int] = {}
        for a in self.rm.alarms:
            stats[a["level"]] = stats.get(a["level"], 0) + 1
        return stats

    # ---------- 系统设置 ----------
    def get_settings(self) -> Dict[str, Any]:
        return {
            "settings": dict(SYSTEM_SETTINGS),
            "notify_channels": NOTIFY_CHANNELS,
            "quota": self.rm.list_quota(),
            "isolation": self.rm.list_isolation(),
            "queue_stats": self.state.queue_stats(),
        }

    def update_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        SYSTEM_SETTINGS.update(patch)
        if "schedule_strategy" in patch:
            self.state.master["schedule_strategy"] = patch["schedule_strategy"]
        if "max_retries" in patch:
            self.state.master["max_retries"] = int(patch["max_retries"])
        if "heartbeat_timeout" in patch:
            self.state.master["heartbeat_timeout"] = float(patch["heartbeat_timeout"])
        self._audit("settings_update", patch)
        return dict(SYSTEM_SETTINGS)

    # ---------- 调度演示：一键调度并模拟执行 ----------
    def dispatch_and_run(self, node_id: Optional[str] = None) -> Dict[str, Any]:
        """Master 取下一个任务，分配给 worker 并同步模拟执行。"""
        online = self.state.list_nodes(only_online=True)
        if not online:
            raise RuntimeError("无在线 Worker 节点")
        nid = node_id or random.choice(online)["id"]
        task = self.state.pick_next_task(nid)
        if not task:
            return {"dispatched": False, "message": "就绪队列为空"}
        simulate_worker_run(task, nid)
        return {"dispatched": True, "task_id": task["task_id"],
                "node_id": nid,
                "progress": self.state.tasks[task["task_id"]]["progress"],
                "status": self.state.tasks[task["task_id"]]["status"]}

    # ---------- 审计 ----------
    def _audit(self, action: str, detail: Any) -> None:
        self.audit_log.append({
            "time": datetime.now().isoformat(), "action": action, "detail": detail,
        })
        if len(self.audit_log) > 200:
            self.audit_log = self.audit_log[-200:]

    def list_audit(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.audit_log[-limit:][::-1]


_DASH: Optional[ClusterDashboard] = None


def get_dashboard() -> ClusterDashboard:
    global _DASH
    if _DASH is None:
        _DASH = ClusterDashboard()
    return _DASH


__all__ = ["ClusterDashboard", "get_dashboard", "SYSTEM_SETTINGS",
           "NOTIFY_CHANNELS"]
