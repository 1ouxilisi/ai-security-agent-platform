# -*- coding: utf-8 -*-
"""
cluster_arch.py — 分布式扫描架构核心运行时（第23轮升级 · 方向2）。

职责（Master / Worker 双侧）：
- Master 节点：任务接收 / 任务分发 / 结果聚合 / 状态监控 / 负载均衡
- Worker 节点：任务执行 / 扫描执行 / 结果上报 / 心跳上报 / 资源上报
- 节点注册：Worker 自动注册 / 节点认证 / 节点标签 / 节点能力 / 节点状态
- 任务队列：优先级队列 / 延迟队列 / 重试队列 / 死信队列 / 队列监控
- 任务调度：FIFO / 优先级 / 公平调度 / 资源感知调度 / 定时调度 / 事件触发调度
- 结果聚合：分片结果合并 / 去重 / 排序 / 统计 / 最终报告生成

说明：
- 全部内存字典模拟，不建数据库表；不实际发起网络扫描，仅模拟分片与上报。
- 第三方依赖（psutil）try-import，缺失时回退模拟。
- 仅用于授权范围内的分布式扫描调度框架演示。
"""

from __future__ import annotations

import heapq
import random
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

# 可选第三方库：psutil 用于真实资源探测，缺失时回退模拟
try:  # pragma: no cover
    import psutil  # type: ignore
    _PSUTIL_OK = True
except Exception:
    psutil = None  # type: ignore
    _PSUTIL_OK = False


# ==================== 集群全局状态（内存单例） ====================

class ClusterState:
    """分布式扫描集群的内存运行时状态。线程安全（简单锁）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Master 元信息
        self.master: Dict[str, Any] = {
            "id": "master-001",
            "role": "master",
            "version": "23.0.0",
            "started_at": datetime.now().isoformat(),
            "schedule_strategy": "priority",   # fifo / priority / fair / resource_aware / cron / event
            "max_retries": 3,
            "retry_backoff_base": 2.0,          # 秒
            "heartbeat_timeout": 30.0,          # 秒，超时判离线
            "default_priority": 5,              # 1(最高)~10(最低)
        }
        # Worker 节点注册表：node_id -> node info
        self.nodes: Dict[str, Dict[str, Any]] = {}
        # 扫描任务表：task_id -> task
        self.tasks: Dict[str, Dict[str, Any]] = {}
        # 分片结果表：shard_id -> shard result
        self.shards: Dict[str, Dict[str, Any]] = {}
        # 队列
        self.ready_queue: List[Tuple[int, float, str]] = []   # (priority, enqueue_ts, task_id) 小顶堆
        self.delay_queue: List[Tuple[float, str]] = []         # (run_after_ts, task_id)
        self.retry_queue: List[Tuple[float, str]] = []        # (retry_after_ts, task_id)
        self.dead_letters: List[Dict[str, Any]] = []          # 死信任务记录
        # 已发现漏洞 / 端口（聚合去重）
        self.found_vulns: Dict[str, Dict[str, Any]] = {}
        self.found_ports: Dict[str, Dict[str, Any]] = {}
        # 调度事件日志
        self.event_log: List[Dict[str, Any]] = []
        # 计数器
        self.counters: Dict[str, int] = {
            "tasks_created": 0, "tasks_dispatched": 0, "tasks_completed": 0,
            "tasks_failed": 0, "tasks_dead": 0, "shards_completed": 0,
        }
        # 调度统计
        self.scan_speed_history: List[Dict[str, Any]] = []
        self._seed_nodes()

    # ---------- 内部工具 ----------
    def _now(self) -> float:
        return time.time()

    def _log_event(self, kind: str, message: str, **extra: Any) -> None:
        ev = {
            "time": datetime.now().isoformat(),
            "kind": kind,
            "message": message,
        }
        ev.update(extra)
        self.event_log.append(ev)
        if len(self.event_log) > 500:
            self.event_log = self.event_log[-500:]

    def _seed_nodes(self) -> None:
        """预置 3 个演示 Worker 节点，便于首次访问即有数据。"""
        seeds = [
            ("worker-hz-01", ["scan", "fuzz"], {"cpu": 40, "mem": 55, "disk": 30, "net": 25}),
            ("worker-sh-02", ["scan", "vuln"], {"cpu": 62, "mem": 70, "disk": 48, "net": 55}),
            ("worker-gz-03", ["scan", "web"], {"cpu": 30, "mem": 42, "disk": 22, "net": 18}),
        ]
        for nid, caps, res in seeds:
            self.register_node(nid, capabilities=caps, resources=res,
                               auth_token="demo-token", tags={"region": "cn", "env": "prod"})

    # ---------- 节点注册 / 心跳 ----------
    def register_node(self, node_id: str, capabilities: List[str],
                      resources: Dict[str, float], auth_token: str = "",
                      tags: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        with self._lock:
            now = self._now()
            is_new = node_id not in self.nodes
            node = self.nodes.get(node_id, {})
            node.update({
                "id": node_id,
                "role": "worker",
                "capabilities": capabilities,
                "tags": tags or {},
                "resources": resources,           # 当前资源占用百分比
                "auth_token": auth_token,
                "status": "online",
                "registered_at": node.get("registered_at") or datetime.now().isoformat(),
                "last_heartbeat": now,
                "current_task": None,
                "tasks_done": node.get("tasks_done", 0),
                "tasks_failed": node.get("tasks_failed", 0),
                "load": 0,                        # 当前负载 0~1
            })
            self.nodes[node_id] = node
            self._log_event("node_registered",
                            f"Worker节点 {node_id} {'注册' if is_new else '重新注册'}",
                            node_id=node_id, capabilities=capabilities)
            return dict(node)

    def heartbeat(self, node_id: str, resources: Optional[Dict[str, float]] = None,
                  status: str = "online") -> Dict[str, Any]:
        with self._lock:
            node = self.nodes.get(node_id)
            if not node:
                raise KeyError(f"未注册的节点: {node_id}")
            node["last_heartbeat"] = self._now()
            node["status"] = status
            if resources:
                node["resources"].update(resources)
                # 负载估算：取 CPU/内存/网络 加权
                cpu = float(resources.get("cpu", 0))
                mem = float(resources.get("mem", 0))
                net = float(resources.get("net", 0))
                node["load"] = round((cpu * 0.5 + mem * 0.3 + net * 0.2) / 100.0, 3)
            return dict(node)

    def list_nodes(self, only_online: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            self._reap_offline()
            out = []
            for n in self.nodes.values():
                if only_online and n["status"] != "online":
                    continue
                item = dict(n)
                item.pop("auth_token", None)
                item["heartbeat_age"] = round(self._now() - n["last_heartbeat"], 1)
                out.append(item)
            out.sort(key=lambda x: x["id"])
            return out

    def _reap_offline(self) -> None:
        """心跳超时节点标记离线。"""
        timeout = self.master["heartbeat_timeout"]
        now = self._now()
        for nid, node in self.nodes.items():
            if node["status"] == "online" and (now - node["last_heartbeat"]) > timeout:
                node["status"] = "offline"
                self._log_event("node_offline", f"节点 {nid} 心跳超时离线", node_id=nid)

    def remove_node(self, node_id: str) -> bool:
        with self._lock:
            if node_id in self.nodes:
                self.nodes.pop(node_id)
                self._log_event("node_removed", f"节点 {node_id} 被移除", node_id=node_id)
                return True
            return False

    # ---------- 任务队列 ----------
    def enqueue_task(self, task_id: str, priority: int = 5, delay_seconds: float = 0.0) -> str:
        """入队：delay_seconds>0 进延迟队列，否则进优先级就绪队列。"""
        with self._lock:
            now = self._now()
            if delay_seconds and delay_seconds > 0:
                heapq.heappush(self.delay_queue, (now + delay_seconds, task_id))
                self.tasks[task_id]["queue"] = "delay"
                self._log_event("task_delayed", f"任务 {task_id} 延迟 {delay_seconds}s 入队",
                                task_id=task_id)
                return "delay"
            heapq.heappush(self.ready_queue, (priority, now, task_id))
            self.tasks[task_id]["queue"] = "ready"
            self._log_event("task_enqueued", f"任务 {task_id} 进入就绪队列(优先级{priority})",
                            task_id=task_id, priority=priority)
            return "ready"

    def _requeue_delay(self) -> None:
        """到期延迟任务转入就绪队列。"""
        now = self._now()
        ready: List[Tuple[float, str]] = []
        while self.delay_queue:
            run_after, tid = self.delay_queue[0]
            if run_after <= now:
                heapq.heappop(self.delay_queue)
                prio = self.tasks.get(tid, {}).get("priority", 5)
                heapq.heappush(self.ready_queue, (prio, now, tid))
                if tid in self.tasks:
                    self.tasks[tid]["queue"] = "ready"
            else:
                break
        # 剩余未到期的留在队列里（heapq 不支持原地保留，重建）
        # 上面循环已经把到期的 pop 走了，剩余项仍在 self.delay_queue 中
        _ = ready

    def _requeue_retry(self) -> None:
        """到期重试任务转入就绪队列。"""
        now = self._now()
        while self.retry_queue and self.retry_queue[0][0] <= now:
            retry_after, tid = heapq.heappop(self.retry_queue)
            if tid not in self.tasks:
                continue
            prio = self.tasks[tid].get("priority", 5)
            heapq.heappush(self.ready_queue, (prio, now, tid))
            self.tasks[tid]["queue"] = "ready"
            self.tasks[tid]["status"] = "queued"
            self._log_event("task_retry_enqueued", f"任务 {tid} 进入重试队列", task_id=tid)

    def pick_next_task(self, node_id: str) -> Optional[Dict[str, Any]]:
        """按调度策略从就绪队列选取一个可分配给该 Worker 的任务。"""
        with self._lock:
            self._requeue_delay()
            self._requeue_retry()
            node = self.nodes.get(node_id)
            if not node or node["status"] != "online":
                return None
            strategy = self.master["schedule_strategy"]
            # 收集候选（按策略排序）
            candidates: List[Tuple[Any, str]] = []
            tmp: List[Tuple[int, float, str]] = []
            while self.ready_queue:
                prio, ts, tid = heapq.heappop(self.ready_queue)
                tmp.append((prio, ts, tid))
                candidates.append((prio, ts, tid))
            # 放回去（未选中的）
            chosen: Optional[str] = None
            if candidates:
                chosen = self._select_by_strategy(candidates, node, strategy)
            for item in candidates:
                if item[2] != chosen:
                    heapq.heappush(self.ready_queue, item)
            if chosen is None:
                return None
            task = self.tasks.get(chosen)
            if not task:
                return None
            # 分配给 worker
            task["status"] = "running"
            task["assigned_node"] = node_id
            task["started_at"] = datetime.now().isoformat()
            task["queue"] = "running"
            node["current_task"] = chosen
            node["load"] = min(1.0, node.get("load", 0) + 0.4)
            self.counters["tasks_dispatched"] += 1
            self._log_event("task_dispatched",
                            f"任务 {chosen} 分发到节点 {node_id} (策略={strategy})",
                            task_id=chosen, node_id=node_id, strategy=strategy)
            return dict(task)

    def _select_by_strategy(self, candidates: List[Tuple[int, float, str]],
                            node: Dict[str, Any], strategy: str) -> Optional[str]:
        if not candidates:
            return None
        if strategy == "fifo":
            candidates.sort(key=lambda x: x[1])
        elif strategy == "fair":
            # 公平：优先给累计完成少的节点的任务（这里用 task 创建者近似）
            candidates.sort(key=lambda x: (self.tasks.get(x[2], {}).get("fair_weight", 1), x[1]))
        elif strategy == "resource_aware":
            # 资源感知：只挑该节点能力匹配、且任务优先级最高的
            caps = set(node.get("capabilities", []))
            matched = [c for c in candidates if set(
                self.tasks.get(c[2], {}).get("requires", [])) & caps or
                not self.tasks.get(c[2], {}).get("requires")]
            pool = matched or candidates
            pool.sort(key=lambda x: x[0])
            return pool[0][2]
        else:  # priority / cron / event 默认按优先级
            candidates.sort(key=lambda x: (x[0], x[1]))
        return candidates[0][2]

    def queue_stats(self) -> Dict[str, Any]:
        with self._lock:
            self._requeue_delay()
            self._requeue_retry()
            return {
                "ready_depth": len(self.ready_queue),
                "delay_depth": len(self.delay_queue),
                "retry_depth": len(self.retry_queue),
                "dead_letter_depth": len(self.dead_letters),
                "strategy": self.master["schedule_strategy"],
                "max_retries": self.master["max_retries"],
                "heartbeat_timeout": self.master["heartbeat_timeout"],
            }

    # ---------- 任务生命周期 ----------
    def create_task(self, name: str, targets: List[str], scan_config: Dict[str, Any],
                    priority: int = 5, requires: Optional[List[str]] = None,
                    delay_seconds: float = 0.0, shard_size: int = 50) -> Dict[str, Any]:
        with self._lock:
            tid = f"scan-{uuid.uuid4().hex[:10]}"
            task = {
                "task_id": tid,
                "name": name,
                "targets": targets,
                "scan_config": scan_config,
                "priority": max(1, min(10, priority)),
                "requires": requires or ["scan"],
                "shard_size": shard_size,
                "status": "pending",          # pending/queued/running/paused/completed/failed/canceled/timeout
                "queue": None,
                "assigned_node": None,
                "created_at": datetime.now().isoformat(),
                "started_at": None,
                "finished_at": None,
                "progress": 0.0,
                "current_stage": "排队中",
                "stats": {"ports_found": 0, "vulns_found": 0, "speed": 0.0,
                          "scanned": 0, "total": len(targets)},
                "retries": 0,
                "max_retries": self.master["max_retries"],
                "error": None,
                "shards": [],
                "results_summary": None,
                "fair_weight": random.randint(1, 3),
            }
            self.tasks[tid] = task
            self.counters["tasks_created"] += 1
            self.enqueue_task(tid, priority=task["priority"], delay_seconds=delay_seconds)
            if delay_seconds:
                task["status"] = "pending"
            else:
                task["status"] = "queued"
            return dict(task)

    def report_result(self, task_id: str, node_id: str, shard_id: str,
                      shard_result: Dict[str, Any]) -> Dict[str, Any]:
        """Worker 上报分片结果，Master 聚合。"""
        with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                raise KeyError(f"任务不存在: {task_id}")
            self.shards[shard_id] = {
                "shard_id": shard_id, "task_id": task_id, "node_id": node_id,
                "result": shard_result, "reported_at": datetime.now().isoformat(),
            }
            task["shards"].append(shard_id)
            # 聚合端口
            for port in shard_result.get("ports", []):
                key = f"{port.get('host')}:{port.get('port')}"
                if key not in self.found_ports:
                    self.found_ports[key] = {**port, "first_seen": datetime.now().isoformat()}
                    task["stats"]["ports_found"] += 1
            # 聚合漏洞（按 host+cve 去重）
            for vuln in shard_result.get("vulns", []):
                key = f"{vuln.get('host')}|{vuln.get('cve', vuln.get('id'))}"
                if key not in self.found_vulns:
                    self.found_vulns[key] = {**vuln, "first_seen": datetime.now().isoformat()}
                    task["stats"]["vulns_found"] += 1
            # 进度
            done = task["stats"]["scanned"] + shard_result.get("scanned", 0)
            task["stats"]["scanned"] = done
            total = max(1, task["stats"]["total"])
            task["progress"] = round(min(100.0, done * 100.0 / total), 1)
            self.counters["shards_completed"] += 1
            # 完成判定
            if task["progress"] >= 100.0:
                self._complete_task(task_id, node_id)
            self._log_event("shard_reported",
                            f"分片 {shard_id} 上报，任务 {task_id} 进度 {task['progress']}%",
                            task_id=task_id, shard_id=shard_id)
            return {"task_id": task_id, "progress": task["progress"],
                    "ports": task["stats"]["ports_found"],
                    "vulns": task["stats"]["vulns_found"]}

    def report_failure(self, task_id: str, node_id: str, reason: str) -> Dict[str, Any]:
        with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                raise KeyError(f"任务不存在: {task_id}")
            task["retries"] += 1
            node = self.nodes.get(node_id)
            if node:
                node["tasks_failed"] = node.get("tasks_failed", 0) + 1
                node["current_task"] = None
                node["load"] = max(0.0, node.get("load", 0) - 0.4)
            if task["retries"] > task["max_retries"]:
                # 进入死信
                task["status"] = "dead_letter"
                task["error"] = reason
                self.dead_letters.append({
                    "task_id": task_id, "reason": reason,
                    "retries": task["retries"],
                    "dead_at": datetime.now().isoformat(),
                })
                self.counters["tasks_dead"] += 1
                self._log_event("task_dead", f"任务 {task_id} 进入死信队列", task_id=task_id)
            else:
                backoff = self.master["retry_backoff_base"] * (2 ** (task["retries"] - 1))
                heapq.heappush(self.retry_queue, (self._now() + backoff, task_id))
                task["queue"] = "retry"
                task["status"] = "retrying"
                self._log_event("task_failed",
                                f"任务 {task_id} 失败({reason})，{backoff:.0f}s 后重试",
                                task_id=task_id, retries=task["retries"])
            return {"task_id": task_id, "retries": task["retries"],
                    "status": task["status"]}

    def _complete_task(self, task_id: str, node_id: Optional[str] = None) -> None:
        task = self.tasks[task_id]
        task["status"] = "completed"
        task["finished_at"] = datetime.now().isoformat()
        task["current_stage"] = "完成"
        task["queue"] = None
        node = self.nodes.get(node_id) if node_id else None
        if node:
            node["tasks_done"] = node.get("tasks_done", 0) + 1
            node["current_task"] = None
            node["load"] = max(0.0, node.get("load", 0) - 0.4)
        # 生成最终聚合报告
        task["results_summary"] = self.aggregate_results(task_id)
        self.counters["tasks_completed"] += 1
        self._log_event("task_completed", f"任务 {task_id} 完成", task_id=task_id)

    def cancel_task(self, task_id: str) -> bool:
        with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                return False
            task["status"] = "canceled"
            task["queue"] = None
            task["finished_at"] = datetime.now().isoformat()
            node = self.nodes.get(task.get("assigned_node") or "")
            if node and node.get("current_task") == task_id:
                node["current_task"] = None
            self._log_event("task_canceled", f"任务 {task_id} 被取消", task_id=task_id)
            return True

    def set_priority(self, task_id: str, priority: int) -> bool:
        with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                return False
            task["priority"] = max(1, min(10, priority))
            return True

    # ---------- 结果聚合 ----------
    def aggregate_results(self, task_id: str) -> Dict[str, Any]:
        """合并分片、去重、排序、统计，生成最终报告。"""
        task = self.tasks.get(task_id)
        if not task:
            return {}
        ports: Dict[str, Dict[str, Any]] = {}
        vulns: Dict[str, Dict[str, Any]] = {}
        for sh in self.shards.values():
            if sh["task_id"] != task_id:
                continue
            for p in sh["result"].get("ports", []):
                key = f"{p.get('host')}:{p.get('port')}"
                ports.setdefault(key, p)
            for v in sh["result"].get("vulns", []):
                key = f"{v.get('host')}|{v.get('cve', v.get('id'))}"
                vulns.setdefault(key, v)
        port_list = sorted(ports.values(), key=lambda x: (x.get("host", ""), x.get("port", 0)))
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vuln_list = sorted(vulns.values(),
                           key=lambda x: sev_order.get(x.get("severity", "info"), 9))
        sev_count: Dict[str, int] = {}
        for v in vuln_list:
            sev_count[v.get("severity", "info")] = sev_count.get(v.get("severity", "info"), 0) + 1
        report = {
            "task_id": task_id,
            "generated_at": datetime.now().isoformat(),
            "total_shards": len(task.get("shards", [])),
            "unique_ports": len(port_list),
            "unique_vulns": len(vuln_list),
            "severity_distribution": sev_count,
            "top_ports": port_list[:20],
            "top_vulns": vuln_list[:20],
            "progress": task.get("progress", 100.0),
            "summary": (f"任务 {task_id} 共合并 {len(task.get('shards', []))} 个分片，"
                        f"去重后开放端口 {len(port_list)} 个，唯一漏洞 {len(vuln_list)} 个。"),
        }
        return report

    # ---------- 负载均衡 / 总览 ----------
    def cluster_overview(self) -> Dict[str, Any]:
        with self._lock:
            self._reap_offline()
            online = [n for n in self.nodes.values() if n["status"] == "online"]
            avg_cpu = round(sum(n["resources"].get("cpu", 0) for n in online) / max(1, len(online)), 1)
            avg_mem = round(sum(n["resources"].get("mem", 0) for n in online) / max(1, len(online)), 1)
            running = [t for t in self.tasks.values() if t["status"] == "running"]
            queued = [t for t in self.tasks.values() if t["status"] in ("queued", "pending")]
            # 模拟扫描速度（端口/秒）
            speed = round(random.uniform(80, 260), 1)
            self.scan_speed_history.append({"time": datetime.now().isoformat(), "speed": speed})
            if len(self.scan_speed_history) > 60:
                self.scan_speed_history = self.scan_speed_history[-60:]
            return {
                "master": {"id": self.master["id"], "version": self.master["version"],
                           "strategy": self.master["schedule_strategy"]},
                "nodes_total": len(self.nodes),
                "nodes_online": len(online),
                "nodes_offline": len(self.nodes) - len(online),
                "tasks_total": len(self.tasks),
                "tasks_running": len(running),
                "tasks_queued": len(queued),
                "tasks_completed": self.counters["tasks_completed"],
                "tasks_failed": self.counters["tasks_failed"],
                "dead_letters": len(self.dead_letters),
                "scan_speed": speed,
                "avg_cpu": avg_cpu, "avg_mem": avg_mem,
                "queue_depth": {
                    "ready": len(self.ready_queue),
                    "delay": len(self.delay_queue),
                    "retry": len(self.retry_queue),
                    "dead": len(self.dead_letters),
                },
                "found_ports": len(self.found_ports),
                "found_vulns": len(self.found_vulns),
            }


# ==================== 单例 ====================

_STATE: Optional[ClusterState] = None


def get_cluster_state() -> ClusterState:
    global _STATE
    if _STATE is None:
        _STATE = ClusterState()
    return _STATE


def reset_cluster_state() -> ClusterState:
    """仅用于测试：重置全局状态。"""
    global _STATE
    _STATE = ClusterState()
    return _STATE


# ==================== 模拟 Worker 执行器（供调度演示） ====================

def simulate_worker_run(task: Dict[str, Any], node_id: str) -> None:
    """在调用方线程内同步模拟一个分片的扫描执行并上报结果。
    真实场景由独立 Worker 进程执行；此处仅为端点提供可观察的真实状态流转。
    """
    state = get_cluster_state()
    targets: List[str] = list(task.get("targets", []))
    shard_size = max(1, int(task.get("shard_size", 50)))
    shards = [targets[i:i + shard_size] for i in range(0, len(targets), shard_size)] or [[]]
    for idx, chunk in enumerate(shards):
        shard_id = f"{task['task_id']}-shard-{idx}"
        ports = []
        vulns = []
        for host in chunk:
            n_open = random.randint(0, 6)
            for _ in range(n_open):
                port = random.choice([22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200])
                svc = {22: "ssh", 80: "http", 443: "https", 3306: "mysql",
                       5432: "postgresql", 6379: "redis", 8080: "http-proxy",
                       8443: "https-alt", 9200: "elasticsearch"}.get(port, "unknown")
                ports.append({"host": host, "port": port, "service": svc,
                              "state": "open"})
                if random.random() < 0.18:
                    sev = random.choice(["high", "medium", "medium", "low"])
                    cve = f"CVE-{random.randint(2019, 2025)}-{random.randint(1000, 99999)}"
                    vulns.append({"host": host, "port": port, "cve": cve,
                                  "severity": sev, "title": f"示例漏洞 {cve}"})
        state.report_result(task["task_id"], node_id, shard_id,
                            {"scanned": len(chunk), "ports": ports, "vulns": vulns})


__all__ = [
    "ClusterState", "get_cluster_state", "reset_cluster_state",
    "simulate_worker_run",
]
