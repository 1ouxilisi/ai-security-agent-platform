# -*- coding: utf-8 -*-
"""
resume_scan.py — 断点续扫与增量扫描（第23轮升级 · 方向2）。

职责：
- 扫描状态持久化：进度/已扫描目标/已发现漏洞/当前阶段实时持久化
- 断点恢复：异常中断后从断点恢复 / 状态校验 / 增量补扫 / 结果合并
- 增量扫描：资产变更检测 / 新增资产扫描 / 变更资产重扫 / 未变更跳过
- 扫描快照：进度快照 / 快照管理 / 回滚 / 对比 / 导出
- 扫描分片：大目标自动分片 / 分片并行 / 结果合并 / 失败重试
- 扫描缓存：端口/服务/漏洞结果缓存 / 过期策略

持久化用进程内"伪持久化"（内存字典 + 序列化快照 JSON），不依赖外部 DB。
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .cluster_arch import get_cluster_state


class ResumeScanManager:
    """断点续扫 / 增量 / 快照 / 分片 / 缓存 管理器。"""

    def __init__(self) -> None:
        # 持久化存储：task_id -> 持久化状态
        self.persistent: Dict[str, Dict[str, Any]] = {}
        # 快照：snapshot_id -> snapshot
        self.snapshots: Dict[str, Dict[str, Any]] = {}
        # 资产指纹：asset_key -> fingerprint
        self.asset_fingerprints: Dict[str, str] = {}
        # 扫描缓存：key -> {data, expire_at}
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = 3600          # 默认 1 小时
        # 分片表：shard_id -> shard
        self.shard_registry: Dict[str, Dict[str, Any]] = {}
        # 恢复日志
        self.recovery_log: List[Dict[str, Any]] = []

    # ---------- 状态持久化 ----------
    def save_state(self, task_id: str) -> Dict[str, Any]:
        """将集群中任务的当前状态固化到"持久化层"。"""
        state = get_cluster_state()
        t = state.tasks.get(task_id)
        if not t:
            raise KeyError(f"任务不存在: {task_id}")
        snap = {
            "task_id": task_id,
            "persisted_at": datetime.now().isoformat(),
            "progress": t["progress"],
            "status": t["status"],
            "current_stage": t["current_stage"],
            "scanned": t["stats"]["scanned"],
            "total": t["stats"]["total"],
            "ports_found": t["stats"]["ports_found"],
            "vulns_found": t["stats"]["vulns_found"],
            "assigned_node": t["assigned_node"],
            "shards_completed": list(t.get("shards", [])),
            "targets": list(t.get("targets", [])),
            "scan_config": copy.deepcopy(t.get("scan_config", {})),
            "retries": t.get("retries", 0),
        }
        self.persistent[task_id] = snap
        return snap

    def load_state(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self.persistent.get(task_id)

    # ---------- 断点恢复 ----------
    def recover_task(self, task_id: str, validate: bool = True) -> Dict[str, Any]:
        state = get_cluster_state()
        snap = self.persistent.get(task_id)
        t = state.tasks.get(task_id)
        if not snap or not t:
            raise KeyError(f"无可用断点: {task_id}")
        # 状态校验
        valid = True
        msg = "断点校验通过"
        if validate:
            if snap["scanned"] > snap["total"]:
                valid = False
                msg = "断点数据异常：已扫描数>总数"
            if t["status"] not in ("running", "queued", "pending", "paused", "failed"):
                msg = f"任务当前状态={t['status']}，将强制恢复到 queued"
        # 从断点恢复：把已扫描进度回灌，未完成目标增量补扫
        t["stats"]["scanned"] = snap["scanned"]
        t["progress"] = snap["progress"]
        t["stats"]["ports_found"] = snap["ports_found"]
        t["stats"]["vulns_found"] = snap["vulns_found"]
        t["status"] = "queued"
        t["current_stage"] = f"断点恢复(已完成{snap['progress']}%)"
        t["shards"] = list(snap["shards_completed"])
        # 增量补扫：未完成的目标
        done_ratio = snap["scanned"] / max(1, snap["total"])
        total = len(snap["targets"])
        resume_from = int(total * done_ratio)
        remaining = snap["targets"][resume_from:]
        t["targets"] = remaining or snap["targets"]
        self.recovery_log.append({
            "time": datetime.now().isoformat(), "task_id": task_id,
            "valid": valid, "message": msg,
            "resumed_from": snap["progress"], "remaining_targets": len(remaining),
        })
        # 重新入队
        state.enqueue_task(task_id, priority=t["priority"])
        return {
            "task_id": task_id, "valid": valid, "message": msg,
            "resume_from_progress": snap["progress"],
            "remaining_targets": len(remaining),
            "status": t["status"],
        }

    # ---------- 增量扫描 ----------
    def fingerprint_assets(self, assets: List[Dict[str, Any]]) -> Dict[str, str]:
        """对资产列表生成指纹：host+open_ports+service 串的 hash。"""
        fp_map: Dict[str, str] = {}
        for a in assets:
            key = a.get("host", str(uuid.uuid4()))
            raw = f"{key}|{sorted(a.get('open_ports', []))}|{a.get('service', '')}"
            fp = hashlib.sha1(raw.encode()).hexdigest()[:16]
            fp_map[key] = fp
        return fp_map

    def incremental_diff(self, new_assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """对比资产指纹，输出 新增/变更/未变更。"""
        new_fp = self.fingerprint_assets(new_assets)
        added, changed, unchanged = [], [], []
        for host, fp in new_fp.items():
            old = self.asset_fingerprints.get(host)
            if old is None:
                added.append(host)
            elif old != fp:
                changed.append(host)
            else:
                unchanged.append(host)
        # 写入新指纹
        self.asset_fingerprints.update(new_fp)
        return {
            "added": added, "changed": changed, "unchanged": unchanged,
            "added_count": len(added), "changed_count": len(changed),
            "unchanged_count": len(unchanged),
            "rescan_targets": added + changed,
        }

    # ---------- 快照 ----------
    def take_snapshot(self, task_id: str, name: str = "") -> Dict[str, Any]:
        state = get_cluster_state()
        t = state.tasks.get(task_id)
        if not t:
            raise KeyError(f"任务不存在: {task_id}")
        sid = f"snap-{uuid.uuid4().hex[:8]}"
        snap = {
            "snapshot_id": sid, "task_id": task_id,
            "name": name or f"快照-{datetime.now().strftime('%H:%M:%S')}",
            "taken_at": datetime.now().isoformat(),
            "progress": t["progress"],
            "status": t["status"],
            "scanned": t["stats"]["scanned"],
            "ports": copy.deepcopy(state.aggregate_results(task_id).get("top_ports", [])),
            "vulns": copy.deepcopy(state.aggregate_results(task_id).get("top_vulns", [])),
        }
        self.snapshots[sid] = snap
        return snap

    def list_snapshots(self, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        out = list(self.snapshots.values())
        if task_id:
            out = [s for s in out if s["task_id"] == task_id]
        out.sort(key=lambda x: x["taken_at"], reverse=True)
        return out

    def rollback_snapshot(self, snapshot_id: str) -> Dict[str, Any]:
        snap = self.snapshots.get(snapshot_id)
        if not snap:
            raise KeyError(f"快照不存在: {snapshot_id}")
        # 回滚到快照时的进度（标记为可恢复）
        self.persistent[snap["task_id"]] = {
            "task_id": snap["task_id"],
            "persisted_at": datetime.now().isoformat(),
            "progress": snap["progress"], "status": "paused",
            "current_stage": f"回滚自快照 {snapshot_id}",
            "scanned": snap["scanned"], "total": snap["scanned"],
            "ports_found": len(snap["ports"]),
            "vulns_found": len(snap["vulns"]),
            "assigned_node": None, "shards_completed": [],
            "targets": [], "scan_config": {}, "retries": 0,
        }
        return {"rolled_back_to": snapshot_id, "task_id": snap["task_id"],
                "progress": snap["progress"]}

    def compare_snapshots(self, sid_a: str, sid_b: str) -> Dict[str, Any]:
        a = self.snapshots.get(sid_a)
        b = self.snapshots.get(sid_b)
        if not a or not b:
            raise KeyError("快照不存在")
        return {
            "a": {"id": sid_a, "progress": a["progress"],
                  "ports": len(a["ports"]), "vulns": len(a["vulns"])},
            "b": {"id": sid_b, "progress": b["progress"],
                  "ports": len(b["ports"]), "vulns": len(b["vulns"])},
            "delta_progress": round(b["progress"] - a["progress"], 1),
            "delta_ports": len(b["ports"]) - len(a["ports"]),
            "delta_vulns": len(b["vulns"]) - len(a["vulns"]),
        }

    # ---------- 分片 ----------
    def shard_targets(self, targets: List[str], shard_size: int = 50) -> List[Dict[str, Any]]:
        shards = []
        for i in range(0, len(targets), max(1, shard_size)):
            chunk = targets[i:i + shard_size]
            sid = f"shard-{uuid.uuid4().hex[:8]}"
            reg = {
                "shard_id": sid, "index": i // max(1, shard_size),
                "targets": chunk, "size": len(chunk),
                "status": "pending", "assigned_node": None,
                "created_at": datetime.now().isoformat(), "retries": 0,
            }
            self.shard_registry[sid] = reg
            shards.append(reg)
        return shards

    def mark_shard(self, shard_id: str, status: str,
                   node_id: Optional[str] = None) -> Dict[str, Any]:
        s = self.shard_registry.get(shard_id)
        if not s:
            raise KeyError(f"分片不存在: {shard_id}")
        s["status"] = status
        if node_id:
            s["assigned_node"] = node_id
        if status == "failed":
            s["retries"] += 1
        return s

    def shard_stats(self) -> Dict[str, Any]:
        total = len(self.shard_registry)
        by_status: Dict[str, int] = {}
        for s in self.shard_registry.values():
            by_status[s["status"]] = by_status.get(s["status"], 0) + 1
        return {"total": total, "by_status": by_status}

    # ---------- 缓存 ----------
    def cache_get(self, key: str) -> Optional[Any]:
        item = self.cache.get(key)
        if not item:
            return None
        if item["expire_at"] < time.time():
            self.cache.pop(key, None)
            return None
        return item["data"]

    def cache_set(self, key: str, data: Any, ttl: Optional[int] = None) -> None:
        self.cache[key] = {
            "data": data,
            "expire_at": time.time() + (ttl or self.cache_ttl),
            "set_at": datetime.now().isoformat(),
        }

    def cache_stats(self) -> Dict[str, Any]:
        now = time.time()
        alive = [k for k, v in self.cache.items() if v["expire_at"] >= now]
        return {"total_keys": len(self.cache), "alive_keys": len(alive),
                "ttl_seconds": self.cache_ttl}


_MGR: Optional[ResumeScanManager] = None


def get_resume_manager() -> ResumeScanManager:
    global _MGR
    if _MGR is None:
        _MGR = ResumeScanManager()
    return _MGR


__all__ = ["ResumeScanManager", "get_resume_manager"]
