# -*- coding: utf-8 -*-
"""
commercial_ultra/backup_recovery.py — 备份恢复（商业产品体验极致）。

- 数据自动备份
- 一键恢复
- 备份历史
- 备份策略
"""

from __future__ import annotations

import copy
import threading
import time
from typing import Any, Dict, List


class BackupRecovery:
    """备份恢复（全内存快照模拟）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._backups: Dict[str, Dict[str, Any]] = {}
        self._policy: Dict[str, Any] = {
            "auto": True, "interval_minutes": 60, "retain": 14,
            "compress": True, "encrypt": True,
        }
        self._live_state: Dict[str, Any] = {
            "customers": 12, "projects": 34, "reports": 87,
            "config": "v4.0",
        }
        self._seq = 0
        self.backup("初始化备份")

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{int(time.time()) % 100000:05d}{self._seq:03d}"

    def backup(self, label: str = "") -> Dict[str, Any]:
        with self._lock:
            bid = self._next_id("BAK")
            snap = copy.deepcopy(self._live_state)
            rec = {"backup_id": bid, "label": label or "手动备份",
                   "size_kb": len(str(snap)) // 8,
                   "state": snap, "status": "ready",
                   "created_at": time.strftime("%Y-%m-%d %H:%M:%S")}
            self._backups[bid] = rec
            self._prune()
            return {"backup_id": bid, "label": rec["label"],
                    "size_kb": rec["size_kb"], "created_at": rec["created_at"]}

    def _prune(self) -> None:
        """按保留策略清理旧备份。"""
        retain = self._policy["retain"]
        if len(self._backups) <= retain:
            return
        ordered = sorted(self._backups.items(),
                         key=lambda kv: kv[1]["created_at"])
        for bid, _ in ordered[:-retain]:
            self._backups.pop(bid, None)

    def list_backups(self) -> List[Dict[str, Any]]:
        with self._lock:
            items = []
            for b in self._backups.values():
                items.append({"backup_id": b["backup_id"], "label": b["label"],
                              "size_kb": b["size_kb"],
                              "created_at": b["created_at"],
                              "status": b["status"]})
            return sorted(items, key=lambda x: x["created_at"], reverse=True)

    def restore(self, backup_id: str) -> Dict[str, Any]:
        with self._lock:
            b = self._backups.get(backup_id)
            if not b:
                raise ValueError("备份不存在")
            self._live_state = copy.deepcopy(b["state"])
            return {"restored": True, "backup_id": backup_id,
                    "live_state": self._live_state,
                    "restored_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    def delete_backup(self, backup_id: str) -> bool:
        with self._lock:
            return self._backups.pop(backup_id, None) is not None

    def get_policy(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._policy)

    def set_policy(self, **fields: Any) -> Dict[str, Any]:
        allow = {"auto", "interval_minutes", "retain", "compress", "encrypt"}
        with self._lock:
            for k, v in fields.items():
                if k in allow and v is not None:
                    self._policy[k] = v
            self._prune()
            return dict(self._policy)

    def simulate_drift(self) -> Dict[str, Any]:
        """模拟运行时数据变化（用于演示备份 vs 恢复对比）。"""
        with self._lock:
            self._live_state["customers"] += 5
            self._live_state["projects"] += 3
            return self._live_state

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return {"backups": len(self._backups),
                    "policy": dict(self._policy),
                    "live_state": self._live_state}


_bak: BackupRecovery | None = None


def get_backup_recovery() -> BackupRecovery:
    global _bak
    if _bak is None:
        _bak = BackupRecovery()
    return _bak
