#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_pro/sla_monitor.py — SLA 保障。

- 服务可用性监控（探针 + 历史窗口）
- 故障自动恢复（健康检查失败 → 自动重启计数 / 告警）
- 备份与恢复（快照内存字典）
- 状态页（公开可读的 status page 数据）
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional


class SLAMonitor:
    """SLA 监控与保障（全内存模拟）。"""

    TARGET_AVAILABILITY = 99.9          # 企业版 SLA 目标 99.9%

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._start_ts = time.time()
        # 探针历史：[{ts, ok, latency_ms}]
        self._probes: List[Dict[str, Any]] = []
        # 故障事件
        self._incidents: List[Dict[str, Any]] = []
        # 备份快照
        self._backups: Dict[str, Dict[str, Any]] = {}
        # 自动恢复计数
        self._restarts = 0
        self._current_status = "operational"

    # ------------------------------------------------------------------ #
    # 可用性监控
    # ------------------------------------------------------------------ #
    def probe(self, ok: bool = True, latency_ms: float = 12.0) -> Dict[str, Any]:
        """记录一次健康探针结果。"""
        with self._lock:
            rec = {"ts": int(time.time()), "ok": ok, "latency_ms": latency_ms}
            self._probes.append(rec)
            if len(self._probes) > 1000:
                self._probes = self._probes[-1000:]
            if not ok:
                self._current_status = "degraded"
                self._raise_incident("探针失败", f"延迟 {latency_ms}ms 或服务不可用")
            else:
                if self._current_status != "operational":
                    self._current_status = "operational"
            return rec

    def availability(self, window: int = 500) -> Dict[str, Any]:
        """计算最近 window 次探针的可用性百分比。"""
        with self._lock:
            samples = self._probes[-window:] or [{"ok": True, "latency_ms": 0}]
            ok_cnt = sum(1 for s in samples if s["ok"])
            pct = round(ok_cnt / len(samples) * 100, 3)
            return {
                "availability_pct": pct,
                "target_pct": self.TARGET_AVAILABILITY,
                "meets_target": pct >= self.TARGET_AVAILABILITY,
                "samples": len(samples),
                "ok": ok_cnt,
                "failed": len(samples) - ok_cnt,
            }

    # ------------------------------------------------------------------ #
    # 故障自动恢复
    # ------------------------------------------------------------------ #
    def _raise_incident(self, title: str, detail: str) -> None:
        self._incidents.append({
            "id": f"INC-{len(self._incidents) + 1:04d}",
            "title": title, "detail": detail,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "resolved": False,
        })

    def auto_recover(self) -> Dict[str, Any]:
        """模拟故障自动恢复：检测未解决事件 → 执行重启 → 标记恢复。"""
        with self._lock:
            unresolved = [i for i in self._incidents if not i["resolved"]]
            recovered = 0
            for inc in unresolved:
                inc["resolved"] = True
                inc["resolved_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                inc["recovery"] = "自动重启 worker 池 + 重连依赖"
                recovered += 1
            if recovered:
                self._restarts += 1
                self._current_status = "operational"
            return {"recovered": recovered, "auto_restarts": self._restarts,
                    "current_status": self._current_status}

    def list_incidents(self, only_open: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            if only_open:
                return [i for i in self._incidents if not i["resolved"]]
            return list(reversed(self._incidents))

    # ------------------------------------------------------------------ #
    # 备份与恢复
    # ------------------------------------------------------------------ #
    def backup(self, label: str = "") -> Dict[str, Any]:
        """对关键状态做快照备份。"""
        with self._lock:
            bid = f"BK-{int(time.time())}"
            snap = {
                "backup_id": bid, "label": label or "自动快照",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "probes_snapshot": len(self._probes),
                "incidents_snapshot": len(self._incidents),
                "size_kb": 12,
            }
            self._backups[bid] = snap
            return snap

    def list_backups(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(reversed(list(self._backups.values())))

    def restore(self, backup_id: str) -> Dict[str, Any]:
        with self._lock:
            if backup_id not in self._backups:
                raise ValueError("备份不存在")
            b = self._backups[backup_id]
            return {"restored_from": backup_id, "label": b["label"],
                    "restored_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "message": "已恢复到快照点（演示：重建探针与事件指针）"}

    # ------------------------------------------------------------------ #
    # 状态页
    # ------------------------------------------------------------------ #
    def status_page(self) -> Dict[str, Any]:
        """公开状态页数据。"""
        av = self.availability()
        up_days = round((time.time() - self._start_ts) / 86400, 2)
        return {
            "page": "status",
            "status": self._current_status,
            "availability_30d": av["availability_pct"],
            "target": av["target_pct"],
            "uptime_days": up_days,
            "open_incidents": len(self.list_incidents(only_open=True)),
            "components": [
                {"name": "API 网关", "status": "operational"},
                {"name": "扫描引擎", "status": "operational"},
                {"name": "客户门户", "status": "operational"},
                {"name": "报告服务", "status": "operational"},
                {"name": "计费服务", "status": "operational"},
            ],
            "auto_recoveries": self._restarts,
        }

    def health(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "status": self._current_status,
                "uptime_s": int(time.time() - self._start_ts),
                "probes": len(self._probes),
                "incidents": len(self._incidents),
                "open_incidents": len(self.list_incidents(only_open=True)),
                "backups": len(self._backups),
            }


_sla: SLAMonitor | None = None


def get_sla_monitor() -> SLAMonitor:
    global _sla
    if _sla is None:
        _sla = SLAMonitor()
    return _sla
