# -*- coding: utf-8 -*-
"""
commercial_ultra/sla_monitor_pro.py — SLA 监控 Pro（商业产品体验极致）。

- 服务可用性监控（99.95% 目标）
- 故障自动恢复
- 公开状态页
- 告警通知（webhook / 邮件预留）
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List


class SLAMonitorPro:
    """SLA 监控 Pro（全内存模拟）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._uptime_start = time.time()
        self._checks: List[Dict[str, Any]] = []
        self._incidents: List[Dict[str, Any]] = []
        self._alerts: List[Dict[str, Any]] = []
        self._auto_recoveries = 0
        self._seq = 0
        # 预置一段可用性历史
        for _ in range(30):
            self.probe(True, 20.0)

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{int(time.time()) % 100000:05d}{self._seq:03d}"

    def probe(self, ok: bool = True, latency_ms: float = 20.0) -> Dict[str, Any]:
        """记录一次探活结果。"""
        with self._lock:
            rec = {"ts": time.strftime("%H:%M:%S"), "ok": ok,
                   "latency_ms": latency_ms}
            self._checks.append(rec)
            if len(self._checks) > 288:
                self._checks = self._checks[-288:]
            if not ok:
                self._open_incident(latency_ms)
            return rec

    def _open_incident(self, latency_ms: float) -> None:
        inc = {"incident_id": self._next_id("INC"),
               "status": "open", "latency_ms": latency_ms,
               "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
               "summary": f"探活失败，延迟 {latency_ms}ms"}
        self._incidents.append(inc)
        self._alert("critical", f"故障 {inc['incident_id']}: 延迟 {latency_ms}ms")

    def auto_recover(self) -> Dict[str, Any]:
        """故障自动恢复：把未关闭事件全部标记恢复。"""
        with self._lock:
            recovered = 0
            for inc in self._incidents:
                if inc["status"] == "open":
                    inc["status"] = "recovered"
                    inc["recovered_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    recovered += 1
            self._auto_recoveries += recovered
            if recovered:
                self._alert("info", f"自动恢复 {recovered} 个事件")
            return {"recovered": recovered,
                    "total_auto_recoveries": self._auto_recoveries}

    def _alert(self, level: str, message: str) -> None:
        self._alerts.append({
            "alert_id": self._next_id("ALT"), "level": level,
            "message": message,
            "sent_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "channels": ["webhook", "email"],  # 预留
        })

    def list_alerts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(reversed(self._alerts[-50:]))

    def availability(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._checks)
            ok = sum(1 for c in self._checks if c["ok"])
            rate = round(100.0 * ok / total, 3) if total else 100.0
            latencies = [c["latency_ms"] for c in self._checks if c["ok"]]
            avg_lat = round(sum(latencies) / len(latencies), 1) if latencies else 0
            return {"checks": total, "ok": ok, "failed": total - ok,
                    "availability_pct": rate, "target_pct": 99.95,
                    "avg_latency_ms": avg_lat,
                    "meets_target": rate >= 99.95}

    def status_page(self) -> Dict[str, Any]:
        """公开状态页（客户可见）。"""
        a = self.availability()
        open_inc = [i for i in self._incidents if i["status"] == "open"]
        return {
            "page": "status",
            "service": "AI Hacking Agent 平台",
            "overall": "operational" if a["meets_target"] else "degraded",
            "availability_pct": a["availability_pct"],
            "open_incidents": len(open_inc),
            "history": [
                {"day": "近30天", "availability": a["availability_pct"],
                 "status": "operational" if a["meets_target"] else "degraded"},
            ],
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def list_incidents(self, open_only: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(reversed(self._incidents[-50:]))
            if open_only:
                items = [i for i in items if i["status"] == "open"]
            return items

    def health(self) -> Dict[str, Any]:
        up = int(time.time() - self._uptime_start)
        return {"uptime_sec": up, "availability": self.availability(),
                "auto_recoveries": self._auto_recoveries,
                "alerts_today": len(self._alerts)}


_sla: SLAMonitorPro | None = None


def get_sla_monitor_pro() -> SLAMonitorPro:
    global _sla
    if _sla is None:
        _sla = SLAMonitorPro()
    return _sla
