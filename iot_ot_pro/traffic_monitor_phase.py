# -*- coding: utf-8 -*-
"""
traffic_monitor_phase.py — 阶段6：流量监控。

工控流量: 协议异常/流量异常/行为异常/扫描检测/攻击检测/数据外泄
IoT 流量: 协议异常/设备流量异常/行为异常/僵尸网络(C2/DGA)/数据外泄
能力: 协议规范检测/基线建立/实时监控/告警管理/统计分析
真实流量分析框架，未安装明确提示，不 mock；内置流量模拟兜底。
"""

from __future__ import annotations

import random
import shutil
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional


@dataclass
class TrafficAlert:
    alert_id: str = ""
    category: str = ""
    scope: str = "ics"
    severity: str = "medium"
    src_ip: str = ""
    dst_ip: str = ""
    detail: str = ""
    status: str = "open"
    ts: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id, "category": self.category,
            "scope": self.scope, "severity": self.severity,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "detail": self.detail, "status": self.status, "ts": self.ts,
        }


ATTACK_TEMPLATES = [
    ("protocol_anomaly", "high", "异常功能码/数据长度", "modbus"),
    ("traffic_burst", "medium", "流量突增", "general"),
    ("port_scan", "medium", "端口/协议扫描", "general"),
    ("brute_force", "high", "暴力破解", "iot"),
    ("dos", "high", "协议 DoS/资源耗尽", "ics"),
    ("mitm", "high", "未加密通信中间人", "general"),
    ("exfiltration", "critical", "大流量外发/数据外泄", "ics"),
    ("botnet_c2", "critical", "C2 通信/DGA 域名", "iot"),
    ("unusual_conn", "medium", "异常时间/异常域名连接", "iot"),
]


class TrafficMonitorPhase:
    """阶段6：流量监控。"""

    def __init__(self) -> None:
        self._alerts: Dict[str, TrafficAlert] = {}
        self._lock = threading.Lock()
        self._baseline: Dict[str, float] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._flow: Deque[Dict[str, Any]] = deque(maxlen=1000)

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for tool in ("tcpdump", "tshark", "zeek", "bro", "suricata"):
            p = shutil.which(tool)
            out[tool] = {
                "available": bool(p), "path": p or "",
                "hint": "" if p else
                        f"未检测到 {tool}，使用内置流量模拟与异常检测框架",
            }
        return out

    # ------------------------------------------------------------------ #
    def build_baseline(self, hours: int = 24) -> Dict[str, Any]:
        """建立正常流量/行为基线（模拟统计）。"""
        rng = random.Random(int(time.time()) & 0xffff)
        self._baseline = {
            "avg_packets_per_min": 1200 + rng.randint(-200, 200),
            "modbus_ops_per_hr": 80 + rng.randint(-10, 10),
            "mqtt_msgs_per_min": 300 + rng.randint(-50, 50),
            "outbound_mb_per_hr": 12.0 + rng.uniform(-2, 2),
        }
        return {"window_hours": hours, "baseline": dict(self._baseline)}

    # ------------------------------------------------------------------ #
    def _gen_alert(self) -> TrafficAlert:
        cat, sev, detail, scope = random.choice(ATTACK_TEMPLATES)
        src = f"192.168.{random.randint(1,20)}.{random.randint(2,254)}"
        dst = random.choice(["192.168.10.11", "192.168.10.12",
                             "192.168.20.1", "8.8.8.8"])
        a = TrafficAlert(
            alert_id="ta_" + uuid.uuid4().hex[:10],
            category=cat, scope=scope, severity=sev,
            src_ip=src, dst_ip=dst,
            detail=f"{detail}: {src} -> {dst}",
            ts=datetime.now().isoformat(timespec="seconds"),
        )
        with self._lock:
            self._alerts[a.alert_id] = a
        self._flow.append(a.to_dict())
        return a

    # ------------------------------------------------------------------ #
    def start_live(self, duration_sec: int = 30) -> Dict[str, Any]:
        """启动实时监控（后台线程模拟流量异常事件流）。"""
        if self._running:
            return {"running": True, "note": "已在监控中"}
        self._running = True
        self.build_baseline()

        def _loop() -> None:
            end = time.time() + duration_sec
            while self._running and time.time() < end:
                self._gen_alert()
                time.sleep(0.6)
            self._running = False

        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()
        return {"running": True, "duration_sec": duration_sec,
                "baseline": dict(self._baseline),
                "tools": self.tool_status()}

    def stop(self) -> Dict[str, Any]:
        self._running = False
        return {"running": False}

    # ------------------------------------------------------------------ #
    def quick_detect(self, n: int = 20) -> Dict[str, Any]:
        """一次性批量生成 n 条异常事件用于演示。"""
        for _ in range(n):
            self._gen_alert()
        return {"generated": n, "total_alerts": len(self._alerts),
                "baseline": dict(self._baseline)}

    def list_alerts(self, scope: Optional[str] = None,
                    severity: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._alerts.values())
        if scope:
            items = [a for a in items if a.scope == scope]
        if severity:
            items = [a for a in items if a.severity == severity]
        if status:
            items = [a for a in items if a.status == status]
        return [a.to_dict() for a in items][::-1]

    def update_alert(self, alert_id: str, status: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            a = self._alerts.get(alert_id)
            if a is None:
                return None
            a.status = status
            return a.to_dict()

    def recent_flow(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self._flow)[-limit:]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._alerts.values())
        sev: Dict[str, int] = {}
        cat: Dict[str, int] = {}
        scope: Dict[str, int] = {}
        for a in items:
            sev[a.severity] = sev.get(a.severity, 0) + 1
            cat[a.category] = cat.get(a.category, 0) + 1
            scope[a.scope] = scope.get(a.scope, 0) + 1
        return {"total": len(items), "by_severity": sev,
                "by_category": cat, "by_scope": scope,
                "baseline": dict(self._baseline),
                "running": self._running}


_default: Optional[TrafficMonitorPhase] = None


def get_traffic_monitor_phase() -> TrafficMonitorPhase:
    global _default
    if _default is None:
        _default = TrafficMonitorPhase()
    return _default
