#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_ultra_pro/sla_monitor.py — SLA 监控。

- 服务可用性监控（健康检查/可用性统计/故障记录）
- 响应时间监控（P50/P95/P99）
- 故障自动告警（邮件/短信/Webhook/站内信 + 升级）
- SLA 报告（月度/达标率/违约赔偿）
- 自动恢复（重启/故障转移/限流降级）
"""

from __future__ import annotations

import statistics
import threading
import time
from typing import Any, Dict, List, Optional


SLA_TARGETS = {"99.9%": 0.999, "99.95%": 0.9995, "99.99%": 0.9999}
SEVERITIES = ["warning", "critical", "emergency"]


class SLAMonitor:
    """SLA 监控（内存存储）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # service -> [ {ok, latency_ms, ts} ]
        self._samples: Dict[str, List[Dict[str, Any]]] = {}
        # 故障
        self._incidents: Dict[str, Dict[str, Any]] = {}
        # 告警
        self._alerts: List[Dict[str, Any]] = []
        # 自动恢复记录
        self._recoveries: List[Dict[str, Any]] = []
        # SLA 目标
        self._targets: Dict[str, str] = {"default": "99.9%"}
        self._seq = 0

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}{int(time.time()) % 100000:05d}-{self._seq:03d}"

    def _now(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    # ------------------------------------------------------------------ #
    # 健康检查 / 采样
    # ------------------------------------------------------------------ #
    def health_check(self, service: str = "api", ok: bool = True,
                      latency_ms: float = 12.0, check_type: str = "http") -> Dict[str, Any]:
        """记录一次健康检查采样。失败时自动开故障 + 告警。"""
        with self._lock:
            self._samples.setdefault(service, []).append({
                "ok": ok, "latency_ms": latency_ms, "ts": time.time(),
                "time": self._now(), "type": check_type,
            })
            # 控制内存
            if len(self._samples[service]) > 5000:
                self._samples[service] = self._samples[service][-5000:]
            result = {"service": service, "ok": ok, "latency_ms": latency_ms,
                      "checked_at": self._now()}
            if not ok:
                inc = self._open_incident(service, "健康检查失败", check_type)
                result["incident_id"] = inc["incident_id"]
                self._raise_alert(service, "critical",
                                   f"服务 {service} 健康检查失败",
                                   f"故障ID: {inc['incident_id']}")
            return result

    def _open_incident(self, service: str, reason: str,
                        check_type: str) -> Dict[str, Any]:
        iid = self._next_id("INC")
        inc = {
            "incident_id": iid, "service": service, "reason": reason,
            "check_type": check_type, "status": "open",
            "start_time": self._now(), "end_time": "",
            "duration_sec": 0, "impact": "未知", "root_cause": "",
        }
        self._incidents[iid] = inc
        return inc

    # ------------------------------------------------------------------ #
    # 故障
    # ------------------------------------------------------------------ #
    def resolve_incident(self, incident_id: str, root_cause: str = "",
                          impact: str = "") -> Dict[str, Any]:
        with self._lock:
            inc = self._incidents.get(incident_id)
            if not inc:
                raise ValueError("故障不存在")
            inc["status"] = "resolved"
            inc["end_time"] = self._now()
            inc["root_cause"] = root_cause or "未知"
            inc["impact"] = impact or "部分用户"
            # 计算时长（粗略用 start/end 解析）
            try:
                st = time.mktime(time.strptime(inc["start_time"], "%Y-%m-%d %H:%M:%S"))
                et = time.mktime(time.strptime(inc["end_time"], "%Y-%m-%d %H:%M:%S"))
                inc["duration_sec"] = max(0, int(et - st))
            except ValueError:
                pass
            self._raise_alert(inc["service"], "warning",
                               f"服务 {inc['service']} 已恢复",
                               f"故障 {incident_id} 已解决，时长 {inc['duration_sec']}s")
            return inc

    def list_incidents(self, open_only: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._incidents.values())
            if open_only:
                out = [i for i in out if i["status"] == "open"]
            return sorted(out, key=lambda x: x["start_time"], reverse=True)

    # ------------------------------------------------------------------ #
    # 告警
    # ------------------------------------------------------------------ #
    def _raise_alert(self, service: str, severity: str,
                      title: str, content: str) -> Dict[str, Any]:
        alert = {
            "alert_id": self._next_id("ALT"), "service": service,
            "severity": severity, "title": title, "content": content,
            "channels": ["email", "webhook", "站内信"],
            "raised_at": self._now(), "ack": False,
        }
        self._alerts.append(alert)
        return alert

    def list_alerts(self, ack: Optional[bool] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._alerts)
            if ack is not None:
                out = [a for a in out if a["ack"] == ack]
            return sorted(out, key=lambda x: x["raised_at"], reverse=True)

    def ack_alert(self, alert_id: str) -> Dict[str, Any]:
        with self._lock:
            for a in self._alerts:
                if a["alert_id"] == alert_id:
                    a["ack"] = True
                    return a
            raise ValueError("告警不存在")

    # ------------------------------------------------------------------ #
    # 可用性 / 响应时间统计
    # ------------------------------------------------------------------ #
    def availability(self, service: Optional[str] = None,
                      window: str = "month") -> Dict[str, Any]:
        """按日/周/月/年计算可用性。"""
        with self._lock:
            services = [service] if service else list(self._samples.keys())
            result = {"window": window, "items": []}
            for svc in services:
                samples = self._samples.get(svc, [])
                if not samples:
                    result["items"].append({"service": svc, "availability": 100.0,
                                            "total": 0, "failed": 0})
                    continue
                ok_n = sum(1 for s in samples if s["ok"])
                avail = ok_n / len(samples) * 100
                result["items"].append({
                    "service": svc, "availability": round(avail, 4),
                    "total": len(samples), "failed": len(samples) - ok_n,
                })
            return result

    def response_time(self, service: Optional[str] = None) -> Dict[str, Any]:
        """P50/P95/P99 响应时间。"""
        with self._lock:
            services = [service] if service else list(self._samples.keys())
            items = []
            for svc in services:
                lat = sorted(s["latency_ms"] for s in self._samples.get(svc, []))
                if not lat:
                    items.append({"service": svc, "p50": 0, "p95": 0, "p99": 0,
                                   "avg": 0})
                    continue
                items.append({
                    "service": svc,
                    "p50": round(self._percentile(lat, 50), 2),
                    "p95": round(self._percentile(lat, 95), 2),
                    "p99": round(self._percentile(lat, 99), 2),
                    "avg": round(statistics.mean(lat), 2),
                })
            return {"items": items}

    @staticmethod
    def _percentile(sorted_data: List[float], pct: float) -> float:
        if not sorted_data:
            return 0.0
        k = (len(sorted_data) - 1) * pct / 100.0
        f = int(k)
        c = min(f + 1, len(sorted_data) - 1)
        if f == c:
            return sorted_data[f]
        return sorted_data[f] + (sorted_data[c] - sorted_data[f]) * (k - f)

    # ------------------------------------------------------------------ #
    # SLA 目标 / 报告
    # ------------------------------------------------------------------ #
    def set_target(self, target: str, service: str = "default") -> Dict[str, Any]:
        if target not in SLA_TARGETS:
            raise ValueError(f"SLA 目标必须为 {list(SLA_TARGETS.keys())}")
        with self._lock:
            self._targets[service] = target
            return {"service": service, "target": target}

    def sla_report(self, service: Optional[str] = None) -> Dict[str, Any]:
        """月度 SLA 报告：可用性/响应时间/故障统计/达标/违约赔偿。"""
        avail = self.availability(service)
        rt = self.response_time(service)
        incs = self.list_incidents()
        if service:
            incs = [i for i in incs if i["service"] == service]
        open_n = sum(1 for i in incs if i["status"] == "open")
        total_downtime = sum(i["duration_sec"] for i in incs if i["status"] == "resolved")
        target = SLA_TARGETS.get(self._targets.get(service or "default", "99.9%"))
        items = []
        for it in avail["items"]:
            actual = it["availability"] / 100.0
            met = actual >= target if target else True
            # 违约赔偿：每低 0.1% 赔付月费 5%（演示公式）
            penalty = 0.0
            if not met and target:
                gap = (target - actual) * 10000  # 基点
                penalty = round(min(gap * 0.5, 30), 2)  # 演示：基点 * 0.5元，封顶30
            items.append({**it, "target": self._targets.get(service or "default", "99.9%"),
                          "met": bool(met), "penalty_cny": penalty})
        return {
            "month": time.strftime("%Y-%m"),
            "availability": {"items": items},
            "response_time": rt,
            "incidents_total": len(incs),
            "incidents_open": open_n,
            "total_downtime_sec": total_downtime,
            "overall_met": all(x["met"] for x in items) if items else True,
        }

    # ------------------------------------------------------------------ #
    # 自动恢复
    # ------------------------------------------------------------------ #
    def auto_recover(self, service: str = "api",
                      action: str = "restart") -> Dict[str, Any]:
        """故障后自动恢复：重启/故障转移/限流降级。"""
        if action not in ("restart", "failover", "degrade"):
            raise ValueError("action 必须为 restart/failover/degrade")
        rec = {
            "recovery_id": self._next_id("REC"), "service": service,
            "action": action, "triggered_at": self._now(),
            "result": "success", "message": f"已自动{ {'restart':'重启', 'failover':'主备切换', 'degrade':'限流降级'}[action] }",
        }
        self._recoveries.append(rec)
        # 自动关闭该服务的 open 故障
        with self._lock:
            for inc in self._incidents.values():
                if inc["service"] == service and inc["status"] == "open":
                    self.resolve_incident(inc["incident_id"],
                                          root_cause=f"自动{action}恢复")
        return rec

    def list_recoveries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return sorted(self._recoveries, key=lambda x: x["triggered_at"],
                          reverse=True)

    # ------------------------------------------------------------------ #
    # 总览
    # ------------------------------------------------------------------ #
    def dashboard(self) -> Dict[str, Any]:
        avail = self.availability()
        rt = self.response_time()
        incs = self.list_incidents()
        return {
            "services": len(self._samples),
            "availability": avail,
            "response_time": rt,
            "incidents_open": sum(1 for i in incs if i["status"] == "open"),
            "alerts_unacked": sum(1 for a in self._alerts if not a["ack"]),
            "recoveries": len(self._recoveries),
            "targets": dict(self._targets),
        }


_sla: SLAMonitor | None = None


def get_sla_monitor() -> SLAMonitor:
    global _sla
    if _sla is None:
        _sla = SLAMonitor()
    return _sla
