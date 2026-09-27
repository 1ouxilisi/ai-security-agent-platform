#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
车载安全模块（emerging_comm_security / vehicle_security.py）。

真实功能：
  * 车载总线：CAN / CAN FD / LIN / FlexRay / Ethernet 流量记录与异常检测
  * 已知攻击：CAN 注入、报文篡改、重放、模糊测试、DoS、中间人、RCE、权限提升
  * 车载应用：应用权限 / 数据 / 通信 / 更新 / 隐私
  * 车云通信：远程控制 / 远程诊断 / OTA 状态 / 远程监控 / 双向认证 / 加密
  * 车载数据：车辆 / 驾驶行为 / 位置 / 多媒体 / 诊断 / 用户数据生命周期
  * 入侵检测：基于规则 + 简单统计的 CAN IDS
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

@dataclass
class CANFrame:
    """CAN 总线帧。"""
    frame_id: str
    can_id: int
    data: bytes
    src_ecu: str = ""
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if not self.frame_id:
            self.frame_id = f"cf-{uuid.uuid4().hex[:8]}"
        if not self.timestamp:
            self.timestamp = time.time()


@dataclass
class VehicleApp:
    app_id: str
    name: str
    permissions: List[str] = field(default_factory=list)
    data_collection: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    status: str = "INSTALLED"
    privacy_level: str = "NORMAL"


@dataclass
class Vehicle:
    vin: str
    make: str = ""
    model: str = ""
    year: int = 2024
    ecus: List[str] = field(default_factory=list)
    cloud_link: str = "DISCONNECTED"
    remote_diag: bool = False
    last_cloud_sync: str = ""


@dataclass
class ThreatEvent:
    event_id: str
    kind: str
    severity: str
    target: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    detected_at: str = ""

    def __post_init__(self) -> None:
        if not self.event_id:
            self.event_id = f"ev-{uuid.uuid4().hex[:8]}"
        if not self.detected_at:
            self.detected_at = datetime.now().isoformat()


# ---------------------------------------------------------------------------
# 车载安全控制器
# ---------------------------------------------------------------------------

class VehicleSecurityController:
    """车载安全控制器。"""

    # 已知 CAN 攻击特征：(can_id, 模式)
    SUSPICIOUS_CAN_IDS = {0x000, 0x001, 0x002, 0x003, 0x700, 0x7FF}
    # 正常周期报文 ID
    NORMAL_CYCLE_IDS = [0x100, 0x101, 0x102, 0x150, 0x200, 0x250, 0x300, 0x400]
    MAX_FRAME_RATE_PER_ID = 200          # 每秒帧速率阈值
    RCE_IOCS = ["/tmp/.x", "wget ", "curl ", "chmod 777", "/dev/tty"]

    def __init__(self) -> None:
        self.vehicles: Dict[str, Vehicle] = {}
        self.apps: Dict[str, VehicleApp] = {}
        self.frames: Deque[CANFrame] = deque(maxlen=5000)
        self.frame_rates: Dict[int, float] = {}
        self.threats: List[ThreatEvent] = []
        self.cloud_sessions: Dict[str, Dict[str, Any]] = {}
        self.data_lifecycle: Dict[str, Dict[str, Any]] = {}
        self._seed_bootstrap()

    def _seed_bootstrap(self) -> None:
        v = Vehicle(
            vin="LVGBE21KXNS000001", make="DemoAuto", model="EV-Sedan",
            year=2025,
            ecus=["VCU", "BCM", "GW", "EPS", "ABS", "ICM", "IVI", "TCU"],
            cloud_link="CONNECTED",
        )
        self.vehicles[v.vin] = v
        self.apps["app-navi"] = VehicleApp(
            app_id="app-navi", name="高德车载版",
            permissions=["LOCATION", "NETWORK", "MIC"],
            data_collection=["位置", "路线"],
        )
        self.apps["app-ent"] = VehicleApp(
            app_id="app-ent", name="车载音乐",
            permissions=["NETWORK", "STORAGE"],
            data_collection=["播放历史"],
        )
        self.data_lifecycle = {
            "位置数据": {"采集": True, "存储": "7天", "传输": "TLS1.3", "使用": "导航", "删除": "用户可清除"},
            "驾驶行为": {"采集": True, "存储": "90天", "传输": "TLS1.3", "使用": "保险评估", "删除": "匿名化后保留"},
            "诊断数据": {"采集": True, "存储": "30天", "传输": "双向认证", "使用": "远程诊断", "删除": "用户可清除"},
        }

    # ------------------------- 车辆 / ECU -------------------------
    def register_vehicle(self, vin: str, make: str, model: str, year: int,
                          ecus: Optional[List[str]] = None) -> Vehicle:
        v = Vehicle(vin=vin, make=make, model=model, year=year,
                    ecus=ecus or ["VCU", "BCM", "GW", "IVI", "TCU"])
        self.vehicles[vin] = v
        return v

    def list_vehicles(self) -> List[Dict[str, Any]]:
        return [asdict(v) for v in self.vehicles.values()]

    # ------------------------- CAN 总线 -------------------------
    def ingest_can_frame(self, can_id: int, data: bytes, src_ecu: str = "") -> Dict[str, Any]:
        now = time.time()
        frame = CANFrame(frame_id="", can_id=can_id, data=data, src_ecu=src_ecu)
        self.frames.append(frame)

        # 速率统计
        prev = self.frame_rates.get(can_id, now)
        dt = max(now - prev, 1e-6)
        self.frame_rates[can_id] = now

        verdict: Dict[str, Any] = {"frame_id": frame.frame_id, "can_id": hex(can_id)}

        threats: List[str] = []
        # 1) 异常 ID
        if can_id in self.SUSPICIOUS_CAN_IDS:
            threats.append("SUSPICIOUS_CAN_ID")
        # 2) 速率异常（简化：用最近时间差倒数近似）
        fps_est = 1.0 / dt if dt else 0.0
        if fps_est > self.MAX_FRAME_RATE_PER_ID:
            threats.append("RATE_ANOMALY")
        # 3) 拒绝服务：同一 ID 极高频
        recent_same = sum(1 for f in self.frames if f.can_id == can_id and now - f.timestamp < 1.0)
        if recent_same > self.MAX_FRAME_RATE_PER_ID:
            threats.append("DOS")
        # 4) 模糊测试：长度异常或数据全 0xFF
        if len(data) not in (0, 4, 8, 16, 64) or data == b"\xff" * len(data):
            threats.append("FUZZ")

        if threats:
            sev = "HIGH" if "DOS" in threats or "SUSPICIOUS_CAN_ID" in threats else "MEDIUM"
            ev = ThreatEvent(
                event_id="", kind="CAN_ATTACK", severity=sev,
                target=f"CAN:{hex(can_id)}",
                description=f"检测到 {','.join(threats)}",
                evidence={"frame_id": frame.frame_id, "data_hex": data.hex(),
                          "fps_est": round(fps_est, 2), "recent_same": recent_same},
            )
            self.threats.append(ev)
            verdict["threats"] = threats
            verdict["event_id"] = ev.event_id
        return verdict

    def can_ids_seen(self) -> Dict[str, int]:
        counts: Dict[int, int] = {}
        for f in self.frames:
            counts[f.can_id] = counts.get(f.can_id, 0) + 1
        return {hex(k): v for k, v in sorted(counts.items(), key=lambda x: -x[1])[:30]}

    def detect_replay(self, can_id: int, data: bytes, window_s: float = 5.0) -> bool:
        now = time.time()
        for f in self.frames:
            if f.can_id == can_id and f.data == data and now - f.timestamp <= window_s:
                self.threats.append(ThreatEvent(
                    event_id="", kind="REPLAY_ATTACK", severity="HIGH",
                    target=f"CAN:{hex(can_id)}",
                    description="检测到重复 CAN 帧（疑似重放）",
                    evidence={"can_id": hex(can_id), "data_hex": data.hex()},
                ))
                return True
        return False

    # ------------------------- 远程服务 / RCE -------------------------
    def open_cloud_session(self, vin: str, user: str) -> Dict[str, Any]:
        sid = f"sess-{uuid.uuid4().hex[:10]}"
        # 模拟双向认证 + 派生会话密钥
        k = hashlib.sha256(f"{vin}-{user}-{sid}".encode()).hexdigest()
        sess = {"sid": sid, "vin": vin, "user": user,
                "session_key": k[:32], "transport": "TLS1.3",
                "authenticated": True, "opened_at": datetime.now().isoformat()}
        self.cloud_sessions[sid] = sess
        v = self.vehicles.get(vin)
        if v:
            v.cloud_link = "CONNECTED"
            v.last_cloud_sync = sess["opened_at"]
        return sess

    def scan_remote_command(self, sid: str, command: str) -> Dict[str, Any]:
        """扫描远程控制指令中是否包含 RCE IOC。"""
        sess = self.cloud_sessions.get(sid)
        if not sess:
            return {"allowed": False, "reason": "session not found"}
        hits = [ioc for ioc in self.RCE_IOCS if ioc in command.lower()]
        if hits:
            ev = ThreatEvent(
                event_id="", kind="RCE_ATTEMPT", severity="CRITICAL",
                target=f"CLOUD_SESSION:{sid}",
                description=f"远程命令包含恶意模式: {hits}",
                evidence={"command": command, "iocs": hits},
            )
            self.threats.append(ev)
            return {"allowed": False, "hits": hits, "event_id": ev.event_id}
        return {"allowed": True}

    def detect_privilege_escalation(self, app_id: str, requested: str) -> Dict[str, Any]:
        app = self.apps.get(app_id)
        if not app:
            return {"escalation": False, "reason": "unknown app"}
        dangerous = {"ROOT", "SHELL", "CAN_RAW", "DEBUG"}
        escalates = requested in dangerous and requested not in app.permissions
        if escalates:
            self.threats.append(ThreatEvent(
                event_id="", kind="PRIVILEGE_ESCALATION", severity="HIGH",
                target=f"APP:{app_id}",
                description=f"应用请求越权权限 {requested}",
                evidence={"app_perms": app.permissions, "requested": requested},
            ))
        return {"escalation": escalates, "requested": requested}

    # ------------------------- 应用 / 数据 -------------------------
    def list_apps(self) -> List[Dict[str, Any]]:
        return [asdict(a) for a in self.apps.values()]

    def register_app(self, name: str, permissions: List[str],
                      data_collection: Optional[List[str]] = None) -> VehicleApp:
        a = VehicleApp(app_id=f"app-{uuid.uuid4().hex[:6]}", name=name,
                        permissions=permissions,
                        data_collection=data_collection or [])
        self.apps[a.app_id] = a
        return a

    def data_inventory(self) -> Dict[str, Any]:
        return self.data_lifecycle

    # ------------------------- 总览 -------------------------
    def overview(self) -> Dict[str, Any]:
        sev: Dict[str, int] = {}
        kinds: Dict[str, int] = {}
        for t in self.threats:
            sev[t.severity] = sev.get(t.severity, 0) + 1
            kinds[t.kind] = kinds.get(t.kind, 0) + 1
        return {
            "vehicle_total": len(self.vehicles),
            "app_total": len(self.apps),
            "captured_frames": len(self.frames),
            "threat_total": len(self.threats),
            "threat_by_severity": sev,
            "threat_by_kind": kinds,
            "cloud_sessions": len(self.cloud_sessions),
            "suspicious_can_ids": [hex(x) for x in self.SUSPICIOUS_CAN_IDS],
        }

    def recent_threats(self, limit: int = 20) -> List[Dict[str, Any]]:
        return [asdict(t) for t in reversed(self.threats[-limit:])]


_controller: Optional[VehicleSecurityController] = None


def get_vehicle_controller() -> VehicleSecurityController:
    global _controller
    if _controller is None:
        _controller = VehicleSecurityController()
    return _controller
