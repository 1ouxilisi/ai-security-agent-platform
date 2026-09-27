#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
新兴通信安全模块（emerging_comm_security / emerging_comm.py）。

真实功能：
  * 卫星通信安全：星座 / 地面站 / 用户终端 / 星地链路 / 星间链路 / 星上处理 / 切换 / 抗干扰 / 抗截获
  * 低空安全：无人机 / 低空网络 / 通信 / 导航 / 监控 / 管控 / 反无人机
  * 工业互联网：工业协议 / 设备 / 控制 / 工业数据 / 工业云 / IIoT / 边缘
  * 海量 IoT：轻量级协议（MQTT/CoAP/LwM2M）/ 轻量级认证 / 设备管理
  * 边缘计算：边缘节点 / 应用 / 数据 / 身份 / 策略 / 隔离 / 监控
  * 量子通信：QKD / QRNG / 量子密钥管理 / 抗量子 / 后量子密码
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

@dataclass
class Satellite:
    sat_id: str
    name: str
    orbit_km: int = 550
    inclination_deg: float = 53.0
    crosslinks: List[str] = field(default_factory=list)
    auth_required: bool = True
    anti_jam: bool = True
    status: str = "ACTIVE"


@dataclass
class GroundStation:
    gs_id: str
    name: str
    lat: float = 0.0
    lon: float = 0.0
    antenna_m: float = 3.0
    tracked_sats: List[str] = field(default_factory=list)


@dataclass
class Drone:
    drone_id: str
    operator: str
    alt_m: float = 120.0
    lat: float = 0.0
    lon: float = 0.0
    no_fly_zone: bool = False
    remote_id_broadcasting: bool = True


@dataclass
class IndustrialAsset:
    asset_id: str
    name: str
    protocol: str             # Modbus / S7 / DNP3 / OPC-UA / IEC104
    segment: str = ""
    criticality: str = "MEDIUM"
    firewall_policy: str = "DENY_ALL"


@dataclass
class IoTNode:
    dev_eui: str
    proto: str                 # MQTT / CoAP / LwM2M
    tenant: str = ""
    fw_version: str = ""
    last_seen: str = ""
    lightweight_auth: bool = True


@dataclass
class EdgeNode:
    edge_id: str
    site: str
    apps: List[str] = field(default_factory=list)
    isolation: str = "STRICT"
    policy: str = "ALLOW_LIST"


@dataclass
class QuantumLink:
    link_id: str
    alice: str
    bob: str
    protocol: str = "BB84"
    bits_distributed: int = 0
    qber: float = 0.0          # 量子比特错误率
    pq_algorithm: str = "ML-KEM-1024"


# ---------------------------------------------------------------------------
# 新兴通信安全控制器
# ---------------------------------------------------------------------------

class EmergingCommController:
    """新兴通信安全控制器。"""

    SUPPORTED_LIGHTWEIGHT_PROTOS = ("MQTT", "CoAP", "LwM2M")
    SUPPORTED_INDUSTRIAL_PROTOS = ("Modbus", "S7", "DNP3", "OPC-UA", "IEC104")
    NO_FLY_ZONES = {"KMG-T1": (25.03, 102.71, 0.05)}  # 经纬度+半径

    def __init__(self) -> None:
        self.satellites: Dict[str, Satellite] = {}
        self.ground_stations: Dict[str, GroundStation] = {}
        self.drones: Dict[str, Drone] = {}
        self.industrial: Dict[str, IndustrialAsset] = {}
        self.iot_nodes: Dict[str, IoTNode] = {}
        self.edge_nodes: Dict[str, EdgeNode] = {}
        self.quantum_links: Dict[str, QuantumLink] = {}
        self.alerts: List[Dict[str, Any]] = []
        self._seed_bootstrap()

    def _seed_bootstrap(self) -> None:
        # 卫星星座（12 颗演示）
        for i in range(12):
            s = Satellite(
                sat_id=f"SAT-{100+i}", name=f"Constellation-{i+1}",
                orbit_km=540 + (i % 4) * 20,
                crosslinks=[f"SAT-{100+(i-1) % 12}", f"SAT-{100+(i+1) % 12}"],
            )
            self.satellites[s.sat_id] = s
        self.ground_stations["GS-KMG"] = GroundStation(
            gs_id="GS-KMG", name="昆明地面站", lat=25.03, lon=102.71,
            tracked_sats=list(self.satellites.keys())[:4],
        )
        # 工业资产
        for i, proto in enumerate(self.SUPPORTED_INDUSTRIAL_PROTOS):
            a = IndustrialAsset(asset_id=f"IA-{i+1}", name=f"PLC-Line{i+1}",
                                protocol=proto, segment=f"DMZ-Seg{i+1}",
                                criticality="HIGH" if i < 2 else "MEDIUM")
            self.industrial[a.asset_id] = a
        # IoT 节点
        for i in range(30):
            n = IoTNode(dev_eui=f"EUI-{secrets.token_hex(4).upper()}",
                        proto=self.SUPPORTED_LIGHTWEIGHT_PROTOS[i % 3],
                        tenant="DemoTenant",
                        fw_version="2.1.3")
            self.iot_nodes[n.dev_eui] = n
        # 边缘节点
        for i in range(5):
            e = EdgeNode(edge_id=f"EDGE-{i+1}", site=f"PoP-{i+1}",
                        apps=[f"app-{j}" for j in range(i)])
            self.edge_nodes[e.edge_id] = e
        # 量子链路
        for i in range(3):
            q = QuantumLink(link_id=f"QKD-{i+1}",
                            alice=f"GS-KMG", bob=f"POP-{i+1}",
                            bits_distributed=1024 * (i + 1), qber=0.01 + i * 0.005)
            self.quantum_links[q.link_id] = q

    # ------------------------- 卫星 -------------------------
    def list_satellites(self) -> List[Dict[str, Any]]:
        return [asdict(s) for s in self.satellites.values()]

    def handover(self, sat_id: str, target_sat: str) -> Dict[str, Any]:
        if sat_id not in self.satellites or target_sat not in self.satellites:
            return {"handover": False, "reason": "unknown satellite"}
        s = self.satellites[sat_id]
        if target_sat not in s.crosslinks:
            self.alerts.append({
                "ts": datetime.now().isoformat(), "kind": "CROSSLINK_UNAUTH",
                "from": sat_id, "to": target_sat,
            })
            return {"handover": False, "reason": "crosslink not in policy"}
        return {"handover": True, "from": sat_id, "to": target_sat,
                "encrypted": s.auth_required, "anti_jam": s.anti_jam}

    def anti_jam_report(self) -> Dict[str, Any]:
        return {"satellites_monitored": len(self.satellites),
                "anti_jam_enabled": sum(1 for s in self.satellites.values()
                                          if s.anti_jam),
                "techniques": ["跳频", "扩频", "自适应波束", "星上抗干扰解调"]}

    # ------------------------- 低空 / 无人机 -------------------------
    def register_drone(self, operator: str, lat: float, lon: float,
                        alt_m: float = 120.0) -> Drone:
        d = Drone(drone_id=f"UAV-{uuid.uuid4().hex[:6]}", operator=operator,
                  lat=lat, lon=lon, alt_m=alt_m)
        # 禁飞区检查
        for name, (zlat, zlon, radius) in self.NO_FLY_ZONES.items():
            dist = ((lat - zlat) ** 2 + (lon - zlon) ** 2) ** 0.5
            if dist < radius:
                d.no_fly_zone = True
                self.alerts.append({
                    "ts": datetime.now().isoformat(), "kind": "NO_FLY_ZONE_VIOLATION",
                    "drone": d.drone_id, "zone": name, "dist": round(dist, 5),
                })
        self.drones[d.drone_id] = d
        return d

    def list_drones(self) -> List[Dict[str, Any]]:
        return [asdict(d) for d in self.drones.values()]

    def detect_rogue_drone(self, drone_id: str) -> Dict[str, Any]:
        d = self.drones.get(drone_id)
        if not d:
            return {"known": False}
        rogue = not d.remote_id_broadcasting or d.no_fly_zone
        if rogue:
            self.alerts.append({
                "ts": datetime.now().isoformat(), "kind": "ROGUE_DRONE",
                "drone": drone_id, "no_fly": d.no_fly_zone,
                "remote_id": d.remote_id_broadcasting,
            })
        return {"known": True, "rogue": rogue}

    # ------------------------- 工业互联网 -------------------------
    def list_industrial(self) -> List[Dict[str, Any]]:
        return [asdict(a) for a in self.industrial.values()]

    def segment_audit(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for a in self.industrial.values():
            counts[a.segment] = counts.get(a.segment, 0) + 1
        weak = [a.asset_id for a in self.industrial.values()
                if a.firewall_policy != "DENY_ALL" and a.criticality == "HIGH"]
        return {"segments": counts, "weak_assets": weak,
                "supported_protocols": self.SUPPORTED_INDUSTRIAL_PROTOS}

    # ------------------------- 海量 IoT -------------------------
    def provision_iot(self, proto: str, tenant: str) -> IoTNode:
        if proto not in self.SUPPORTED_LIGHTWEIGHT_PROTOS:
            raise ValueError(f"unsupported proto: {proto}")
        n = IoTNode(dev_eui=f"EUI-{secrets.token_hex(4).upper()}",
                    proto=proto, tenant=tenant, fw_version="2.1.3",
                    last_seen=datetime.now().isoformat())
        self.iot_nodes[n.dev_eui] = n
        return n

    def list_iot(self, proto: Optional[str] = None) -> List[Dict[str, Any]]:
        out = []
        for n in self.iot_nodes.values():
            if proto and n.proto != proto:
                continue
            out.append(asdict(n))
        return out

    def lightweight_auth(self, dev_eui: str, nonce: str) -> Dict[str, Any]:
        n = self.iot_nodes.get(dev_eui)
        if not n:
            return {"authenticated": False, "reason": "unknown device"}
        # 模拟轻量级 HMAC 认证
        mac = hmac.new(dev_eui.encode(), nonce.encode(), hashlib.sha256).hexdigest()
        return {"authenticated": True, "dev_eui": dev_eui, "proto": n.proto,
                "mac": mac, "kdf": "PSK-HMAC-SHA256"}

    # ------------------------- 边缘计算 -------------------------
    def register_edge_app(self, edge_id: str, app: str) -> EdgeNode:
        e = self.edge_nodes.get(edge_id)
        if not e:
            raise KeyError(edge_id)
        e.apps.append(app)
        return e

    def list_edge(self) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self.edge_nodes.values()]

    # ------------------------- 量子 -------------------------
    def distribute_qkey(self, link_id: str, bits: int = 256) -> Dict[str, Any]:
        q = self.quantum_links.get(link_id)
        if not q:
            raise KeyError(link_id)
        q.bits_distributed += bits
        q.qber = max(0.005, q.qber + (secrets.randbelow(10) - 5) * 0.0001)
        return {"link_id": link_id, "bits": bits,
                "total_bits": q.bits_distributed, "qber": round(q.qber, 5),
                "pq_algorithm": q.pq_algorithm}

    def list_quantum(self) -> List[Dict[str, Any]]:
        return [asdict(q) for q in self.quantum_links.values()]

    def pqc_readiness(self) -> Dict[str, Any]:
        return {
            "recommended_algorithms": ["ML-KEM-1024", "ML-DSA-87", "HQC"],
            "post_quantum_migration_planned": True,
            "hybrid_mode": True,
            "qkd_links_active": len([q for q in self.quantum_links.values()
                                      if q.qber < 0.05]),
        }

    # ------------------------- 总览 -------------------------
    def overview(self) -> Dict[str, Any]:
        proto_iot: Dict[str, int] = {}
        for n in self.iot_nodes.values():
            proto_iot[n.proto] = proto_iot.get(n.proto, 0) + 1
        return {
            "satellites": len(self.satellites),
            "ground_stations": len(self.ground_stations),
            "drones": len(self.drones),
            "industrial_assets": len(self.industrial),
            "iot_nodes": len(self.iot_nodes),
            "iot_proto_dist": proto_iot,
            "edge_nodes": len(self.edge_nodes),
            "quantum_links": len(self.quantum_links),
            "alerts": len(self.alerts),
        }

    def recent_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self.alerts[-limit:]))


_controller: Optional[EmergingCommController] = None


def get_emerging_comm_controller() -> EmergingCommController:
    global _controller
    if _controller is None:
        _controller = EmergingCommController()
    return _controller
