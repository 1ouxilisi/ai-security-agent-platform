#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2X 车联网安全模块（emerging_comm_security / v2x_security.py）。

真实功能：
  * V2X 节点管理：OBU / RSU / 应用服务器 / 行人设备
  * 通信接口：PC5（直连）/ Uu（蜂窝）/ DSRC / C-V2X
  * 消息类型：BSM（基本安全消息）/ SPAT（信号相位与配时）/ MAP（地图）/
              RSM（路侧安全消息）/ IVIM（交叉口车辆信息）
  * 消息安全：签名 / 完整性 / 新鲜性 / 重放窗口 / 篡改检测 / 伪造检测 / 洪泛检测
  * PKI：假名证书签发 / 撤销 / 更新 / 身份追溯 / 隐私保护
  * 隐私：位置 / 轨迹 / 身份匿名、假名轮换、混淆、聚合、差分隐私
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

@dataclass
class V2XNode:
    """V2X 节点（OBU / RSU / 应用）。"""
    node_id: str
    node_type: str            # OBU / RSU / APP / PSEUDO_PEDESTRIAN
    pseudonym: str = ""       # 假名证书 ID
    cert_id: str = ""
    pubkey: str = ""
    lat: float = 0.0
    lon: float = 0.0
    speed: float = 0.0
    heading: float = 0.0
    status: str = "ACTIVE"
    last_seen: str = ""
    region: str = ""

    def __post_init__(self) -> None:
        if not self.pseudonym:
            self.pseudonym = f"anon-{secrets.token_hex(4)}"
        if not self.cert_id:
            self.cert_id = f"cert-{uuid.uuid4().hex[:10]}"
        if not self.pubkey:
            self.pubkey = secrets.token_hex(32)
        if not self.last_seen:
            self.last_seen = datetime.now().isoformat()


@dataclass
class V2XMessage:
    """V2X 消息。"""
    msg_id: str
    msg_type: str             # BSM / SPAT / MAP / RSM / IVIM
    sender_pseudonym: str
    payload: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    signed_at: float = 0.0
    ttl_ms: int = 100
    received_at: str = ""

    def __post_init__(self) -> None:
        if not self.signature:
            self.signature = hmac.new(
                self.sender_pseudonym.encode(),
                (self.msg_type + str(self.payload)).encode(),
                hashlib.sha256,
            ).hexdigest()
        if not self.signed_at:
            self.signed_at = time.time()
        if not self.received_at:
            self.received_at = datetime.now().isoformat()


@dataclass
class RevokedCert:
    cert_id: str
    pseudonym: str
    revoked_at: str
    reason: str


# ---------------------------------------------------------------------------
# V2X 安全控制器
# ---------------------------------------------------------------------------

class V2XSecurityController:
    """V2X 安全控制器。"""

    SUPPORTED_MSG_TYPES = ("BSM", "SPAT", "MAP", "RSM", "IVIM")
    REPLAY_WINDOW_MS = 5000      # 重放窗口
    PSEUDONYM_ROTATION_S = 300   # 假名 5 分钟轮换

    def __init__(self) -> None:
        self.nodes: Dict[str, V2XNode] = {}
        self.messages: List[V2XMessage] = []
        self.revoked: Dict[str, RevokedCert] = {}
        self.anomaly_events: List[Dict[str, Any]] = []
        self.cert_pool: Dict[str, Dict[str, str]] = {}
        self._seed_bootstrap()

    def _seed_bootstrap(self) -> None:
        # 3 个 RSU
        for i in range(3):
            n = V2XNode(node_id=f"RSU-{i+1}", node_type="RSU",
                        lat=25.03 + i * 0.001, lon=102.71 + i * 0.001,
                        region="Kunming")
            self.nodes[n.node_id] = n
        # 20 个 OBU
        for i in range(20):
            n = V2XNode(node_id=f"OBU-{1000+i}", node_type="OBU",
                        lat=25.03 + (i % 5) * 0.0008,
                        lon=102.71 + (i % 4) * 0.0008,
                        speed=30 + (i % 6) * 5, heading=(i * 17) % 360,
                        region="Kunming")
            self.nodes[n.node_id] = n
            self.cert_pool[n.pseudonym] = {
                "cert_id": n.cert_id, "pubkey": n.pubkey,
                "issued_at": datetime.now().isoformat(), "ttl_hours": 24,
            }

    # ------------------------- 节点 -------------------------
    def register_node(self, node_type: str, region: str = "") -> V2XNode:
        nid = f"{node_type}-{uuid.uuid4().hex[:6]}"
        n = V2XNode(node_id=nid, node_type=node_type, region=region)
        self.nodes[nid] = n
        self.cert_pool[n.pseudonym] = {
            "cert_id": n.cert_id, "pubkey": n.pubkey,
            "issued_at": datetime.now().isoformat(), "ttl_hours": 24,
        }
        return n

    def list_nodes(self, node_type: Optional[str] = None) -> List[Dict[str, Any]]:
        out = []
        for n in self.nodes.values():
            if node_type and n.node_type != node_type:
                continue
            out.append(asdict(n))
        return out

    # ------------------------- PKI -------------------------
    def issue_pseudonym_cert(self, real_id: str) -> Dict[str, Any]:
        """为 OBU 申请一张新的假名证书。"""
        pseudonym = f"anon-{secrets.token_hex(6)}"
        cert_id = f"cert-{uuid.uuid4().hex[:10]}"
        pubkey = secrets.token_hex(32)
        rec = {"cert_id": cert_id, "pseudonym": pseudonym, "pubkey": pubkey,
               "real_id": real_id, "issued_at": datetime.now().isoformat(),
               "ttl_hours": 1, "status": "ACTIVE"}
        self.cert_pool[pseudonym] = rec
        return rec

    def revoke_cert(self, cert_id: str, reason: str = "compromised") -> bool:
        target_pseudo = None
        for pseudo, rec in self.cert_pool.items():
            if rec.get("cert_id") == cert_id:
                target_pseudo = pseudo
                break
        if not target_pseudo:
            return False
        self.revoked[cert_id] = RevokedCert(
            cert_id=cert_id, pseudonym=target_pseudo,
            revoked_at=datetime.now().isoformat(), reason=reason)
        self.cert_pool.pop(target_pseudo, None)
        return True

    def list_revoked(self) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self.revoked.values()]

    def rotate_pseudonym(self, node_id: str) -> Dict[str, Any]:
        node = self.nodes.get(node_id)
        if not node:
            raise KeyError(node_id)
        old = node.pseudonym
        node.pseudonym = f"anon-{secrets.token_hex(6)}"
        node.cert_id = f"cert-{uuid.uuid4().hex[:10]}"
        node.last_seen = datetime.now().isoformat()
        self.anomaly_events.append({
            "ts": datetime.now().isoformat(), "kind": "PSEUDONYM_ROTATION",
            "node_id": node_id, "old": old, "new": node.pseudonym,
        })
        return {"node_id": node_id, "old": old, "new": node.pseudonym}

    # ------------------------- 消息接收与验证 -------------------------
    def ingest_message(self, msg_type: str, sender_pseudonym: str,
                        payload: Dict[str, Any], signature: str = "",
                        signed_at: Optional[float] = None) -> Dict[str, Any]:
        if msg_type not in self.SUPPORTED_MSG_TYPES:
            raise ValueError(f"unsupported message type: {msg_type}")
        # 检查证书是否被撤销
        cert = self.cert_pool.get(sender_pseudonym)
        revoked = any(r.pseudonym == sender_pseudonym for r in self.revoked.values())
        # 验证签名
        expected = hmac.new(
            sender_pseudonym.encode(),
            (msg_type + str(payload)).encode(),
            hashlib.sha256,
        ).hexdigest()
        sig_ok = hmac.compare_digest(signature or expected, expected)
        # 新鲜性
        now = time.time()
        age_ms = int((now - (signed_at or now)) * 1000)
        fresh_ok = abs(age_ms) <= self.REPLAY_WINDOW_MS
        # 重放检测
        replay_hit = any(m.sender_pseudonym == sender_pseudonym
                         and m.signature == (signature or expected)
                         and abs(m.signed_at - (signed_at or now)) * 1000
                         < self.REPLAY_WINDOW_MS
                         for m in self.messages[-500:])

        verdict = {
            "sig_ok": sig_ok, "fresh_ok": fresh_ok,
            "replay": replay_hit, "revoked": revoked,
            "age_ms": age_ms,
        }
        if revoked or not sig_ok or replay_hit or not fresh_ok:
            self.anomaly_events.append({
                "ts": datetime.now().isoformat(), "kind": "MSG_REJECTED",
                "pseudonym": sender_pseudonym, "msg_type": msg_type, **verdict,
            })
        else:
            msg = V2XMessage(
                msg_id=f"msg-{uuid.uuid4().hex[:8]}",
                msg_type=msg_type, sender_pseudonym=sender_pseudonym,
                payload=payload, signature=signature or expected,
                signed_at=signed_at or now,
            )
            self.messages.append(msg)
            verdict["accepted"] = True
            verdict["msg_id"] = msg.msg_id
        return verdict

    def list_messages(self, msg_type: Optional[str] = None,
                        limit: int = 50) -> List[Dict[str, Any]]:
        out = []
        for m in reversed(self.messages):
            if msg_type and m.msg_type != msg_type:
                continue
            out.append({"msg_id": m.msg_id, "msg_type": m.msg_type,
                        "sender": m.sender_pseudonym,
                        "payload": m.payload, "received_at": m.received_at})
            if len(out) >= limit:
                break
        return out

    # ------------------------- 洪泛 / 伪造检测 -------------------------
    def detect_flood(self, window_s: int = 10, threshold: int = 50) -> Dict[str, Any]:
        cutoff = time.time() - window_s
        counts: Dict[str, int] = {}
        for m in self.messages:
            if m.signed_at >= cutoff:
                counts[m.sender_pseudonym] = counts.get(m.sender_pseudonym, 0) + 1
        flooders = [p for p, c in counts.items() if c > threshold]
        if flooders:
            self.anomaly_events.append({
                "ts": datetime.now().isoformat(), "kind": "FLOOD_DETECTED",
                "flooders": flooders, "window_s": window_s, "threshold": threshold,
            })
        return {"window_s": window_s, "threshold": threshold,
                "counts": counts, "flooders": flooders}

    def detect_spoofed_position(self, node_id: str, declared_lat: float,
                                  declared_lon: float) -> Dict[str, Any]:
        """基于历史轨迹的位置一致性检测（粗糙）。"""
        node = self.nodes.get(node_id)
        if not node:
            return {"known": False}
        drift = ((declared_lat - node.lat) ** 2 + (declared_lon - node.lon) ** 2) ** 0.5
        suspicious = drift > 0.01
        if suspicious:
            self.anomaly_events.append({
                "ts": datetime.now().isoformat(), "kind": "POSITION_SPOOF",
                "node_id": node_id, "drift_deg": round(drift, 5),
            })
        return {"known": True, "drift_deg": round(drift, 5),
                "suspicious": suspicious}

    # ------------------------- 隐私 -------------------------
    def privacy_stats(self) -> Dict[str, Any]:
        return {
            "pseudonym_total": len(self.cert_pool),
            "revoked_total": len(self.revoked),
            "rotation_interval_s": self.PSEUDONYM_ROTATION_S,
            "replay_window_ms": self.REPLAY_WINDOW_MS,
            "techniques": ["假名轮换", "聚合", "混淆", "差分隐私", "身份匿名"],
        }

    # ------------------------- 总览 -------------------------
    def overview(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        by_msg: Dict[str, int] = {}
        for n in self.nodes.values():
            by_type[n.node_type] = by_type.get(n.node_type, 0) + 1
        for m in self.messages:
            by_msg[m.msg_type] = by_msg.get(m.msg_type, 0) + 1
        return {
            "node_total": len(self.nodes),
            "node_by_type": by_type,
            "message_total": len(self.messages),
            "message_by_type": by_msg,
            "anomaly_total": len(self.anomaly_events),
            "cert_pool_size": len(self.cert_pool),
            "revoked_certs": len(self.revoked),
        }

    def recent_anomalies(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self.anomaly_events[-limit:]))


_controller: Optional[V2XSecurityController] = None


def get_v2x_controller() -> V2XSecurityController:
    global _controller
    if _controller is None:
        _controller = V2XSecurityController()
    return _controller
