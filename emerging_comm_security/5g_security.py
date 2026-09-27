#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
5G 核心网安全模块（emerging_comm_security / 5g_security.py）。

真实功能：
  * 注册与管理 5G NF 节点：AMF / SMF / UPF / AUSF / UDM / PCF / NRF / NSSF / NEF
  * NF 服务化接口（SBI）注册 / 发现 / 订阅 / 通知 / 授权
  * 5G-AKA / EAP-AKA' 认证流程（SUPI -> SUCI -> 归属网络认证 -> 服务网络认证）
  * 匿名化与匿名索引（SUPI 临时身份 5G-GUTI / 5G-S-TMSI）
  * 空口 / NAS / RRC / 用户面 / 控制面安全（完整性 / 加密 / 算法协商 / 密钥管理）
  * 网络切片：隔离 / 授权 / 认证 / 策略 / 监控 / 跨切片攻击检测
  * MEC 边缘计算安全：边缘身份 / 策略 / 监控 / 隔离

所有数据均为进程内字典模拟。
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
class NFNode:
    """5G 网络功能（NF）节点。"""
    nf_type: str            # AMF / SMF / UPF / AUSF / UDM / PCF / NRF / NSSF / NEF
    nf_id: str = ""
    name: str = ""
    address: str = ""
    port: int = 8000
    status: str = "REGISTERED"   # REGISTERED / UNREGISTERED / SUSPENDED
    services: List[str] = field(default_factory=list)
    slices: List[str] = field(default_factory=list)   # S-NSSAI
    vendor: str = ""
    version: str = ""
    registered_at: str = ""
    last_heartbeat: str = ""

    def __post_init__(self) -> None:
        if not self.nf_id:
            self.nf_id = f"{self.nf_type}-{uuid.uuid4().hex[:8]}"
        if not self.name:
            self.name = f"{self.nf_type}-node-{self.nf_id[-4:]}"
        if not self.registered_at:
            self.registered_at = datetime.now().isoformat()


@dataclass
class Subscriber:
    """5G 签约用户。"""
    supi: str                       # 永久签约标识 (IMSI 形式)
    suci: str = ""                  # 隐藏签约标识
    guti: str = ""                  # 全局唯一临时标识
    serving_nf: str = ""            # 当前服务 AMF
    slice_supported: List[str] = field(default_factory=list)
    k: str = ""                     # 签约密钥 (模拟)
    opc: str = ""                   # 运营商派生密钥 (模拟)
    auth_count: int = 0
    last_auth_at: str = ""
    state: str = "DEREGISTERED"     # DEREGISTERED / REGISTERED / AUTHENTICATED


@dataclass
class Slice:
    """网络切片。"""
    sst: int                        # 切片/服务类型
    sd: str = "000000"              # 切片区分符
    name: str = ""
    qos_profile: str = "STANDARD"
    isolation_level: str = "HIGH"   # NONE / LOW / MEDIUM / HIGH
    authorized_subscribers: int = 0
    upf_pool: List[str] = field(default_factory=list)
    monitoring: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityAssociation:
    """UE 与网络之间的安全联盟。"""
    supi: str
    amf_id: str
    knas_int: str = ""
    knas_enc: str = ""
    kgnb: str = ""
    nas_alg_int: str = "128-NIA2"    # EIA2/SM4-NIA
    nas_alg_enc: str = "128-NEA2"
    rrc_alg_int: str = "128-NIA2"
    rrc_alg_enc: str = "128-NEA2"
    up_alg_int: str = "128-NIA0"     # 用户面默认可不做完整性
    up_alg_enc: str = "128-NEA1"
    ul_count: int = 0
    dl_count: int = 0
    established_at: str = ""


# ---------------------------------------------------------------------------
# 5G 安全核心控制器
# ---------------------------------------------------------------------------

class SecurityController:
    """5G 安全核心控制器。"""

    VALID_NF_TYPES = ("AMF", "SMF", "UPF", "AUSF", "UDM", "PCF", "NRF", "NSSF", "NEF")
    SUPPORTED_INTEGRITY_ALGS = ("128-NIA0", "128-NIA1", "128-NIA2", "128-NIA3")
    SUPPORTED_CIPHER_ALGS = ("128-NEA0", "128-NEA1", "128-NEA2", "128-NEA3")

    def __init__(self) -> None:
        self.nfs: Dict[str, NFNode] = {}
        self.subscribers: Dict[str, Subscriber] = {}
        self.slices: Dict[str, Slice] = {}
        self.security_associations: Dict[str, SecurityAssociation] = {}
        self.auth_events: List[Dict[str, Any]] = []
        self.nf_subscriptions: Dict[str, List[Dict[str, str]]] = {}
        self.slice_alerts: List[Dict[str, Any]] = []
        self.mec_apps: Dict[str, Dict[str, Any]] = {}
        self._seed_default_infra()

    # ------------------------- 初始化种子数据 -------------------------
    def _seed_default_infra(self) -> None:
        for nf_type in ("NRF", "UDM", "AUSF", "AMF", "SMF", "UPF", "PCF", "NSSF", "NEF"):
            node = NFNode(
                nf_type=nf_type,
                address=f"10.0.{hash(nf_type) % 200 + 1}.{hash(nf_type[::-1]) % 200 + 1}",
                services=[f"nsd:{nf_type.lower()}-management", f"nsd:{nf_type.lower()}-callback"],
                vendor="DemoCo",
                version="17.8.0",
            )
            self.nfs[node.nf_id] = node
        # 默认切片
        self.slices["5G:1:000001"] = Slice(
            sst=1, sd="000001", name="eMBB-Standard", qos_profile="STANDARD",
            isolation_level="HIGH",
            upf_pool=[n.nf_id for n in self.nfs.values() if n.nf_type == "UPF"],
        )
        self.slices["5G:2:000002"] = Slice(
            sst=2, sd="000002", name="URLLC-V2X", qos_profile="URLLC",
            isolation_level="HIGH",
            upf_pool=[n.nf_id for n in self.nfs.values() if n.nf_type == "UPF"],
        )
        self.slices["5G:3:000003"] = Slice(
            sst=3, sd="000003", name="mMTC-IoT", qos_profile="LOW",
            isolation_level="MEDIUM",
            upf_pool=[n.nf_id for n in self.nfs.values() if n.nf_type == "UPF"],
        )

    # ------------------------- NF 管理 -------------------------
    def register_nf(self, nf_type: str, name: str = "", address: str = "",
                    port: int = 8000, slices: Optional[List[str]] = None) -> NFNode:
        if nf_type not in self.VALID_NF_TYPES:
            raise ValueError(f"不支持的 NF 类型: {nf_type}")
        node = NFNode(
            nf_type=nf_type, name=name, address=address, port=port,
            slices=slices or [], status="REGISTERED",
        )
        self.nfs[node.nf_id] = node
        return node

    def deregister_nf(self, nf_id: str) -> bool:
        node = self.nfs.get(nf_id)
        if not node:
            return False
        node.status = "UNREGISTERED"
        return True

    def list_nfs(self, nf_type: Optional[str] = None) -> List[Dict[str, Any]]:
        out = []
        for n in self.nfs.values():
            if nf_type and n.nf_type != nf_type:
                continue
            d = asdict(n)
            d["last_heartbeat"] = n.last_heartbeat or datetime.now().isoformat()
            out.append(d)
        return out

    def nf_discovery(self, service_name: str, requester: str) -> List[Dict[str, Any]]:
        """NRF 服务发现：按服务名查找可用 NF。"""
        results = []
        for n in self.nfs.values():
            if n.status != "REGISTERED":
                continue
            if any(service_name in s for s in n.services):
                results.append({"nf_id": n.nf_id, "nf_type": n.nf_type,
                                "address": n.address, "port": n.port,
                                "distance_score": round(secrets.randbelow(100) / 100, 3)})
        # 记录一次发现审计
        self.auth_events.append({
            "ts": datetime.now().isoformat(), "kind": "NF_DISCOVERY",
            "requester": requester, "service": service_name, "hits": len(results),
        })
        return results

    def nf_subscribe(self, subscriber_nf: str, event: str, target_nf: str) -> Dict[str, Any]:
        key = subscriber_nf
        self.nf_subscriptions.setdefault(key, []).append(
            {"event": event, "target": target_nf, "subscribed_at": datetime.now().isoformat()}
        )
        return {"subscribed": True, "subscriber": subscriber_nf,
                "event": event, "target": target_nf}

    def nf_authorize(self, requester: str, target_service: str) -> Dict[str, Any]:
        """NF 间授权（基于简单白名单模拟 OAuth2 客户端凭证）。"""
        allowed = {
            "AMF": ["nausf-auth", "nudm-uecm", "n1-n2-messages", "nsmf-pdusession"],
            "SMF": ["nausf-auth", "nudm-sdms", "nupf-pdusession", "npcf-am-policy"],
            "AUSF": ["nudm-authentication"],
            "UDM": ["nausf-auth"],
            "NRF": ["nnrf-nfm", "nnrf-disc"],
        }
        req_node = next((n for n in self.nfs.values() if n.nf_id == requester), None)
        if not req_node:
            return {"authorized": False, "reason": "unknown requester NF"}
        ok = target_service in allowed.get(req_node.nf_type, [])
        return {"authorized": ok, "requester": req_node.nf_type,
                "service": target_service,
                "policy": "default allow-list" if ok else "deny"}

    # ------------------------- 用户 / 签约 -------------------------
    def provision_subscriber(self, supi: str, slices: Optional[List[str]] = None) -> Subscriber:
        if not supi.startswith(("imsi-", "msisdn-")):
            supi = f"imsi-{supi}"
        if supi in self.subscribers:
            return self.subscribers[supi]
        k = secrets.token_hex(16)
        opc = secrets.token_hex(16)
        sub = Subscriber(supi=supi, k=k, opc=opc,
                         slice_supported=slices or ["5G:1:000001"])
        # 计算 SUCI（基于公钥加密模拟，此处用 HMAC 表示）
        sub.suci = "suci-0-" + self._h(supi + "::" + k)[:10] + "-0000-0-"
        self.subscribers[supi] = sub
        return sub

    @staticmethod
    def _h(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    # ------------------------- 5G-AKA 认证流程 -------------------------
    def run_5g_aka(self, supi: str, serving_network_name: str = "5G:mcc001.mnc001") -> Dict[str, Any]:
        """
        模拟 5G-AKA 流程：
          1. UE 发送 SUCI 到 AMF -> AUSF -> UDM
          2. UDM 生成 RAND / AUTN / XRES* / Kausf
          3. AUSF 转发给 AMF -> UE 计算 RES*
          4. AUSF 验证 -> 派生 Kseaf -> AMF 派生 KAMF -> 建立 NAS 安全
        """
        sub = self.subscribers.get(supi)
        if not sub:
            sub = self.provision_subscriber(supi)

        rand = secrets.token_hex(16)
        autn = secrets.token_hex(16)
        # 派生 XRES* / Kausf / Kseaf / KAMF（仅做演示）
        xstar = hmac.new(sub.k.encode(), (sub.supi + rand).encode(), hashlib.sha256).hexdigest()
        kausf = hmac.new(sub.opc.encode(), (rand + "AUSF").encode(), hashlib.sha256).hexdigest()
        kseaf = hmac.new(kausf.encode(), serving_network_name.encode(), hashlib.sha256).hexdigest()
        kamf = hmac.new(kseaf.encode(), (sub.supi + "AMF").encode(), hashlib.sha256).hexdigest()

        # UE 侧计算 RES*（在仿真里我们直接接受）
        res_star = xstar
        verified = hmac.compare_digest(res_star, xstar)

        # 协商算法：UE 与网络取交集，这里默认最强
        alg_int = "128-NIA2"
        alg_enc = "128-NEA2"

        assoc = SecurityAssociation(
            supi=supi,
            amf_id=next(n.nf_id for n in self.nfs.values() if n.nf_type == "AMF"),
            knas_int=kamf[:32],
            knas_enc=kamf[32:64] + kamf[:32],
            kgnb="",  # 下方由 KAMF 派生后回填
            nas_alg_int=alg_int,
            nas_alg_enc=alg_enc,
            established_at=datetime.now().isoformat(),
        )
        assoc.kgnb = hmac.new(kamf.encode(), "K_gNB".encode(), hashlib.sha256).hexdigest()
        self.security_associations[supi] = assoc

        sub.auth_count += 1
        sub.last_auth_at = datetime.now().isoformat()
        sub.state = "AUTHENTICATED"
        sub.guti = f"5G-GUTI-{secrets.token_hex(4).upper()}"
        sub.serving_nf = assoc.amf_id

        event = {
            "ts": datetime.now().isoformat(),
            "kind": "5G-AKA",
            "supi": sub.supi, "suci_used": bool(sub.suci),
            "serving_network": serving_network_name,
            "rand": rand, "autn": autn,
            "xres*": xstar, "res*": res_star,
            "verified": verified,
            "kausf_prefix": kausf[:16],
            "kseaf_prefix": kseaf[:16],
            "kamf_prefix": kamf[:16],
            "nas_alg_int": alg_int, "nas_alg_enc": alg_enc,
            "anonymized_identity": sub.guti,
        }
        self.auth_events.append(event)
        return event

    # ------------------------- 算法 / 密钥协商 -------------------------
    def negotiate_security_algorithms(self, ue_pref_int: List[str],
                                     ue_pref_enc: List[str]) -> Dict[str, str]:
        """按网络偏好强度取交集（NIA3>NIA2>NIA1>NIA0）。"""
        net_int = list(reversed(self.SUPPORTED_INTEGRITY_ALGS))
        net_enc = list(reversed(self.SUPPORTED_CIPHER_ALGS))
        chosen_int = next((a for a in net_int if a in ue_pref_int), "128-NIA0")
        chosen_enc = next((a for a in net_enc if a in ue_pref_enc), "128-NEA0")
        return {"nas_int": chosen_int, "nas_enc": chosen_enc,
                "rrc_int": chosen_int, "rrc_enc": chosen_enc,
                "up_int": "128-NIA0", "up_enc": chosen_enc}

    # ------------------------- 切片 -------------------------
    def list_slices(self) -> List[Dict[str, Any]]:
        return [asdict(s) for s in self.slices.values()]

    def authorize_slice(self, supi: str, s_nssai: str) -> Dict[str, Any]:
        sub = self.subscribers.get(supi)
        if not sub:
            return {"authorized": False, "reason": "unknown subscriber"}
        if s_nssai not in sub.slice_supported:
            return {"authorized": False, "reason": "subscriber not subscribed to slice",
                    "requested": s_nssai, "allowed": sub.slice_supported}
        sl = self.slices.get(s_nssai)
        if not sl:
            return {"authorized": False, "reason": "slice not defined"}
        return {"authorized": True, "s_nssai": s_nssai,
                "isolation": sl.isolation_level, "qos": sl.qos_profile}

    def detect_cross_slice_attack(self, suspect_flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        跨切片攻击检测：检查 UPF 上是否出现从 A 切片流向 B 切片的异常流。
        suspect_flow = {src_slice, dst_slice, volume_mb, duration_s}
        """
        src = suspect_flow.get("src_slice")
        dst = suspect_flow.get("dst_slice")
        verdict = {"suspicious": False, "reason": "normal inter-slice routing"}
        if src and dst and src != dst:
            src_sl = self.slices.get(src)
            dst_sl = self.slices.get(dst)
            if src_sl and dst_sl:
                if src_sl.isolation_level == "HIGH" and dst_sl.isolation_level == "HIGH":
                    verdict = {"suspicious": True, "reason": "HIGH-isolation slice to HIGH-isolation slice",
                               "src_slice": src, "dst_slice": dst,
                               "volume_mb": suspect_flow.get("volume_mb")}
                    self.slice_alerts.append({**verdict, "ts": datetime.now().isoformat()})
        return verdict

    # ------------------------- MEC / 边缘 -------------------------
    def register_mec_app(self, app_id: str, edge_site: str, owner: str,
                         required_slice: str) -> Dict[str, Any]:
        app = {
            "app_id": app_id, "edge_site": edge_site, "owner": owner,
            "required_slice": required_slice, "identity": f"mec-{app_id}",
            "policy": "ALLOW:READ; DENY:INTERNET",
            "isolated_from": "all-other-apps",
            "status": "RUNNING",
            "registered_at": datetime.now().isoformat(),
        }
        self.mec_apps[app_id] = app
        return app

    def list_mec_apps(self) -> List[Dict[str, Any]]:
        return list(self.mec_apps.values())

    # ------------------------- 总览 -------------------------
    def overview(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for n in self.nfs.values():
            by_type[n.nf_type] = by_type.get(n.nf_type, 0) + 1
        return {
            "nf_total": len(self.nfs),
            "nf_by_type": by_type,
            "subscriber_total": len(self.subscribers),
            "authenticated_total": sum(1 for s in self.subscribers.values()
                                       if s.state == "AUTHENTICATED"),
            "slice_total": len(self.slices),
            "active_security_associations": len(self.security_associations),
            "auth_events_total": len(self.auth_events),
            "slice_alerts_total": len(self.slice_alerts),
            "mec_apps_total": len(self.mec_apps),
            "supported_integrity_algs": self.SUPPORTED_INTEGRITY_ALGS,
            "supported_cipher_algs": self.SUPPORTED_CIPHER_ALGS,
        }

    def recent_auth_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self.auth_events[-limit:]))


# 单例
_controller: Optional[SecurityController] = None


def get_5g_controller() -> SecurityController:
    global _controller
    if _controller is None:
        _controller = SecurityController()
    return _controller
