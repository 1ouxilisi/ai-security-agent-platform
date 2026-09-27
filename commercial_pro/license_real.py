#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_pro/license_real.py — 真实 License 系统。

特性：
1. 真实机器码生成：CPU ID + 磁盘序列号 + MAC 地址 → SHA-256 硬件指纹
2. 真实签名验证：RSA-PSS（SHA-256），私钥签发、公钥验签
3. 功能分级：免费(free) / 专业(pro) / 企业(enterprise)
4. 过期提醒 / 在线激活
5. 全部内存字典模拟存储（可离线运行，cryptography 缺失时降级为 HMAC 演示）
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import uuid
import time
import threading
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# 密码学后端：优先 cryptography（RSA-PSS），缺失时降级 HMAC-SHA256 演示
# --------------------------------------------------------------------------- #
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.exceptions import InvalidSignature

    _CRYPTO_OK = True
except Exception:  # pragma: no cover
    hashes = None  # type: ignore
    rsa = None  # type: ignore
    padding = None  # type: ignore
    serialization = None  # type: ignore
    InvalidSignature = Exception  # type: ignore
    _CRYPTO_OK = False


# 功能分级能力矩阵
TIER_CAPABILITIES: Dict[str, Dict[str, Any]] = {
    "free": {
        "label": "免费版",
        "max_scans_per_month": 5,
        "concurrent_scans": 1,
        "features": ["web_basic", "report_basic", "community_support"],
        "price_cny": 0,
    },
    "pro": {
        "label": "专业版",
        "max_scans_per_month": 500,
        "concurrent_scans": 10,
        "features": ["web_full", "api_security", "report_pro",
                     "mobile_scan", "email_support", "custom_report"],
        "price_cny": 299,
    },
    "enterprise": {
        "label": "企业版",
        "max_scans_per_month": -1,          # -1 = 不限
        "concurrent_scans": 100,
        "features": ["all", "private_deploy", "sso", "dedicated_support",
                     "sla_999", "audit_log", "onsite_training"],
        "price_cny": 19999,
    },
}


def _read_cpu_id() -> str:
    """读取 CPU 标识（跨平台尽力而为）。"""
    try:
        if platform.system() == "Windows":
            import subprocess
            out = subprocess.check_output(
                ["wmic", "cpu", "get", "ProcessorId"],
                stderr=subprocess.DEVNULL, timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).decode("utf-8", "ignore")
            return out.strip().splitlines()[1].strip() if out.count("\n") >= 2 else platform.processor()
        # Linux / macOS
        return open("/proc/cpuinfo", "r", encoding="ignore").read().split("processor")[0][:64] \
            if os.path.exists("/proc/cpuinfo") else platform.processor()
    except Exception:
        return platform.processor() or "cpu-unknown"


def _read_disk_serial() -> str:
    """读取系统盘序列号（尽力而为）。"""
    try:
        if platform.system() == "Windows":
            import subprocess
            out = subprocess.check_output(
                ["wmic", "diskdrive", "get", "SerialNumber"],
                stderr=subprocess.DEVNULL, timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).decode("utf-8", "ignore")
            lines = [l.strip() for l in out.splitlines()[1:] if l.strip()]
            return lines[0] if lines else "disk-unknown"
        return os.environ.get("HOSTNAME", "disk-local")
    except Exception:
        return "disk-unknown"


def _read_mac() -> str:
    """读取 MAC 地址。"""
    try:
        return hex(uuid.getnode())[2:].zfill(12)
    except Exception:
        return "000000000000"


def generate_machine_code() -> Dict[str, str]:
    """生成真实机器码硬件指纹。

    返回 {machine_code, cpu, disk, mac, platform}
    """
    cpu = _read_cpu_id()
    disk = _read_disk_serial()
    mac = _read_mac()
    raw = f"{cpu}|{disk}|{mac}|{platform.node()}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    # 格式化为 XXXX-XXXX-XXXX-XXXX-XXXX
    grouped = "-".join(digest[i:i + 4] for i in range(0, 20, 4))
    return {
        "machine_code": grouped.upper(),
        "machine_hash": digest,
        "cpu": cpu[:40],
        "disk": disk[:40],
        "mac": mac,
        "platform": f"{platform.system()} {platform.release()}",
    }


class _RsaKeyPair:
    """进程内 RSA 密钥对（演示用，真实环境私钥应离线保管）。"""

    def __init__(self) -> None:
        self.available = _CRYPTO_OK
        self.private_pem: str = ""
        self.public_pem: str = ""
        if self.available:
            try:
                self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                self.private_pem = self._key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode()
                self.public_pem = self._key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode()
            except Exception:
                self.available = False


class LicenseManager:
    """License 签发 / 验签 / 激活 / 分级管理。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._keypair = _RsaKeyPair()
        # 已签发 License：key=license_key -> record
        self._licenses: Dict[str, Dict[str, Any]] = {}
        # 已激活：machine_code -> license_key
        self._activations: Dict[str, str] = {}
        # 演示：预置一个企业版 License
        self._seed_demo()

    # ------------------------------------------------------------------ #
    # 签名原语
    # ------------------------------------------------------------------ #
    def _sign(self, payload_b64: str) -> str:
        if self._keypair.available:
            sig = self._keypair._key.sign(
                payload_b64.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return sig.hex()
        # 降级：HMAC-SHA256
        return hmac.new(b"demo-secret-key", payload_b64.encode(),
                        hashlib.sha256).hexdigest()

    def _verify(self, payload_b64: str, signature_hex: str) -> bool:
        if self._keypair.available:
            try:
                pub = serialization.load_pem_public_key(
                    self._keypair.public_pem.encode())
                pub.verify(
                    bytes.fromhex(signature_hex),
                    payload_b64.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return True
            except InvalidSignature:
                return False
            except Exception:
                return False
        expected = hmac.new(b"demo-secret-key", payload_b64.encode(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_hex)

    # ------------------------------------------------------------------ #
    # 内部工具
    # ------------------------------------------------------------------ #
    def _seed_demo(self) -> None:
        demo = self.issue(
            customer="演示企业", tier="enterprise", seats=10,
            duration_days=365, note="预置演示企业版 License",
        )
        # 预置激活当前机器
        mc = generate_machine_code()["machine_code"]
        self.activate(demo["license_key"], mc)

    def _build_payload(self, customer: str, tier: str, seats: int,
                       issued: int, expires: int, machine: str) -> str:
        body = {
            "customer": customer, "tier": tier, "seats": seats,
            "issued": issued, "expires": expires, "machine": machine,
            "issuer": "AI-Hacking-Agent CA",
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    # ------------------------------------------------------------------ #
    # 签发 / 激活 / 校验
    # ------------------------------------------------------------------ #
    def issue(self, customer: str, tier: str = "pro", seats: int = 1,
              duration_days: int = 365, note: str = "") -> Dict[str, Any]:
        """签发一份 License（离线，绑定指定机器码）。"""
        if tier not in TIER_CAPABILITIES:
            raise ValueError(f"未知分级: {tier}")
        with self._lock:
            issued = int(time.time())
            expires = issued + duration_days * 86400
            machine = "UNBOUND"   # 未绑定机器，激活时绑定
            payload = self._build_payload(customer, tier, seats, issued, expires, machine)
            import base64
            payload_b64 = base64.b64encode(payload.encode()).decode()
            signature = self._sign(payload_b64)
            license_key = "L-" + hashlib.sha1(
                (payload + signature).encode()).hexdigest()[:24].upper()
            rec = {
                "license_key": license_key,
                "customer": customer,
                "tier": tier,
                "tier_label": TIER_CAPABILITIES[tier]["label"],
                "seats": seats,
                "issued": issued,
                "expires": expires,
                "note": note,
                "payload_b64": payload_b64,
                "signature": signature,
                "activated_machine": None,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._licenses[license_key] = rec
            return rec

    def activate(self, license_key: str, machine_code: str) -> Dict[str, Any]:
        """在线激活：把 License 绑定到机器码。"""
        with self._lock:
            rec = self._licenses.get(license_key)
            if not rec:
                return {"success": False, "reason": "License 不存在"}
            if rec["activated_machine"] and rec["activated_machine"] != machine_code:
                return {"success": False, "reason": "License 已绑定其他机器（防盗用）"}
            rec["activated_machine"] = machine_code
            rec["activated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self._activations[machine_code] = license_key
            return {"success": True, "activated_machine": machine_code,
                    "tier": rec["tier"], "expires": rec["expires"]}

    def verify(self, license_key: str, machine_code: str) -> Dict[str, Any]:
        """校验 License：签名有效 + 机器匹配 + 未过期。"""
        with self._lock:
            rec = self._licenses.get(license_key)
            if not rec:
                return {"valid": False, "reason": "License 不存在"}
            # 1) 验签
            if not self._verify(rec["payload_b64"], rec["signature"]):
                return {"valid": False, "reason": "签名无效（被篡改）"}
            # 2) 机器绑定
            if rec["activated_machine"] != machine_code:
                return {"valid": False, "reason": "机器码不匹配"}
            # 3) 过期
            now = int(time.time())
            if rec["expires"] < now:
                return {"valid": False, "reason": "License 已过期",
                        "expired_days": (now - rec["expires"]) // 86400}
            days_left = (rec["expires"] - now) // 86400
            tier = rec["tier"]
            return {
                "valid": True,
                "customer": rec["customer"],
                "tier": tier,
                "tier_label": rec["tier_label"],
                "capabilities": TIER_CAPABILITIES[tier],
                "seats": rec["seats"],
                "days_left": days_left,
                "expires_at": time.strftime("%Y-%m-%d", time.localtime(rec["expires"])),
                "expiring_soon": days_left <= 30,
                "crypto_backend": "RSA-PSS" if self._keypair.available else "HMAC-SHA256(降级)",
            }

    def remind(self, machine_code: str) -> Dict[str, Any]:
        """过期提醒：返回当前机器 License 的剩余天数与建议。"""
        key = self._activations.get(machine_code)
        if not key:
            return {"has_license": False, "message": "当前机器未激活任何 License"}
        v = self.verify(key, machine_code)
        if not v.get("valid"):
            return {"has_license": True, "expired": True,
                    "message": v.get("reason", "License 失效"), "action": "请联系续费"}
        days = v["days_left"]
        if days <= 7:
            level, msg = "critical", f"License 将在 {days} 天后过期，请立即续费"
        elif days <= 30:
            level, msg = "warning", f"License 将在 {days} 天后过期"
        else:
            level, msg = "ok", f"License 剩余 {days} 天，状态正常"
        return {"has_license": True, "expired": False, "level": level,
                "days_left": days, "message": msg, "tier": v["tier"]}

    # ------------------------------------------------------------------ #
    # 管理查询
    # ------------------------------------------------------------------ #
    def list_licenses(self) -> List[Dict[str, Any]]:
        with self._lock:
            out = []
            for rec in self._licenses.values():
                out.append({
                    "license_key": rec["license_key"],
                    "customer": rec["customer"],
                    "tier": rec["tier"],
                    "tier_label": rec["tier_label"],
                    "seats": rec["seats"],
                    "activated_machine": rec["activated_machine"],
                    "created_at": rec["created_at"],
                    "expires": rec["expires"],
                    "expires_at": time.strftime("%Y-%m-%d", time.localtime(rec["expires"])),
                })
            return out

    def tiers(self) -> Dict[str, Any]:
        return TIER_CAPABILITIES

    def key_info(self) -> Dict[str, Any]:
        return {
            "crypto_backend": "RSA-PSS / SHA-256" if self._keypair.available
            else "HMAC-SHA256（cryptography 未安装，演示降级）",
            "rsa_key_size": 2048 if self._keypair.available else 0,
            "public_key_sha256": hashlib.sha256(
                self._keypair.public_pem.encode()).hexdigest()[:32]
            if self._keypair.public_pem else "n/a",
        }


_mgr: LicenseManager | None = None


def get_license_manager() -> LicenseManager:
    global _mgr
    if _mgr is None:
        _mgr = LicenseManager()
    return _mgr
