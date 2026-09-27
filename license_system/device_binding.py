# -*- coding: utf-8 -*-
"""
device_binding.py — 激活与设备绑定。

能力:
    * 设备指纹：CPU ID / 主板序列号 / 硬盘序列号 / MAC / OS / 机器名 → SHA-256 综合指纹
    * 激活流程：首次/重新/在线/离线激活、激活向导、状态机
    * 设备绑定：单/多设备、设备数限制、解绑、迁移、黑名单
    * 离线激活：请求码生成 → 离线激活码签发 → 离线验证
    * 在线激活服务器：激活 API、配额、限流、日志、异常检测
    * 激活问题诊断：失败原因归类与修复建议
"""

from __future__ import annotations

import hashlib
import os
import platform
import socket
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

try:
    import psutil  # type: ignore
    _PSUTIL_OK = True
except Exception:
    psutil = None  # type: ignore
    _PSUTIL_OK = False

from .license_generator import get_issuer, LOCK  # noqa: E402


# --------------------------------------------------------------------------- #
# 设备指纹采集
# --------------------------------------------------------------------------- #
class DeviceFingerprint:
    """采集本机硬件标识并生成综合指纹。真实采集失败时回退到模拟值。"""

    @staticmethod
    def cpu_id() -> str:
        try:
            if platform.system() == "Windows":
                import subprocess
                out = subprocess.check_output(
                    ["wmic", "cpu", "get", "ProcessorId"],
                    stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", "ignore")
                lines = [l.strip() for l in out.splitlines() if l.strip() and "ProcessorId" not in l]
                if lines:
                    return lines[0]
        except Exception:
            pass
        try:
            return open("/proc/cpuinfo", "rb").read(64).hex()[:16]
        except Exception:
            return "CPU-" + uuid.getnode().to_bytes(6, "big").hex()[:12]

    @staticmethod
    def motherboard_serial() -> str:
        try:
            if platform.system() == "Windows":
                import subprocess
                out = subprocess.check_output(
                    ["wmic", "baseboard", "get", "SerialNumber"],
                    stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", "ignore")
                lines = [l.strip() for l in out.splitlines()
                         if l.strip() and "SerialNumber" not in l]
                if lines:
                    return lines[0]
        except Exception:
            pass
        return "MB-" + hashlib.md5(uuid.getnode().to_bytes(6, "big")).hexdigest()[:12]

    @staticmethod
    def disk_serial() -> str:
        try:
            if _PSUTIL_OK:
                part = psutil.disk_partitions()[0]
                usage = psutil.disk_usage(part.mountpoint)
                return f"DISK-{part.device}-{usage.total}"
        except Exception:
            pass
        return "DISK-" + uuid.getnode().to_bytes(6, "big").hex()[:12]

    @staticmethod
    def mac_address() -> str:
        mac = uuid.getnode()
        return ":".join(f"{(mac >> i) & 0xff:02x}" for i in range(40, -1, -8))

    @staticmethod
    def os_info() -> str:
        return f"{platform.system()}-{platform.release()}-{platform.machine()}"

    @staticmethod
    def machine_name() -> str:
        return socket.gethostname()

    @classmethod
    def collect(cls) -> Dict[str, str]:
        return {
            "cpu_id": cls.cpu_id(),
            "motherboard_serial": cls.motherboard_serial(),
            "disk_serial": cls.disk_serial(),
            "mac_address": cls.mac_address(),
            "os": cls.os_info(),
            "machine_name": cls.machine_name(),
        }

    @classmethod
    def fingerprint(cls) -> str:
        parts = cls.collect()
        raw = "|".join(f"{k}={v}" for k, v in sorted(parts.items()))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# 激活服务器
# --------------------------------------------------------------------------- #
ACTIVATION_STORE: Dict[str, Dict[str, Any]] = {
    "records": {},        # activation_id -> record
    "by_license": {},     # license_id -> [activation_id]
    "offline_requests": {},  # request_id -> {license_id, fp, expires_at}
    "blacklist_devices": set(),
    "rate_limit": {},     # fp -> [timestamps]
}


class ActivationServer:
    """在线/离线激活、设备绑定与诊断。"""

    def __init__(self) -> None:
        self.issuer = get_issuer()

    # ---------------- 在线激活 ---------------- #
    def activate(self, license_id: str, activation_code: str,
                device_info: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        fp = (device_info or {}).get("fingerprint") or DeviceFingerprint.fingerprint()
        # 限流：同一指纹 60 秒内最多 10 次
        now = time.time()
        lst = ACTIVATION_STORE["rate_limit"].setdefault(fp, [])
        lst[:] = [t for t in lst if now - t < 60]
        if len(lst) >= 10:
            return {"ok": False, "error": "rate_limited",
                    "message": "激活请求过于频繁，请稍后再试"}
        lst.append(now)

        rec = self.issuer.licenses.get(license_id)
        if not rec:
            return {"ok": False, "error": "license_not_found"}
        if rec["activation_code"] != activation_code.strip().upper():
            return {"ok": False, "error": "invalid_code"}
        if license_id in self.issuer.revoked:
            return {"ok": False, "error": "revoked"}
        if fp in ACTIVATION_STORE["blacklist_devices"]:
            return {"ok": False, "error": "device_blacklisted"}

        devices = rec.setdefault("devices", [])
        if fp in devices:
            state = "already_activated"
        else:
            if len(devices) >= rec["payload"]["max_devices"]:
                return {"ok": False, "error": "device_limit_exceeded",
                        "message": f"已达设备数上限 {rec['payload']['max_devices']}"}
            devices.append(fp)
            state = "first_activated"

        act_id = "ACT-" + uuid.uuid4().hex[:12].upper()
        record = {
            "activation_id": act_id, "license_id": license_id,
            "fingerprint": fp, "device_info": device_info or DeviceFingerprint.collect(),
            "state": state, "activated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": (device_info or {}).get("ip", "127.0.0.1"),
        }
        ACTIVATION_STORE["records"][act_id] = record
        ACTIVATION_STORE["by_license"].setdefault(license_id, []).append(act_id)
        return {"ok": True, "activation_id": act_id, "state": state,
                "fingerprint": fp, "license": self.issuer.get(license_id)}

    # ---------------- 离线激活 ---------------- #
    def create_offline_request(self, license_id: str) -> Dict[str, Any]:
        """客户端生成离线激活请求（含设备指纹），由管理员离线签发。"""
        fp = DeviceFingerprint.fingerprint()
        req_id = "OFF-" + uuid.uuid4().hex[:10].upper()
        ACTIVATION_STORE["offline_requests"][req_id] = {
            "license_id": license_id, "fingerprint": fp,
            "created_at": int(time.time()), "expires_in": 7 * 86400,
        }
        token = f"{req_id}.{fp}"
        return {"request_id": req_id, "offline_token": token,
                "fingerprint": fp, "valid_hours": 168}

    def issue_offline_code(self, offline_token: str) -> Dict[str, Any]:
        try:
            req_id, fp = offline_token.split(".", 1)
        except ValueError:
            return {"ok": False, "error": "bad_token"}
        req = ACTIVATION_STORE["offline_requests"].get(req_id)
        if not req:
            return {"ok": False, "error": "request_not_found"}
        if time.time() - req["created_at"] > req["expires_in"]:
            return {"ok": False, "error": "request_expired"}
        # 离线码 = HMAC(license_id + fp)
        from .license_generator import get_key_manager
        import hmac as _hmac
        import hashlib as _hl
        code = _hmac.new(get_key_manager().sign(b"offline").encode()[:32],
                         f"{req['license_id']}|{fp}".encode(),
                         _hl.sha256).hexdigest()[:24].upper()
        return {"ok": True, "offline_code": code, "request_id": req_id,
                "license_id": req["license_id"], "valid_days": 365}

    def verify_offline_code(self, license_id: str, offline_code: str,
                            fingerprint: Optional[str] = None) -> Dict[str, Any]:
        from .license_generator import get_key_manager
        import hmac as _hmac
        import hashlib as _hl
        fp = fingerprint or DeviceFingerprint.fingerprint()
        expect = _hmac.new(get_key_manager().sign(b"offline").encode()[:32],
                          f"{license_id}|{fp}".encode(),
                          _hl.sha256).hexdigest()[:24].upper()
        ok = _hmac.compare_digest(offline_code.strip().upper(), expect)
        return {"valid": ok, "fingerprint": fp}

    # ---------------- 设备管理 ---------------- #
    def list_devices(self, license_id: Optional[str] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for act_id, rec in ACTIVATION_STORE["records"].items():
            if license_id and rec["license_id"] != license_id:
                continue
            out.append({
                "activation_id": act_id,
                "license_id": rec["license_id"],
                "fingerprint": rec["fingerprint"],
                "machine_name": rec["device_info"].get("machine_name", "unknown"),
                "os": rec["device_info"].get("os", "unknown"),
                "activated_at": rec["activated_at"],
                "ip": rec["ip"],
                "blacklisted": rec["fingerprint"] in ACTIVATION_STORE["blacklist_devices"],
            })
        return out

    def unbind_device(self, activation_id: str) -> bool:
        rec = ACTIVATION_STORE["records"].pop(activation_id, None)
        if not rec:
            return False
        lid = rec["license_id"]
        if lid in self.issuer.licenses:
            fp = rec["fingerprint"]
            if fp in self.issuer.licenses[lid]["devices"]:
                self.issuer.licenses[lid]["devices"].remove(fp)
        return True

    def migrate_device(self, old_activation_id: str,
                       new_device_info: Dict[str, str]) -> Dict[str, Any]:
        rec = ACTIVATION_STORE["records"].get(old_activation_id)
        if not rec:
            return {"ok": False, "error": "activation_not_found"}
        new_fp = new_device_info.get("fingerprint") or DeviceFingerprint.fingerprint()
        lid = rec["license_id"]
        lic = self.issuer.licenses.get(lid)
        if not lic:
            return {"ok": False, "error": "license_not_found"}
        if rec["fingerprint"] in lic["devices"]:
            lic["devices"].remove(rec["fingerprint"])
        lic["devices"].append(new_fp)
        rec["fingerprint"] = new_fp
        rec["device_info"] = new_device_info
        rec["migrated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return {"ok": True, "new_fingerprint": new_fp}

    def blacklist_device(self, fingerprint: str) -> bool:
        ACTIVATION_STORE["blacklist_devices"].add(fingerprint)
        return True

    def unblacklist_device(self, fingerprint: str) -> bool:
        ACTIVATION_STORE["blacklist_devices"].discard(fingerprint)
        return fingerprint not in ACTIVATION_STORE["blacklist_devices"]

    # ---------------- 诊断 ---------------- #
    def diagnose(self, license_id: str,
                 device_info: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        findings: List[Dict[str, str]] = []
        lic = self.issuer.licenses.get(license_id)
        if not lic:
            findings.append({"level": "error", "code": "license_not_found",
                             "message": "License 不存在，请检查激活码",
                             "fix": "联系销售重新签发"})
            return {"ok": False, "findings": findings}
        p = lic["payload"]
        now = time.time()
        if p["expires_at"] < now:
            findings.append({"level": "error", "code": "expired",
                             "message": "License 已过期",
                             "fix": "续费或升级后重新激活"})
        elif p["expires_at"] - now < 7 * 86400:
            findings.append({"level": "warn", "code": "expiring_soon",
                             "message": "License 即将在一周内到期",
                             "fix": "建议立即续费"})
        if license_id in self.issuer.revoked:
            findings.append({"level": "error", "code": "revoked",
                             "message": "License 已被吊销",
                             "fix": "联系管理员查询吊销原因"})
        fp = (device_info or {}).get("fingerprint") or DeviceFingerprint.fingerprint()
        if fp in ACTIVATION_STORE["blacklist_devices"]:
            findings.append({"level": "error", "code": "blacklisted",
                             "message": "当前设备已被列入黑名单",
                             "fix": "联系安全团队申诉"})
        if len(lic["devices"]) >= p["max_devices"]:
            findings.append({"level": "warn", "code": "device_full",
                             "message": f"设备绑定已达上限 {p['max_devices']}",
                             "fix": "解绑旧设备或扩容设备数"})
        # 网络诊断（模拟）
        findings.append({"level": "info", "code": "network",
                         "message": "在线激活服务器连通性正常（模拟）",
                         "fix": "如真实环境失败，请检查出站 HTTPS"})
        ok = not any(f["level"] == "error" for f in findings)
        return {"ok": ok, "findings": findings,
                "license": self.issuer.get(license_id)}


_server: Optional[ActivationServer] = None


def get_activation_server() -> ActivationServer:
    global _server
    with LOCK:
        if _server is None:
            _server = ActivationServer()
        return _server
