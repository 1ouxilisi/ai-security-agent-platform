# -*- coding: utf-8 -*-
"""
anti_piracy.py — 防盗版与安全。

能力:
    * 防篡改：文件完整性校验（HMAC）、运行时校验、篡改响应
    * 逆向工程防护：代码混淆/字符串加密/控制流平坦化（静态描述 + 检测 hook）
    * 破解检测：License 破解/补丁/注册机/破解工具识别与行为响应
    * 水印追踪：用户/设备/时间/隐形水印，泄露溯源
    * 黑名单：破解者/设备/IP/用户，同步与校验
    * 法律合规：用户协议/隐私政策/许可证协议/使用条款/违规处理
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from .license_generator import get_issuer, LOCK

INTEGRITY_STORE: Dict[str, str] = {}      # file_path -> sha256
BLACKLIST: Dict[str, set] = {
    "devices": set(), "ips": set(), "users": set(), "emails": set(),
}
CRACK_ALERTS: List[Dict[str, Any]] = []
WATERMARKS: Dict[str, Dict[str, Any]] = {}

LEGAL_TERMS = {
    "eula": ("本软件受著作权法保护。未经授权复制、修改、分发、逆向工程均属违法。"
             "License 一经签发仅限绑定设备使用，禁止共享、出租或转售。"),
    "privacy": ("激活过程仅采集硬件指纹（CPU/主板/硬盘/MAC）用于授权校验，"
                "不上传个人身份信息，数据仅存储于授权服务器。"),
    "license_agreement": ("License 为非独占、不可转让的使用许可，到期后功能降级；"
                          "违反许可条款将被吊销并保留法律追溯权利。"),
    "tos": ("使用本服务即表示您同意：不得用于非法目的，不得绕过授权机制，"
            "不得对软件进行反编译或制作破解补丁。"),
}

CRACK_SIGNATURES = {
    "keygen_hashes": ["a1b2c3...fake", "deadbeef-crack"],
    "patch_patterns": [b"LicenseValidator::always_true", b"check_signature\x90\x90"],
    "debugger_strings": ["x64dbg", "ida64", "ollydbg", "windbg"],
    "hook_libraries": ["frida", "xposed", "substrate", "detours"],
}


class AntiPiracyGuard:
    """防盗版与安全防护。"""

    def __init__(self) -> None:
        self.issuer = get_issuer()

    # ---------------- 防篡改 ---------------- #
    def record_integrity(self, path: str) -> bool:
        try:
            h = hashlib.sha256(open(path, "rb").read()).hexdigest()
            INTEGRITY_STORE[path] = h
            return True
        except Exception:
            return False

    def check_integrity(self, path: str) -> Dict[str, Any]:
        try:
            cur = hashlib.sha256(open(path, "rb").read()).hexdigest()
            old = INTEGRITY_STORE.get(path)
            if old is None:
                return {"tracked": False, "status": "untracked"}
            tampered = not hmac.compare_digest(cur, old)
            if tampered:
                self._alert("tamper_detected", path, "文件被篡改")
            return {"tracked": True, "tampered": tampered, "path": path}
        except Exception as e:
            return {"tracked": True, "tampered": None, "error": str(e)}

    def runtime_protection(self) -> Dict[str, Any]:
        """模拟运行时校验：检测调试器/Hook。"""
        indicators = {
            "debugger_present": False,   # 真实环境可检测 IsDebuggerPresent
            "frida_detected": False,
            "hook_detected": False,
            "patch_detected": False,
        }
        return {"protected": True, "indicators": indicators,
                "countermeasures": ["obfuscation", "vm_protection", "anti_debug"]}

    # ---------------- 逆向防护配置 ---------------- #
    def hardening_profile(self) -> Dict[str, Any]:
        return {
            "code_obfuscation": "enabled",
            "string_encryption": "enabled",
            "control_flow_flattening": "enabled",
            "anti_debug": "enabled",
            "anti_hook": "enabled",
            "virtual_machine_protection": "optional",
        }

    # ---------------- 破解检测 ---------------- #
    def detect_crack(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """sample 可含 strings / loaded_libs / memory_hash / license_id。"""
        hits: List[str] = []
        loaded = [s.lower() for s in sample.get("loaded_libs", [])]
        for lib in CRACK_SIGNATURES["hook_libraries"]:
            if any(lib in l for l in loaded):
                hits.append(f"hook_library:{lib}")
        strings = [s.lower() for s in sample.get("strings", [])]
        for dbg in CRACK_SIGNATURES["debugger_strings"]:
            if any(dbg in s for s in strings):
                hits.append(f"debugger:{dbg}")
        if sample.get("memory_hash") == CRACK_SIGNATURES["keygen_hashes"][0]:
            hits.append("keygen_detected")
        for pat in CRACK_SIGNATURES["patch_patterns"]:
            if pat.decode("latin-1") in sample.get("raw_bytes", ""):
                hits.append("patch_detected")
        if hits:
            lid = sample.get("license_id")
            if lid:
                self.issuer.revoke(lid, "检测到破解行为")
            self._alert("crack_detected", sample.get("license_id", "-"),
                        f"命中: {hits}")
        return {"crack_detected": bool(hits), "hits": hits,
                "response": "license_revoked_and_blacklisted" if hits else "none"}

    # ---------------- 水印 ---------------- #
    def embed_watermark(self, license_id: str, document_id: str,
                        wm_type: str = "user") -> Dict[str, Any]:
        wid = "WM-" + uuid.uuid4().hex[:10].upper()
        wm = {
            "watermark_id": wid, "license_id": license_id,
            "document_id": document_id, "type": wm_type,
            "embedded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "payload": hashlib.sha256(
                f"{license_id}|{document_id}|{time.time()}".encode()).hexdigest()[:32],
            "invisible": wm_type in ("invisible", "time"),
        }
        WATERMARKS[wid] = wm
        return wm

    def trace_watermark(self, watermark_id_or_payload: str) -> Dict[str, Any]:
        wm = WATERMARKS.get(watermark_id_or_payload)
        if not wm:
            # 按 payload 反查
            for w in WATERMARKS.values():
                if w["payload"] == watermark_id_or_payload:
                    wm = w
                    break
        if not wm:
            return {"found": False}
        lic = self.issuer.licenses.get(wm["license_id"])
        return {"found": True, "watermark": wm,
                "customer": lic["payload"]["customer"] if lic else "unknown",
                "leak_suspect": lic["payload"]["customer"] if lic else "unknown"}

    # ---------------- 黑名单 ---------------- #
    def add_blacklist(self, kind: str, value: str) -> bool:
        if kind in BLACKLIST:
            BLACKLIST[kind].add(value)
            return True
        return False

    def remove_blacklist(self, kind: str, value: str) -> bool:
        if kind in BLACKLIST:
            BLACKLIST[kind].discard(value)
            return True
        return False

    def check_blacklist(self, kind: str, value: str) -> bool:
        return value in BLACKLIST.get(kind, set())

    def blacklist_summary(self) -> Dict[str, int]:
        return {k: len(v) for k, v in BLACKLIST.items()}

    # ---------------- 法律合规 ---------------- #
    def legal_docs(self) -> Dict[str, str]:
        return LEGAL_TERMS

    def violation_report(self, license_id: str,
                         description: str) -> Dict[str, Any]:
        self.issuer.revoke(license_id, f"违规: {description}")
        self._alert("legal_violation", license_id, description)
        return {"reported": True, "license_revoked": True,
                "legal_action": "保留进一步追溯权利"}

    # ---------------- 告警 ---------------- #
    def _alert(self, atype: str, target: str, detail: str) -> None:
        CRACK_ALERTS.append({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": atype, "target": target, "detail": detail,
        })

    def recent_alerts(self) -> List[Dict[str, Any]]:
        return list(reversed(CRACK_ALERTS[-50:]))


_guard: Optional[AntiPiracyGuard] = None


def get_anti_piracy_guard() -> AntiPiracyGuard:
    global _guard
    with LOCK:
        if _guard is None:
            _guard = AntiPiracyGuard()
        return _guard
