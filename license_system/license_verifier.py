# -*- coding: utf-8 -*-
"""
license_verifier.py — License 验证中间件（v30.0 真实 License 系统）。

职责:
    * 解析 License 字符串（Base64(JSON).Base64(RSA-Signature)）
    * 校验 RSA-PSS 签名是否被篡改
    * 校验机器码是否与当前主机匹配
    * 校验是否过期
    * 输出统一的验证结果 {valid, reason, payload}

不依赖任何数据库，全部内存计算。
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

from .license_generator import (
    LOCK,
    REAL_TIERS,
    RealLicenseIssuer,
    generate_machine_code,
    get_key_manager,
)


class LicenseVerificationError(Exception):
    """License 验证失败的友好异常。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class LicenseVerifier:
    """License 验证器。"""

    def __init__(self) -> None:
        self._km = get_key_manager()
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = 60  # 秒

    # ------------------------------------------------------------------ #
    def verify(
        self,
        license_key: str,
        *,
        expected_machine_code: Optional[str] = None,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """验证一份 License。

        Args:
            license_key: License 字符串（payload_b64.signature_b64）
            expected_machine_code: 期望绑定的机器码；默认取当前主机机器码。
            now: 测试用时间戳；默认 time.time()。

        Returns:
            {
              "valid": bool,
              "code": "ok" | "invalid_format" | "bad_signature" |
                      "machine_mismatch" | "expired" | "unknown_tier",
              "reason": 人类可读错误/成功说明,
              "payload": {...},          # 成功时为 License payload
              "days_remaining": int,     # 剩余天数
            }
        """
        ts = float(now if now is not None else time.time())
        machine = (expected_machine_code or generate_machine_code()).strip().lower()

        # 1) 解析
        try:
            parsed = RealLicenseIssuer.parse(license_key)
        except Exception as exc:
            return self._result(False, "invalid_format",
                                f"License format error: {exc}", None)

        payload: Dict[str, Any] = parsed["payload"]
        # RealLicenseIssuer.parse returns decoded signature bytes; re-encode to
        # base64 to match KeyManager.verify's expected interface.
        import base64 as _b64
        signature_b64 = _b64.urlsafe_b64encode(parsed["signature"]).rstrip(b"=").decode("ascii")

        # 2) schema 校验
        if payload.get("schema") != "aiah/v30":
            return self._result(False, "invalid_format",
                               "License schema 不兼容（应为 aiah/v30）", payload)

        # 3) 签名校验（防篡改）
        canonical = self._canonical(payload)
        try:
            sig_ok = self._km.verify(canonical, signature_b64)
        except Exception as exc:
            return self._result(False, "bad_signature",
                                f"Signature check error: {exc}", payload)
        if not sig_ok:
            return self._result(False, "bad_signature",
                                "License 签名无效或已被篡改", payload)

        # 4) 机器码匹配
        lic_machine = str(payload.get("machine_code", "")).strip().lower()
        if lic_machine and lic_machine != machine:
            return self._result(False, "machine_mismatch",
                                f"机器码不匹配: License 绑定 {lic_machine}，"
                                f"当前主机 {machine}", payload)

        # 5) 过期校验
        expires_at = int(payload.get("expires_at", 0))
        if expires_at and ts > expires_at:
            days_expired = int((ts - expires_at) // 86400)
            return self._result(
                False, "expired",
                f"License 已过期 {days_expired} 天，请续费升级", payload)

        # 6) 等级校验
        tier = payload.get("tier")
        if tier not in REAL_TIERS:
            return self._result(False, "unknown_tier",
                                f"未知 License 等级: {tier}", payload)

        days_remaining = max(0, int((expires_at - ts) // 86400)) if expires_at else -1
        return {
            "valid": True,
            "code": "ok",
            "reason": f"License 校验通过：{payload.get('tier_name', tier)}",
            "payload": payload,
            "days_remaining": days_remaining,
        }

    # ------------------------------------------------------------------ #
    @staticmethod
    def _canonical(payload: Dict[str, Any]) -> bytes:
        import json as _json
        return _json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _result(valid: bool, code: str, reason: str,
                payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "valid": valid,
            "code": code,
            "reason": reason,
            "payload": payload,
            "days_remaining": 0,
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_verifier: Optional[LicenseVerifier] = None
_verifier_lock = threading.RLock()


def get_verifier() -> LicenseVerifier:
    global _verifier
    with _verifier_lock:
        if _verifier is None:
            _verifier = LicenseVerifier()
        return _verifier


def verify_license(license_key: str,
                   expected_machine_code: Optional[str] = None) -> Dict[str, Any]:
    """便捷函数：验证一份 License。"""
    return get_verifier().verify(license_key,
                                 expected_machine_code=expected_machine_code)
