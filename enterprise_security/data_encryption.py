# -*- coding: utf-8 -*-
"""data_encryption.py — 敏感数据 AES-256 加密存储。

- 算法: AES-256-GCM（认证加密，保密性 + 完整性）
- 密钥: 从环境变量 ENTERPRISE_SECRET_KEY 读取（必须 >=32 字节）；
        未设置时自动派生一个进程内随机演示密钥（启动时打印告警）。
- 仅在需要明文时才解密；落库的是 base64(iv + ciphertext + tag)。
"""
from __future__ import annotations

import base64
import json
import os
import warnings
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_KEY_ENV = "ENTERPRISE_SECRET_KEY"
_SALT = b"enterprise-security::aes256::v1"


class DataEncryption:
    """AES-256-GCM 加解密器。"""

    def __init__(self, key_material: Optional[str] = None) -> None:
        raw = key_material or os.environ.get(_KEY_ENV)
        if not raw:
            # 演示回退：进程内随机密钥（不跨重启持久化明文密钥）
            raw = base64.urlsafe_b64encode(os.urandom(48)).decode()
            warnings.warn(
                f"[data_encryption] 未设置环境变量 {_KEY_ENV}，"
                "使用进程内随机演示密钥（重启后旧密文无法解密）",
                stacklevel=2,
            )
        # 派生出 32 字节（256 位）密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=_SALT, iterations=200_000,
        )
        self._key = kdf.derive(raw.encode("utf-8"))
        self._aes = AESGCM(self._key)
        # 加密后的凭据库存（内存字典）
        self._vault: Dict[str, str] = {}

    # ------------------------------------------------------------------ #
    @property
    def algorithm(self) -> str:
        return "AES-256-GCM"

    def encrypt(self, plaintext: str) -> str:
        """加密任意字符串，返回 base64(iv | ct | tag)。"""
        if plaintext is None:
            raise ValueError("待加密内容不能为空")
        iv = os.urandom(12)
        ct = self._aes.encrypt(iv, plaintext.encode("utf-8"), None)
        return base64.b64encode(iv + ct).decode("ascii")

    def decrypt(self, token: str) -> str:
        """解密 base64 token。"""
        data = base64.b64decode(token.encode("ascii"))
        iv, ct = data[:12], data[12:]
        return self._aes.decrypt(iv, ct, None).decode("utf-8")

    # ------------------------------------------------------------------ #
    # 凭据库（内存）
    # ------------------------------------------------------------------ #
    def store_secret(self, name: str, plaintext: str,
                     meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        enc = self.encrypt(plaintext)
        self._vault[name] = enc
        return {
            "name": name,
            "ciphertext": enc,
            "algorithm": self.algorithm,
            "key_source": "env:" + _KEY_ENV,
            "meta": meta or {},
        }

    def list_secrets(self) -> Dict[str, Dict[str, Any]]:
        """列表只返回元信息，绝不返回明文/密文。"""
        return {n: {"name": n, "has_value": True,
                    "algorithm": self.algorithm} for n in self._vault}

    def reveal_secret(self, name: str) -> str:
        """仅授权调用方在需要明文时调用。"""
        if name not in self._vault:
            raise KeyError(f"凭据不存在: {name}")
        return self.decrypt(self._vault[name])

    def delete_secret(self, name: str) -> bool:
        return self._vault.pop(name, None) is not None

    # ------------------------------------------------------------------ #
    def self_test(self) -> Dict[str, Any]:
        """加解密自检。"""
        sample = "sk-demo-1234567890-sensitive"
        token = self.encrypt(sample)
        back = self.decrypt(token)
        ok = back == sample and token != sample
        return {
            "algorithm": self.algorithm,
            "key_bits": 256,
            "key_from_env": bool(os.environ.get(_KEY_ENV)),
            "roundtrip_ok": ok,
            "sample_ciphertext_prefix": token[:24] + "...",
        }

    def mask(self, plaintext: str) -> str:
        """脱敏展示，例如 sk-***1234。"""
        if len(plaintext) <= 4:
            return "***"
        return plaintext[:3] + "***" + plaintext[-4:]
