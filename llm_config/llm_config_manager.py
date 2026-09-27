# -*- coding: utf-8 -*-
"""
llm_config/llm_config_manager.py — LLM Key 配置管理

- 多 Key 配置（每个 provider 一个）
- 默认 provider 选择
- Key 加密存储（优先 cryptography.Fernet，否则本地 XOR+base64 兜底）
- 持久化到 data/llm_config.json
- 导入 / 导出（加密导出）
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

_CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "data")
_CONFIG_PATH = os.path.join(_CONFIG_DIR, "llm_config.json")
_MACHINE_KEY = hashlib.sha256(b"ai-hacking-agent-llm-secret").digest()


# ---------------------------------------------------------------------------
# 加密层
# ---------------------------------------------------------------------------
def _encrypt(plain: str) -> str:
    if not plain:
        return ""
    try:
        from cryptography.fernet import Fernet  # type: ignore
        key = base64.urlsafe_b64encode(_MACHINE_KEY)
        token = Fernet(key).encrypt(plain.encode("utf-8"))
        return "fernet:" + token.decode("utf-8")
    except Exception:
        # 兜底：XOR + base64（可逆但不明文）
        data = plain.encode("utf-8")
        out = bytes(b ^ _MACHINE_KEY[i % len(_MACHINE_KEY)]
                    for i, b in enumerate(data))
        return "xor:" + base64.b64encode(out).decode("utf-8")


def _decrypt(stored: str) -> str:
    if not stored:
        return ""
    try:
        if stored.startswith("fernet:"):
            from cryptography.fernet import Fernet  # type: ignore
            key = base64.urlsafe_b64encode(_MACHINE_KEY)
            return Fernet(key).decrypt(stored[7:].encode("utf-8")).decode("utf-8")
        if stored.startswith("xor:"):
            data = base64.b64decode(stored[4:])
            out = bytes(b ^ _MACHINE_KEY[i % len(_MACHINE_KEY)]
                        for i, b in enumerate(data))
            return out.decode("utf-8")
    except Exception:
        return ""
    return ""


def _mask_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return key[:2] + "****"
    return key[:4] + "****" + key[-4:]


# ---------------------------------------------------------------------------
# 配置管理
# ---------------------------------------------------------------------------
class LLMConfigManager:
    def __init__(self, path: str = _CONFIG_PATH) -> None:
        self.path = path
        self._data: Dict[str, Any] = {
            "providers": {},
            "default_provider": None,
            "updated_at": None,
        }
        self._load()

    def _load(self) -> None:
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
        except Exception:
            self._data = {"providers": {}, "default_provider": None}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._data["updated_at"] = time.time()
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)

    # ---- 保存 / 更新 ----
    def save_key(self, provider_id: str, api_key: str,
                 base_url: Optional[str] = None,
                 model: Optional[str] = None,
                 temperature: float = 0.7,
                 max_tokens: int = 4096,
                 timeout: int = 60,
                 retries: int = 3,
                 proxy: Optional[str] = None) -> Dict[str, Any]:
        enc = _encrypt(api_key)
        self._data["providers"][provider_id] = {
            "api_key_enc": enc,
            "base_url": base_url,
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": timeout,
            "retries": retries,
            "proxy": proxy,
            "updated_at": time.time(),
        }
        self._save()
        return {"success": True, "provider": provider_id}

    def delete_key(self, provider_id: str) -> bool:
        if provider_id in self._data["providers"]:
            del self._data["providers"][provider_id]
            if self._data.get("default_provider") == provider_id:
                self._data["default_provider"] = None
            self._save()
            return True
        return False

    def set_default(self, provider_id: str) -> bool:
        if provider_id not in self._data["providers"]:
            return False
        self._data["default_provider"] = provider_id
        self._save()
        return True

    # ---- 读取（脱敏 / 明文） ----
    def list_keys_masked(self) -> List[Dict[str, Any]]:
        out = []
        for pid, cfg in self._data["providers"].items():
            key = _decrypt(cfg.get("api_key_enc", ""))
            out.append({
                "provider": pid,
                "api_key_masked": _mask_key(key),
                "base_url": cfg.get("base_url"),
                "model": cfg.get("model"),
                "temperature": cfg.get("temperature"),
                "max_tokens": cfg.get("max_tokens"),
                "timeout": cfg.get("timeout"),
                "retries": cfg.get("retries"),
                "is_default": self._data.get("default_provider") == pid,
                "updated_at": cfg.get("updated_at"),
            })
        return out

    def get_clear_key(self, provider_id: Optional[str] = None) -> Dict[str, Any]:
        pid = provider_id or self._data.get("default_provider")
        if not pid or pid not in self._data["providers"]:
            return {"configured": False}
        cfg = self._data["providers"][pid]
        return {
            "configured": True,
            "provider": pid,
            "api_key": _decrypt(cfg.get("api_key_enc", "")),
            "base_url": cfg.get("base_url"),
            "model": cfg.get("model"),
            "temperature": cfg.get("temperature", 0.7),
            "max_tokens": cfg.get("max_tokens", 4096),
            "timeout": cfg.get("timeout", 60),
            "retries": cfg.get("retries", 3),
            "proxy": cfg.get("proxy"),
        }

    def status(self) -> Dict[str, Any]:
        keys = self.list_keys_masked()
        return {
            "total_configured": len(keys),
            "default_provider": self._data.get("default_provider"),
            "keys": keys,
            "any_configured": len(keys) > 0,
            "encryption": "fernet" if self._uses_fernet() else "xor-fallback",
        }

    def _uses_fernet(self) -> bool:
        for cfg in self._data["providers"].values():
            if str(cfg.get("api_key_enc", "")).startswith("fernet:"):
                return True
        return False

    # ---- 导入导出 ----
    def export_encrypted(self) -> Dict[str, Any]:
        return dict(self._data)

    def import_config(self, data: Dict[str, Any]) -> int:
        provs = data.get("providers") or {}
        n = 0
        for pid, cfg in provs.items():
            if "api_key_enc" in cfg:
                self._data["providers"][pid] = cfg
                n += 1
        self._data["default_provider"] = data.get(
            "default_provider", self._data.get("default_provider"))
        self._save()
        return n


_singleton: Optional[LLMConfigManager] = None


def get_config_manager() -> LLMConfigManager:
    global _singleton
    if _singleton is None:
        _singleton = LLMConfigManager()
    return _singleton
