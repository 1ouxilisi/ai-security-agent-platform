# -*- coding: utf-8 -*-
"""app_key_manager.py — API 密钥与应用管理。

能力：
- 应用注册 / 审核 / 统计
- API Key 生成 / 轮换 / 撤销
- 权限范围 (Scope)、IP 白名单、回调 URL
"""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Any, Dict, List, Optional


SCOPES: List[Dict[str, str]] = [
    {"scope": "scanner:read", "desc": "读取扫描任务"},
    {"scope": "scanner:write", "desc": "创建/触发扫描"},
    {"scope": "report:read", "desc": "读取报告"},
    {"scope": "report:write", "desc": "生成报告"},
    {"scope": "asset:read", "desc": "读取资产"},
    {"scope": "asset:write", "desc": "写入资产"},
    {"scope": "intel:read", "desc": "读取威胁情报"},
]


class AppKeyManager:
    """应用与 API Key 管理。"""

    def __init__(self) -> None:
        self.apps: Dict[str, Dict[str, Any]] = {}
        self.keys: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    # 应用
    # ------------------------------------------------------------------ #
    def register_app(self, name: str, owner: str, description: str = "",
                     scopes: Optional[List[str]] = None) -> Dict[str, Any]:
        app_id = "app_" + uuid.uuid4().hex[:10]
        app = {
            "app_id": app_id,
            "name": name,
            "owner": owner,
            "description": description,
            "scopes": scopes or ["scanner:read"],
            "status": "pending_review",
            "ip_whitelist": [],
            "callback_url": "",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stats": {"calls_total": 0, "calls_today": 0, "errors_24h": 0},
        }
        self.apps[app_id] = app
        return app

    def get_app(self, app_id: str) -> Optional[Dict[str, Any]]:
        return self.apps.get(app_id)

    def list_apps(self, owner: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.apps.values())
        if owner:
            items = [a for a in items if a.get("owner") == owner]
        return items

    def review_app(self, app_id: str, approved: bool, note: str = "") -> Dict[str, Any]:
        app = self.apps.get(app_id)
        if not app:
            return {}
        app["status"] = "approved" if approved else "rejected"
        app["review_note"] = note
        app["reviewed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return app

    def update_app(self, app_id: str, **fields: Any) -> Dict[str, Any]:
        app = self.apps.get(app_id)
        if not app:
            return {}
        for k in ("ip_whitelist", "callback_url", "scopes", "description"):
            if k in fields:
                app[k] = fields[k]
        app["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return app

    # ------------------------------------------------------------------ #
    # API Key
    # ------------------------------------------------------------------ #
    def create_key(self, app_id: str, name: str = "default",
                   expires_days: int = 365) -> Dict[str, Any]:
        app = self.apps.get(app_id)
        if not app:
            return {}
        key_id = "key_" + uuid.uuid4().hex[:10]
        raw = "ak_" + secrets.token_urlsafe(32)
        now = int(time.time())
        rec = {
            "key_id": key_id,
            "app_id": app_id,
            "name": name,
            "key_prefix": raw[:12],
            "key_hint": raw[:12] + "...",
            "key_hash": secrets.token_hex(32),  # 真实场景仅存哈希
            "status": "active",
            "scopes": app.get("scopes", []),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(now + expires_days * 86400)),
            "rotated_count": 0,
            "last_used_at": None,
        }
        self.keys[key_id] = rec
        # 返回明文 key 仅一次
        rec["_plaintext_once"] = raw
        return rec

    def rotate_key(self, key_id: str) -> Dict[str, Any]:
        rec = self.keys.get(key_id)
        if not rec:
            return {}
        raw = "ak_" + secrets.token_urlsafe(32)
        rec["key_prefix"] = raw[:12]
        rec["key_hint"] = raw[:12] + "..."
        rec["key_hash"] = secrets.token_hex(32)
        rec["rotated_count"] += 1
        rec["rotated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        rec["_plaintext_once"] = raw
        return rec

    def revoke_key(self, key_id: str, reason: str = "") -> Dict[str, Any]:
        rec = self.keys.get(key_id)
        if not rec:
            return {}
        rec["status"] = "revoked"
        rec["revoked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        rec["revoke_reason"] = reason
        return rec

    def list_keys(self, app_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.keys.values())
        if app_id:
            items = [k for k in items if k.get("app_id") == app_id]
        # 不返回敏感字段
        out = []
        for k in items:
            safe = {kk: vv for kk, vv in k.items() if kk not in ("_plaintext_once", "key_hash")}
            out.append(safe)
        return out

    def scopes_catalog(self) -> List[Dict[str, str]]:
        return SCOPES

    def app_stats(self, app_id: str) -> Dict[str, Any]:
        app = self.apps.get(app_id)
        if not app:
            return {}
        return {
            "app_id": app_id,
            "name": app.get("name"),
            "stats": app.get("stats", {}),
            "key_count": sum(1 for k in self.keys.values() if k.get("app_id") == app_id),
            "active_keys": sum(1 for k in self.keys.values()
                               if k.get("app_id") == app_id and k.get("status") == "active"),
        }


_key_mgr: Optional[AppKeyManager] = None


def get_app_key_manager() -> AppKeyManager:
    global _key_mgr
    if _key_mgr is None:
        _key_mgr = AppKeyManager()
    return _key_mgr
