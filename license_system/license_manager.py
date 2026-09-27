# -*- coding: utf-8 -*-
"""
license_manager.py — License 生命周期管理（v30.0 真实 License 系统）。

职责:
    * 内存字典存储当前激活的 License
    * 激活 / 卸载 / 状态查询 / 过期提醒
    * 历史签发记录（内存）
    * 升级 / 续费引导信息
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from .license_generator import (
    REAL_TIERS,
    VALID_TIER_CODES,
    RealLicenseIssuer,
    generate_machine_code,
    generate_real_license,
)
from .license_verifier import get_verifier
from .feature_gating import get_gate, TIER_COMPARISON


class LicenseManager:
    """License 管理器：负责当前实例的激活状态与历史记录。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._active: Optional[Dict[str, Any]] = None  # 当前激活的 License
        self._issued: List[Dict[str, Any]] = []         # 管理员签发历史
        self._activation_log: List[Dict[str, Any]] = []  # 激活/卸载日志

    # ------------------------------------------------------------------ #
    # 激活 / 卸载
    # ------------------------------------------------------------------ #
    def activate(self, license_key: str) -> Dict[str, Any]:
        """激活一份 License。

        Returns:
            {"success": bool, "data": {...}, "error": str|None}
        """
        result = get_verifier().verify(license_key)
        if not result["valid"]:
            self._log_event("activate_failed", result["code"], result["reason"])
            return {
                "success": False,
                "data": None,
                "error": {
                    "code": result["code"],
                    "message": result["reason"],
                },
            }

        payload = result["payload"]
        with self._lock:
            self._active = {
                "license_key": license_key,
                "payload": payload,
                "activated_at": int(time.time()),
                "days_remaining": result["days_remaining"],
            }
            self._log_event("activate_ok", payload.get("tier"),
                            f"License {payload.get('lic_id')} 已激活")

        return {
            "success": True,
            "data": self.status(),
            "error": None,
        }

    def deactivate(self) -> Dict[str, Any]:
        with self._lock:
            was = self._active
            self._active = None
        if was:
            self._log_event("deactivate", was["payload"].get("tier"),
                            f"License {was['payload'].get('lic_id')} 已卸载")
        return {"success": True,
                "data": {"deactivated": bool(was)},
                "error": None}

    # ------------------------------------------------------------------ #
    # 状态查询
    # ------------------------------------------------------------------ #
    def status(self) -> Dict[str, Any]:
        with self._lock:
            active = self._active
        machine = generate_machine_code()

        if not active:
            return {
                "activated": False,
                "tier": "free",
                "tier_name": "免费版 (Free)",
                "customer": None,
                "machine_code": machine,
                "days_remaining": 0,
                "expires_at": None,
                "expires_at_iso": None,
                "activated_at": None,
                "license_id": None,
                "warning": "尚未激活 License，当前为免费版（每日 API 100 次）",
                "upgrade_guide": self._upgrade_guide("free"),
            }

        payload = active["payload"]
        days_remaining = max(
            0, int((int(payload["expires_at"]) - time.time()) // 86400))
        warning = None
        if days_remaining <= 0:
            warning = "License 已过期，请续费升级"
        elif days_remaining <= 15:
            warning = f"License 将在 {days_remaining} 天后过期，请及时续费"

        return {
            "activated": True,
            "tier": payload.get("tier"),
            "tier_name": payload.get("tier_name"),
            "customer": payload.get("customer"),
            "machine_code": machine,
            "bound_machine_code": payload.get("machine_code"),
            "days_remaining": days_remaining,
            "issued_at": payload.get("issued_at"),
            "expires_at": payload.get("expires_at"),
            "activated_at": active.get("activated_at"),
            "license_id": payload.get("lic_id"),
            "modules": payload.get("modules", []),
            "features": payload.get("features", []),
            "multi_tenant": bool(payload.get("multi_tenant")),
            "priority_support": bool(payload.get("priority_support")),
            "warning": warning,
            "upgrade_guide": self._upgrade_guide(payload.get("tier", "free")),
        }

    # ------------------------------------------------------------------ #
    # 管理员：签发
    # ------------------------------------------------------------------ #
    def issue_license(
        self,
        *,
        machine_code: Optional[str] = None,
        tier: str = "pro",
        customer: str = "Anonymous",
        duration_days: int = 365,
    ) -> Dict[str, Any]:
        if tier not in REAL_TIERS:
            return {
                "success": False,
                "data": None,
                "error": {
                    "code": "unknown_tier",
                    "message": f"未知版本等级 {tier}，可选 {VALID_TIER_CODES}",
                },
            }
        issued = generate_real_license(
            machine_code=machine_code,
            tier=tier,
            customer=customer,
            duration_days=duration_days,
        )
        with self._lock:
            self._issued.append({
                "issued_at": int(time.time()),
                "customer": customer,
                "tier": tier,
                "machine_code": machine_code or generate_machine_code(),
                "lic_id": issued["payload"]["lic_id"],
                "duration_days": duration_days,
            })
        return {"success": True, "data": issued, "error": None}

    # ------------------------------------------------------------------ #
    # 功能列表
    # ------------------------------------------------------------------ #
    def features(self) -> Dict[str, Any]:
        with self._lock:
            active = self._active
        payload = active["payload"] if active else None
        gate = get_gate()
        return {
            "current": gate.describe(payload),
            "tiers": TIER_COMPARISON,
        }

    # ------------------------------------------------------------------ #
    # 历史 / 日志
    # ------------------------------------------------------------------ #
    def history(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "issued": list(self._issued),
                "events": list(self._activation_log[-50:]),
            }

    # ------------------------------------------------------------------ #
    # 内部
    # ------------------------------------------------------------------ #
    def _log_event(self, event: str, tier: Optional[str], message: str) -> None:
        with self._lock:
            self._activation_log.append({
                "ts": int(time.time()),
                "event": event,
                "tier": tier,
                "message": message,
            })

    @staticmethod
    def _upgrade_guide(current_tier: str) -> Dict[str, Any]:
        order = ["free", "pro", "enterprise"]
        try:
            idx = order.index(current_tier)
        except ValueError:
            idx = 0
        next_tier = order[idx + 1] if idx + 1 < len(order) else None
        return {
            "current": current_tier,
            "next_tier": next_tier,
            "message": ("已是最高版本" if next_tier is None
                        else f"可升级到 {REAL_TIERS[next_tier]['name']}"),
            "pricing": TIER_COMPARISON,
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_manager: Optional[LicenseManager] = None
_manager_lock = threading.RLock()


def get_manager() -> LicenseManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = LicenseManager()
        return _manager
