# -*- coding: utf-8 -*-
"""
feature_control.py — 功能权限与限制。

能力:
    * 功能模块按 License 类型启停、模块依赖、模块升级
    * 用户数限制：最大/并发/管理员/普通用户，超限处理
    * 时间限制：有效期、到期提醒、宽限期、降级、续费
    * API 调用限制：配额、频率、并发、超限、重置、升级
    * 数据量限制：资产/扫描任务/报告/存储 上限
    * 高级功能解锁：AI 分析/高级报告/多租户/分布式/API 开放/自定义集成
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from .license_generator import get_issuer, LICENSE_PLANS, ALL_MODULES, ADVANCED_FEATURES, LOCK

# 模块依赖：key 依赖 value 中的模块
MODULE_DEPS: Dict[str, List[str]] = {
    "ai_analysis": ["report"],
    "advanced_report": ["report"],
    "distributed_scan": ["basic_scan"],
    "multi_tenant": ["asset_mgmt"],
    "custom_integration": ["api_open"],
}

USAGE: Dict[str, Dict[str, Any]] = {
    "users": {},        # license_id -> {active_users, admins, concurrent}
    "api": {},          # license_id -> {day, used, minute_calls: [ts...]}
    "data": {},         # license_id -> {assets, scan_tasks, reports, storage_mb}
}


class FeatureController:
    """根据 License 策略做功能/配额/数据量校验。"""

    def __init__(self) -> None:
        self.issuer = get_issuer()

    # ---------------- 模块控制 ---------------- #
    def module_status(self, license_id: str) -> Dict[str, Any]:
        lic = self.issuer.licenses.get(license_id)
        if not lic:
            return {"modules": {}, "error": "license_not_found"}
        granted = set(lic["payload"]["modules"])
        all_granted = "*" in granted
        out: Dict[str, Dict[str, Any]] = {}
        for m in ALL_MODULES:
            enabled = all_granted or m in granted
            missing_deps = [d for d in MODULE_DEPS.get(m, [])
                            if not (all_granted or d in granted)]
            out[m] = {
                "enabled": enabled,
                "dep_missing": missing_deps,
                "usable": enabled and not missing_deps,
            }
        return {"modules": out, "plan": lic["payload"]["plan"]}

    def require_module(self, license_id: str, module: str) -> Dict[str, Any]:
        st = self.module_status(license_id)
        if "error" in st:
            return {"allowed": False, "reason": st["error"]}
        info = st["modules"].get(module)
        if not info:
            return {"allowed": False, "reason": "unknown_module"}
        if info["usable"]:
            return {"allowed": True}
        if not info["enabled"]:
            return {"allowed": False, "reason": "module_not_in_plan",
                    "message": f"模块 {module} 需要更高版本"}
        return {"allowed": False, "reason": "dependency_missing",
                "missing": info["dep_missing"]}

    # ---------------- 用户数 ---------------- #
    def usage_users(self, license_id: str, active: int = 0,
                    admins: int = 0, concurrent: int = 0) -> Dict[str, Any]:
        lic = self.issuer.licenses.get(license_id)
        if not lic:
            return {"allowed": False, "reason": "license_not_found"}
        p = lic["payload"]
        cur = USAGE["users"].setdefault(license_id,
                                       {"active_users": 0, "admins": 0, "concurrent": 0})
        if active:
            cur["active_users"] = active
        if admins:
            cur["admins"] = admins
        if concurrent:
            cur["concurrent"] = concurrent
        over_users = cur["active_users"] > p["max_users"]
        return {
            "allowed": not over_users,
            "current": cur,
            "limit": {"max_users": p["max_users"],
                      "max_concurrent": p["max_users"] * 2},
            "over_limit": over_users,
            "action": "block_new_users" if over_users else "ok",
        }

    # ---------------- 时间限制 ---------------- #
    def time_status(self, license_id: str) -> Dict[str, Any]:
        lic = self.issuer.licenses.get(license_id)
        if not lic:
            return {"valid": False, "reason": "license_not_found"}
        p = lic["payload"]
        now = time.time()
        days_left = (p["expires_at"] - now) / 86400
        if now > p["expires_at"]:
            stage = "expired"
        elif days_left <= p["grace_days"]:
            stage = "grace"
        elif days_left <= 15:
            stage = "expiring_soon"
        else:
            stage = "active"
        degraded = stage in ("expired", "grace")
        return {
            "stage": stage,
            "days_remaining": round(days_left, 1),
            "grace_days": p["grace_days"],
            "degraded": degraded,
            "degraded_features": ["ai_analysis", "distributed_scan", "api_open"]
                                 if degraded else [],
            "renew_url": f"/api/v1/license-system/billing/renew?license_id={license_id}",
        }

    # ---------------- API 配额 ---------------- #
    def api_quota_check(self, license_id: str, cost: int = 1) -> Dict[str, Any]:
        lic = self.issuer.licenses.get(license_id)
        if not lic:
            return {"allowed": False, "reason": "license_not_found"}
        p = lic["payload"]
        day = time.strftime("%Y-%m-%d")
        bucket = USAGE["api"].setdefault(license_id,
                                         {"day": day, "used": 0, "minute_calls": []})
        if bucket["day"] != day:
            bucket["day"] = day
            bucket["used"] = 0
            bucket["minute_calls"] = []
        now = time.time()
        bucket["minute_calls"][:] = [t for t in bucket["minute_calls"] if now - t < 60]
        if len(bucket["minute_calls"]) >= 100:
            return {"allowed": False, "reason": "rate_limited",
                    "message": "API 频率超限（100 次/分钟）"}
        if bucket["used"] + cost > p["api_quota_per_day"]:
            return {"allowed": False, "reason": "quota_exceeded",
                    "used": bucket["used"], "limit": p["api_quota_per_day"],
                    "upgrade_hint": "升级版本以提升日配额"}
        bucket["used"] += cost
        bucket["minute_calls"].append(now)
        return {"allowed": True, "used": bucket["used"],
                "limit": p["api_quota_per_day"],
                "remaining": p["api_quota_per_day"] - bucket["used"]}

    # ---------------- 数据量 ---------------- #
    def data_quota_check(self, license_id: str, assets: int = 0,
                         scan_tasks: int = 0, reports: int = 0,
                         storage_mb: int = 0) -> Dict[str, Any]:
        lic = self.issuer.licenses.get(license_id)
        if not lic:
            return {"allowed": False, "reason": "license_not_found"}
        p = lic["payload"]
        cur = USAGE["data"].setdefault(license_id,
                                       {"assets": 0, "scan_tasks": 0,
                                        "reports": 0, "storage_mb": 0})
        if assets:
            cur["assets"] += assets
        if scan_tasks:
            cur["scan_tasks"] += scan_tasks
        if reports:
            cur["reports"] += reports
        if storage_mb:
            cur["storage_mb"] += storage_mb
        over = {k: cur[k] > p[k] for k in
                ("assets", "scan_tasks", "reports", "storage_mb")}
        any_over = any(over.values())
        limits = {"max_assets": p["max_assets"], "max_scan_tasks": p["max_scan_tasks"],
                  "max_reports": p["max_reports"], "max_storage_mb": p["max_storage_mb"]}
        return {"allowed": not any_over, "over": over,
                "current": cur, "limits": limits,
                "action": "block_new" if any_over else "ok"}

    # ---------------- 高级功能 ---------------- #
    def unlockable_features(self, license_id: str) -> Dict[str, Any]:
        lic = self.issuer.licenses.get(license_id)
        if not lic:
            return {"features": [], "error": "license_not_found"}
        granted = set(lic["payload"]["advanced_features"])
        all_granted = "*" in granted
        out = {}
        for f in ADVANCED_FEATURES:
            out[f] = {"unlocked": all_granted or f in granted,
                      "required_plan": "enterprise/custom" if f in
                      ("multi_tenant", "distributed_scan", "custom_integration")
                      else "professional"}
        return {"features": out, "plan": lic["payload"]["plan"]}


_ctrl: Optional[FeatureController] = None


def get_feature_controller() -> FeatureController:
    global _ctrl
    with LOCK:
        if _ctrl is None:
            _ctrl = FeatureController()
        return _ctrl
