#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_ultra_pro/subscription_management.py — 订阅管理。

套餐：免费版 / 专业版 / 企业版
周期：按月 / 按年(优惠) / 按次(按扫描次数)
能力：创建/升级/降级/取消、自动续费、到期提醒、功能权限控制、用量统计、超额处理。
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional


PLANS: Dict[str, Dict[str, Any]] = {
    "free": {
        "label": "免费版", "monthly": 0, "yearly": 0,
        "scans_monthly": 10, "api_calls_monthly": 1000, "reports_monthly": 2,
        "features": ["basic_scan", "basic_report", "community_support"],
        "support": "社区支持", "sla_target": None,
    },
    "pro": {
        "label": "专业版", "monthly": 299, "yearly": 2990,
        "scans_monthly": 500, "api_calls_monthly": 50000, "reports_monthly": 100,
        "features": ["basic_scan", "advanced_scan", "advanced_report",
                     "api_access", "priority_support", "custom_report"],
        "support": "优先支持", "sla_target": "99.9%",
    },
    "enterprise": {
        "label": "企业版", "monthly": 1999, "yearly": 19999,
        "scans_monthly": -1, "api_calls_monthly": -1, "reports_monthly": -1,
        "features": ["*"],   # 全部功能
        "support": "专属支持/SLA保障", "sla_target": "99.99%",
    },
}

PERIODS = ["monthly", "yearly", "on_demand"]
PERIOD_LABELS = {"monthly": "按月", "yearly": "按年(8.3折)", "on_demand": "按次"}

# 按次订阅：每千次扫描包价格
ON_DEMAND_PACKS = {
    "pack_1k": {"label": "1000次扫描包", "count": 1000, "price": 499},
    "pack_5k": {"label": "5000次扫描包", "count": 5000, "price": 1999},
}


class SubscriptionManager:
    """订阅管理（内存存储）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # customer_id -> subscription dict
        self._subs: Dict[str, Dict[str, Any]] = {}
        # customer_id -> usage
        self._usage: Dict[str, Dict[str, Any]] = {}
        # subscription history
        self._history: List[Dict[str, Any]] = []
        self._seq = 0

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}{int(time.time()) % 100000:05d}-{self._seq:03d}"

    def _now(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def _ensure(self, customer_id: str) -> Dict[str, Any]:
        if customer_id not in self._subs:
            self._subs[customer_id] = {
                "customer_id": customer_id, "plan": "free",
                "period": None, "status": "active",
                "auto_renew": False, "started_at": self._now(),
                "expires_at": None, "on_demand_balance": 0,
            }
        if customer_id not in self._usage:
            self._usage[customer_id] = {
                "scans": 0, "api_calls": 0, "reports": 0,
                "cycle_start": time.strftime("%Y-%m"),
            }
        return self._subs[customer_id]

    def _record_history(self, customer_id: str, action: str, detail: Dict[str, Any]) -> None:
        self._history.append({
            "hist_id": self._next_id("HIS"),
            "customer_id": customer_id, "action": action,
            "detail": detail, "at": self._now(),
        })

    # ------------------------------------------------------------------ #
    # 套餐
    # ------------------------------------------------------------------ #
    def plans(self) -> Dict[str, Any]:
        return {"plans": PLANS, "periods": PERIODS,
                "period_labels": PERIOD_LABELS,
                "on_demand_packs": ON_DEMAND_PACKS}

    # ------------------------------------------------------------------ #
    # 订阅创建/升级/降级/取消
    # ------------------------------------------------------------------ #
    def subscribe(self, customer_id: str, plan: str,
                  period: str = "monthly", auto_renew: bool = False) -> Dict[str, Any]:
        if plan not in PLANS:
            raise ValueError(f"未知套餐: {plan}")
        if period not in PERIODS:
            raise ValueError(f"周期必须为 {PERIODS}")
        with self._lock:
            sub = self._ensure(customer_id)
            old_plan = sub["plan"]
            if period == "on_demand":
                raise ValueError("按次订阅请使用 buy_ondemand_pack")
            price = PLANS[plan][period]
            days = 365 if period == "yearly" else 30
            sub["plan"] = plan
            sub["period"] = period
            sub["status"] = "active"
            sub["auto_renew"] = auto_renew
            sub["started_at"] = self._now()
            sub["expires_at"] = int(time.time()) + days * 86400
            # 重置用量周期
            self._usage[customer_id]["cycle_start"] = time.strftime("%Y-%m")
            self._usage[customer_id]["scans"] = 0
            self._usage[customer_id]["api_calls"] = 0
            self._usage[customer_id]["reports"] = 0
            self._record_history(customer_id, "subscribe", {
                "from": old_plan, "to": plan, "period": period, "price": price,
            })
            return {"customer_id": customer_id, "plan": plan,
                    "plan_label": PLANS[plan]["label"], "period": period,
                    "price": price, "auto_renew": auto_renew,
                    "expires_at": sub["expires_at"],
                    "expires_at_str": time.strftime("%Y-%m-%d", time.localtime(sub["expires_at"])),
                    "changed_from": old_plan,
                    "operation": "upgraded" if old_plan != plan and plan != "free"
                                 else ("downgraded" if old_plan != plan else "renewed")}

    def buy_ondemand_pack(self, customer_id: str, pack_key: str = "pack_1k") -> Dict[str, Any]:
        """按次订阅：购买扫描次数包。"""
        if pack_key not in ON_DEMAND_PACKS:
            raise ValueError(f"未知次数包: {pack_key}")
        pack = ON_DEMAND_PACKS[pack_key]
        with self._lock:
            sub = self._ensure(customer_id)
            sub["on_demand_balance"] += pack["count"]
            self._record_history(customer_id, "buy_ondemand", pack)
            return {"customer_id": customer_id, "pack": pack,
                    "on_demand_balance": sub["on_demand_balance"]}

    def cancel(self, customer_id: str, immediate: bool = False) -> Dict[str, Any]:
        with self._lock:
            sub = self._ensure(customer_id)
            sub["auto_renew"] = False
            if immediate:
                sub["status"] = "cancelled"
                sub["plan"] = "free"
                sub["period"] = None
            else:
                sub["status"] = "pending_cancel"
            self._record_history(customer_id, "cancel", {"immediate": immediate})
            return {"customer_id": customer_id, "status": sub["status"],
                    "message": "已关闭自动续费，到期后降级为免费版" if not immediate
                               else "已立即取消并降级为免费版"}

    def set_auto_renew(self, customer_id: str, enabled: bool) -> Dict[str, Any]:
        with self._lock:
            sub = self._ensure(customer_id)
            sub["auto_renew"] = enabled
            return {"customer_id": customer_id, "auto_renew": enabled}

    # ------------------------------------------------------------------ #
    # 到期提醒
    # ------------------------------------------------------------------ #
    def expiry_reminders(self) -> List[Dict[str, Any]]:
        """检查所有即将到期的订阅，返回 7/3/1 天提醒。"""
        now = time.time()
        out = []
        with self._lock:
            for cid, sub in self._subs.items():
                if not sub.get("expires_at"):
                    continue
                days_left = (sub["expires_at"] - now) / 86400
                if 0 <= days_left <= 7:
                    level = "1天" if days_left <= 1 else ("3天" if days_left <= 3 else "7天")
                    out.append({
                        "customer_id": cid, "plan": sub["plan"],
                        "days_left": round(days_left, 1), "remind_level": level,
                        "auto_renew": sub["auto_renew"],
                        "expires_at_str": time.strftime("%Y-%m-%d", time.localtime(sub["expires_at"])),
                    })
        return sorted(out, key=lambda x: x["days_left"])

    # ------------------------------------------------------------------ #
    # 功能权限控制
    # ------------------------------------------------------------------ #
    def check_feature(self, customer_id: str, feature: str) -> Dict[str, Any]:
        with self._lock:
            sub = self._ensure(customer_id)
            plan = PLANS[sub["plan"]]
            allowed = "*" in plan["features"] or feature in plan["features"]
            return {"customer_id": customer_id, "plan": sub["plan"],
                    "feature": feature, "allowed": bool(allowed),
                    "plan_label": plan["label"]}

    # ------------------------------------------------------------------ #
    # 用量统计 / 超额处理
    # ------------------------------------------------------------------ #
    def usage_report(self, customer_id: str, scans: int = 0,
                     api_calls: int = 0, reports: int = 0) -> Dict[str, Any]:
        """记录用量并返回是否超额。"""
        with self._lock:
            sub = self._ensure(customer_id)
            u = self._usage[customer_id]
            plan = PLANS[sub["plan"]]
            u["scans"] += scans
            u["api_calls"] += api_calls
            u["reports"] += reports
            limits = {
                "scans": plan["scans_monthly"],
                "api_calls": plan["api_calls_monthly"],
                "reports": plan["reports_monthly"],
            }
            overages = {}
            for k, limit in limits.items():
                used = u[k]
                if limit > 0 and used > limit:
                    overages[k] = {"used": used, "limit": limit,
                                    "over": used - limit,
                                    "action": "超额：已限制功能并提示升级"}
            return {"customer_id": customer_id, "plan": sub["plan"],
                    "usage": u, "limits": limits,
                    "on_demand_balance": sub["on_demand_balance"],
                    "overages": overages,
                    "has_overage": bool(overages)}

    def get_usage(self, customer_id: str) -> Dict[str, Any]:
        with self._lock:
            sub = self._ensure(customer_id)
            u = self._usage[customer_id]
            plan = PLANS[sub["plan"]]
            return {"customer_id": customer_id, "plan": sub["plan"],
                    "plan_label": plan["label"], "usage": u,
                    "limits": {"scans": plan["scans_monthly"],
                               "api_calls": plan["api_calls_monthly"],
                               "reports": plan["reports_monthly"]},
                    "on_demand_balance": sub["on_demand_balance"]}

    # ------------------------------------------------------------------ #
    # 汇总
    # ------------------------------------------------------------------ #
    def get_subscription(self, customer_id: str) -> Dict[str, Any]:
        with self._lock:
            sub = self._ensure(customer_id)
            return dict(sub)

    def list_subscriptions(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(s) for s in self._subs.values()]

    def history(self, customer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._history)
            if customer_id:
                out = [h for h in out if h["customer_id"] == customer_id]
            return sorted(out, key=lambda x: x["at"], reverse=True)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_plan: Dict[str, int] = {}
            active = 0
            for s in self._subs.values():
                by_plan[s["plan"]] = by_plan.get(s["plan"], 0) + 1
                if s["status"] == "active":
                    active += 1
            return {"total_subscribers": len(self._subs),
                    "active": active, "by_plan": by_plan,
                    "auto_renew": sum(1 for s in self._subs.values() if s["auto_renew"]),
                    "expiring_soon": len(self.expiry_reminders())}


_sub_mgr: SubscriptionManager | None = None


def get_subscription_manager() -> SubscriptionManager:
    global _sub_mgr
    if _sub_mgr is None:
        _sub_mgr = SubscriptionManager()
    return _sub_mgr
