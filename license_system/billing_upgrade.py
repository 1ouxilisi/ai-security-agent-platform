# -*- coding: utf-8 -*-
"""
billing_upgrade.py — 续费与升级管理。

能力:
    * 续费提醒/报价/订单/激活/历史/优惠
    * 版本升级路径/报价/订单/激活/数据迁移/回滚
    * 模块加购：报价/订单/激活/依赖/升级
    * 用户数扩容：报价/订单/激活/历史/优惠
    * 订单管理：创建/状态/支付/发票/退款/历史
    * 价格管理：版本/模块/用户数/API/折扣/促销
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from .license_generator import get_issuer, LICENSE_PLANS, LOCK

ORDERS: Dict[str, Dict[str, Any]] = {}
RENEW_HISTORY: List[Dict[str, Any]] = []

PRICE_TABLE: Dict[str, Any] = {
    "plans": {k: v["price_year"] for k, v in LICENSE_PLANS.items()},
    "module_addon_price": {
        "ai_analysis": 3000, "advanced_report": 1500, "multi_tenant": 8000,
        "distributed_scan": 12000, "api_open": 5000, "custom_integration": 20000,
    },
    "per_user_per_year": 600,
    "per_device_per_year": 200,
    "extra_api_million": 800,
    "discount": {"early_bird": 0.9, "loyalty": 0.95, "annual": 0.85},
    "promotions": [
        {"code": "NEW2026", "percent": 0.8, "until": "2026-12-31"},
        {"code": "BLACKFRIDAY", "percent": 0.7, "until": "2026-11-29"},
    ],
}


class BillingManager:
    """续费/升级/加购/扩容/订单/报价。"""

    def __init__(self) -> None:
        self.issuer = get_issuer()

    # ---------------- 报价 ---------------- #
    def quote_renewal(self, license_id: str, years: int = 1,
                      promo_code: Optional[str] = None) -> Dict[str, Any]:
        lic = self.issuer.licenses.get(license_id)
        if not lic:
            return {"error": "license_not_found"}
        plan = lic["payload"]["plan"]
        unit = LICENSE_PLANS[plan]["price_year"]
        gross = unit * years
        discount = self._apply_promo(gross, promo_code)
        return {"license_id": license_id, "plan": plan, "years": years,
                "unit_price": unit, "gross": gross, "discount": discount,
                "final": round(gross - discount, 2),
                "suggested_renewal_date": time.strftime("%Y-%m-%d")}

    def quote_upgrade(self, license_id: str, new_plan: str) -> Dict[str, Any]:
        lic = self.issuer.licenses.get(license_id)
        if not lic or new_plan not in LICENSE_PLANS:
            return {"error": "invalid_input"}
        old_plan = lic["payload"]["plan"]
        old_price = LICENSE_PLANS[old_plan]["price_year"]
        new_price = LICENSE_PLANS[new_plan]["price_year"]
        # 按剩余天数比例折算差价
        p = lic["payload"]
        total_days = max(1, p["duration_days"])
        remain_ratio = max(0, (p["expires_at"] - time.time()) / 86400) / total_days
        diff = max(0, (new_price - old_price) * remain_ratio)
        return {"license_id": license_id, "from": old_plan, "to": new_plan,
                "remain_ratio": round(remain_ratio, 3),
                "price": round(diff, 2),
                "path": f"{LICENSE_PLANS[old_plan]['name']} → {LICENSE_PLANS[new_plan]['name']}"}

    def quote_module_addon(self, license_id: str, modules: List[str]) -> Dict[str, Any]:
        lic = self.issuer.licenses.get(license_id)
        if not lic:
            return {"error": "license_not_found"}
        items = []
        total = 0
        for m in modules:
            price = PRICE_TABLE["module_addon_price"].get(m, 1000)
            items.append({"module": m, "price": price})
            total += price
        return {"license_id": license_id, "items": items, "total": total}

    def quote_expand_users(self, license_id: str, extra_users: int) -> Dict[str, Any]:
        lic = self.issuer.licenses.get(license_id)
        if not lic:
            return {"error": "license_not_found"}
        price = extra_users * PRICE_TABLE["per_user_per_year"]
        return {"license_id": license_id, "extra_users": extra_users,
                "price_per_user": PRICE_TABLE["per_user_per_year"],
                "total": price}

    # ---------------- 订单 ---------------- #
    def create_order(self, license_id: str, kind: str, amount: float,
                     detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        order_id = "ORD-" + uuid.uuid4().hex[:12].upper()
        order = {
            "order_id": order_id, "license_id": license_id, "kind": kind,
            "amount": amount, "status": "pending", "detail": detail or {},
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "paid_at": None, "invoice_no": None, "refunded": False,
        }
        ORDERS[order_id] = order
        return order

    def pay_order(self, order_id: str) -> Dict[str, Any]:
        o = ORDERS.get(order_id)
        if not o:
            return {"ok": False, "error": "order_not_found"}
        o["status"] = "paid"
        o["paid_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        o["invoice_no"] = "INV-" + uuid.uuid4().hex[:10].upper()
        self._apply_order_effect(o)
        return {"ok": True, "order": o}

    def refund_order(self, order_id: str, reason: str = "客户退款") -> Dict[str, Any]:
        o = ORDERS.get(order_id)
        if not o or o["status"] != "paid":
            return {"ok": False, "error": "order_not_refundable"}
        o["status"] = "refunded"
        o["refunded"] = True
        o["refund_reason"] = reason
        return {"ok": True, "order": o}

    def _apply_order_effect(self, order: Dict[str, Any]) -> None:
        lid = order["license_id"]
        kind = order["kind"]
        d = order["detail"]
        if kind == "renew":
            self.issuer.extend(lid, int(d.get("years", 1)) * 365)
            RENEW_HISTORY.append({**order, "type": "renew"})
        elif kind == "upgrade":
            self.issuer.upgrade_plan(lid, d.get("to_plan", "standard"))
        elif kind == "expand_users":
            lic = self.issuer.licenses.get(lid)
            if lic:
                lic["payload"]["max_users"] += int(d.get("extra_users", 0))
        elif kind == "module_addon":
            lic = self.issuer.licenses.get(lid)
            if lic:
                cur = lic["payload"]["modules"]
                if "*" not in cur:
                    cur.extend(d.get("modules", []))
                    lic["payload"]["modules"] = list(set(cur))

    # ---------------- 查询 ---------------- #
    def list_orders(self, license_id: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict[str, Any]]:
        out = []
        for o in ORDERS.values():
            if license_id and o["license_id"] != license_id:
                continue
            if status and o["status"] != status:
                continue
            out.append(o)
        return out

    def revenue_summary(self) -> Dict[str, Any]:
        total = 0.0
        by_plan: Dict[str, float] = {}
        by_kind: Dict[str, float] = {}
        monthly: Dict[str, float] = {}
        for o in ORDERS.values():
            if o["status"] != "paid":
                continue
            amt = float(o["amount"])
            total += amt
            by_kind[o["kind"]] = by_kind.get(o["kind"], 0) + amt
            lic = self.issuer.licenses.get(o["license_id"])
            if lic:
                plan = lic["payload"]["plan"]
                by_plan[plan] = by_plan.get(plan, 0) + amt
            month = (o["paid_at"] or o["created_at"])[:7]
            monthly[month] = monthly.get(month, 0) + amt
        return {"total_revenue": round(total, 2),
                "by_plan": by_plan, "by_kind": by_kind, "monthly": monthly,
                "order_count": len(ORDERS)}

    def renewal_reminders(self) -> List[Dict[str, Any]]:
        out = []
        for lid, lic in self.issuer.licenses.items():
            days_left = (lic["payload"]["expires_at"] - time.time()) / 86400
            if 0 < days_left <= 30:
                out.append({"license_id": lid,
                            "customer": lic["payload"]["customer"],
                            "days_left": round(days_left, 1),
                            "plan": lic["payload"]["plan"]})
        return out

    # ---------------- 价格管理 ---------------- #
    def price_config(self) -> Dict[str, Any]:
        return PRICE_TABLE

    def update_price(self, key: str, value: Any) -> Dict[str, Any]:
        if key in PRICE_TABLE:
            PRICE_TABLE[key] = value
            return {"ok": True, "key": key, "value": value}
        return {"ok": False, "error": "unknown_key"}

    # ---------------- 内部 ---------------- #
    def _apply_promo(self, gross: float, code: Optional[str]) -> float:
        if not code:
            return 0.0
        for p in PRICE_TABLE["promotions"]:
            if p["code"] == code:
                return round(gross * (1 - p["percent"]), 2)
        return 0.0


_billing: Optional[BillingManager] = None


def get_billing_manager() -> BillingManager:
    global _billing
    with LOCK:
        if _billing is None:
            _billing = BillingManager()
        return _billing
