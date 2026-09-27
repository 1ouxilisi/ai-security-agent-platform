#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_pro/billing_system.py — 计费系统。

- 按扫描次数计费（计量后付费）
- 按月 / 按年订阅
- 支付接口预留（Stripe / 支付宝）—— 内存模拟，不真实扣款
- 账单（Invoice）管理：生成 / 查询 / 支付状态
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional


# 价目表（单位：元）
PRICING: Dict[str, Any] = {
    "per_scan_price": 1.5,           # 每次扫描 1.5 元（后付费）
    "subscriptions": {
        "free":    {"label": "免费版",  "monthly": 0,     "yearly": 0,
                    "scans_included": 5},
        "pro":     {"label": "专业版",  "monthly": 299,   "yearly": 2990,
                    "scans_included": 500},
        "enterprise": {"label": "企业版", "monthly": 1999, "yearly": 19999,
                       "scans_included": -1},
    },
    "payment_gateways": ["stripe", "alipay"],
}


class BillingSystem:
    """计费系统（全内存模拟）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # customer_id -> {scans_used, plan, period, renew_at, balance}
        self._accounts: Dict[str, Dict[str, Any]] = {}
        # invoices: id -> record
        self._invoices: Dict[str, Dict[str, Any]] = {}
        self._seq = 0

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{int(time.time()) % 100000:05d}{self._seq:03d}"

    def _ensure(self, customer_id: str) -> Dict[str, Any]:
        if customer_id not in self._accounts:
            self._accounts[customer_id] = {
                "plan": "free", "period": None, "scans_used": 0,
                "renew_at": None, "balance": 0.0, "created_at": time.time(),
            }
        return self._accounts[customer_id]

    # ------------------------------------------------------------------ #
    # 按扫描次数计费
    # ------------------------------------------------------------------ #
    def record_scan(self, customer_id: str, count: int = 1) -> Dict[str, Any]:
        """一次扫描结束后记账。超出订阅额度的部分按单价计费。"""
        with self._lock:
            acc = self._ensure(customer_id)
            plan = PRICING["subscriptions"].get(acc["plan"], PRICING["subscriptions"]["free"])
            included = plan["scans_included"]
            acc["scans_used"] += count
            overage = 0
            if included > 0 and acc["scans_used"] > included:
                overage = min(count, acc["scans_used"] - included)
            charge = round(overage * PRICING["per_scan_price"], 2)
            acc["balance"] += charge
            return {"customer_id": customer_id, "plan": acc["plan"],
                    "scans_used": acc["scans_used"], "scans_included": included,
                    "overage_scans": overage, "charge_cny": charge,
                    "balance_cny": round(acc["balance"], 2)}

    # ------------------------------------------------------------------ #
    # 订阅
    # ------------------------------------------------------------------ #
    def subscribe(self, customer_id: str, plan: str,
                   period: str = "monthly") -> Dict[str, Any]:
        """订阅 / 升级套餐。period in {monthly, yearly}。"""
        if plan not in PRICING["subscriptions"]:
            raise ValueError(f"未知套餐: {plan}")
        if period not in ("monthly", "yearly"):
            raise ValueError("period 必须为 monthly 或 yearly")
        with self._lock:
            acc = self._ensure(customer_id)
            price = PRICING["subscriptions"][plan][period]
            inv = self._issue_invoice(customer_id, f"订阅-{plan}-{period}",
                                      price, gateway="alipay")
            acc["plan"] = plan
            acc["period"] = period
            days = 365 if period == "yearly" else 30
            acc["renew_at"] = int(time.time()) + days * 86400
            acc["balance"] = 0.0
            return {"customer_id": customer_id, "plan": plan, "period": period,
                    "price_cny": price, "renew_at": acc["renew_at"],
                    "invoice_id": inv["invoice_id"], "note": "支付接口为预留模拟"}

    # ------------------------------------------------------------------ #
    # 支付接口预留
    # ------------------------------------------------------------------ #
    def pay(self, invoice_id: str, gateway: str = "alipay") -> Dict[str, Any]:
        """发起支付（预留接口，不真实扣款）。"""
        with self._lock:
            inv = self._invoices.get(invoice_id)
            if not inv:
                raise ValueError("账单不存在")
            if inv["status"] == "paid":
                return {"invoice_id": invoice_id, "status": "paid",
                        "message": "该账单已支付"}
            if gateway not in PRICING["payment_gateways"]:
                raise ValueError("不支持的支付渠道（预留）")
            # 模拟：返回一个伪支付链接，直接置为待支付
            inv["gateway"] = gateway
            inv["pay_url"] = f"https://pay.demo/{gateway}/?order={invoice_id}"
            inv["status"] = "pending"
            return {"invoice_id": invoice_id, "gateway": gateway,
                    "status": "pending", "pay_url": inv["pay_url"],
                    "message": "支付接口预留，生产环境对接 Stripe/支付宝沙箱"}

    def confirm_payment(self, invoice_id: str) -> Dict[str, Any]:
        """模拟支付成功回调。"""
        with self._lock:
            inv = self._invoices.get(invoice_id)
            if not inv:
                raise ValueError("账单不存在")
            inv["status"] = "paid"
            inv["paid_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            return {"invoice_id": invoice_id, "status": "paid",
                    "paid_at": inv["paid_at"]}

    # ------------------------------------------------------------------ #
    # 账单
    # ------------------------------------------------------------------ #
    def _issue_invoice(self, customer_id: str, title: str, amount: float,
                       gateway: str = "alipay") -> Dict[str, Any]:
        inv_id = self._next_id("INV")
        inv = {
            "invoice_id": inv_id, "customer_id": customer_id, "title": title,
            "amount_cny": amount, "gateway": gateway, "status": "unpaid",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._invoices[inv_id] = inv
        return inv

    def list_invoices(self, customer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._invoices.values())
            if customer_id:
                out = [i for i in out if i["customer_id"] == customer_id]
            return sorted(out, key=lambda x: x["created_at"], reverse=True)

    def get_invoice(self, invoice_id: str) -> Dict[str, Any]:
        with self._lock:
            inv = self._invoices.get(invoice_id)
            if not inv:
                raise ValueError("账单不存在")
            return inv

    # ------------------------------------------------------------------ #
    # 账户 / 聚合
    # ------------------------------------------------------------------ #
    def account(self, customer_id: str) -> Dict[str, Any]:
        with self._lock:
            acc = self._ensure(customer_id)
            plan = PRICING["subscriptions"].get(acc["plan"])
            return {
                "customer_id": customer_id, "plan": acc["plan"],
                "plan_label": plan["label"] if plan else "free",
                "period": acc["period"], "scans_used": acc["scans_used"],
                "scans_included": plan["scans_included"] if plan else 0,
                "balance_cny": round(acc["balance"], 2),
                "renew_at": acc["renew_at"],
                "renew_at_str": time.strftime("%Y-%m-%d", time.localtime(acc["renew_at"]))
                if acc["renew_at"] else None,
            }

    def pricing(self) -> Dict[str, Any]:
        return PRICING

    def admin_stats(self) -> Dict[str, Any]:
        with self._lock:
            paid = [i for i in self._invoices.values() if i["status"] == "paid"]
            return {
                "accounts": len(self._accounts),
                "invoices": len(self._invoices),
                "paid_invoices": len(paid),
                "revenue_cny": round(sum(i["amount_cny"] for i in paid), 2),
            }


_billing: BillingSystem | None = None


def get_billing_system() -> BillingSystem:
    global _billing
    if _billing is None:
        _billing = BillingSystem()
    return _billing
