# -*- coding: utf-8 -*-
"""
commercial_ultra/billing_system_pro.py — 计费系统 Pro（商业产品体验极致）。

- 按扫描次数计费（按量）
- 按月 / 按年订阅（套餐）
- 支付接口预留（Stripe / 支付宝，仅模拟下单）
- 账单管理（发票 / 账单）
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional


PLANS = {
    "free": {"name": "免费版", "monthly": 0, "yearly": 0, "scans_included": 50,
             "overage_price": 0.0},
    "pro": {"name": "专业版", "monthly": 299, "yearly": 2870,
            "scans_included": 5000, "overage_price": 0.5},
    "enterprise": {"name": "企业版", "monthly": 999, "yearly": 9590,
                   "scans_included": 100000, "overage_price": 0.2},
}

GATEWAYS = ["stripe", "alipay"]


class BillingSystemPro:
    """计费系统 Pro（全内存模拟）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._accounts: Dict[str, Dict[str, Any]] = {}
        self._invoices: Dict[str, Dict[str, Any]] = {}
        self._seq = 0
        self._ensure("C-DEMO-00001", plan="pro", period="monthly")

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{int(time.time()) % 100000:05d}{self._seq:03d}"

    def _ensure(self, customer_id: str, plan: str = "free",
                period: str = "monthly") -> Dict[str, Any]:
        if customer_id not in self._accounts:
            self._accounts[customer_id] = {
                "customer_id": customer_id, "plan": plan, "period": period,
                "scans_used": 0, "status": "active",
                "since": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        return self._accounts[customer_id]

    # ------------------------------------------------------------------ #
    # 定价
    # ------------------------------------------------------------------ #
    def pricing(self) -> Dict[str, Any]:
        return {"plans": PLANS, "gateways": GATEWAYS,
                "currency": "CNY", "note": "年付约 8 折；超额按次计费"}

    # ------------------------------------------------------------------ #
    # 按扫描次数计费
    # ------------------------------------------------------------------ #
    def record_scan(self, customer_id: str, count: int = 1) -> Dict[str, Any]:
        with self._lock:
            acc = self._ensure(customer_id)
            acc["scans_used"] += count
            plan = PLANS.get(acc["plan"], PLANS["free"])
            included = plan["scans_included"]
            overage = max(0, acc["scans_used"] - included)
            overage_fee = round(overage * plan["overage_price"], 2)
            return {"customer_id": customer_id, "scans_used": acc["scans_used"],
                    "included": included, "overage": overage,
                    "overage_fee": overage_fee, "plan": acc["plan"]}

    # ------------------------------------------------------------------ #
    # 订阅
    # ------------------------------------------------------------------ #
    def subscribe(self, customer_id: str, plan: str = "pro",
                  period: str = "monthly") -> Dict[str, Any]:
        if plan not in PLANS:
            raise ValueError(f"未知套餐: {plan}")
        if period not in ("monthly", "yearly"):
            raise ValueError("period 只能是 monthly / yearly")
        with self._lock:
            acc = self._ensure(customer_id)
            acc["plan"] = plan
            acc["period"] = period
            acc["status"] = "active"
            price = PLANS[plan][period]
            inv_id = self._next_id("INV")
            self._invoices[inv_id] = {
                "invoice_id": inv_id, "customer_id": customer_id,
                "type": "subscription", "plan": plan, "period": period,
                "amount": price, "currency": "CNY", "status": "unpaid",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            return {"customer_id": customer_id, "plan": plan, "period": period,
                    "amount_due": price, "invoice_id": inv_id,
                    "message": "已生成账单，请前往支付"}

    # ------------------------------------------------------------------ #
    # 支付（接口预留：Stripe / 支付宝）
    # ------------------------------------------------------------------ #
    def pay(self, invoice_id: str, gateway: str = "alipay") -> Dict[str, Any]:
        if gateway not in GATEWAYS:
            raise ValueError(f"暂不支持的支付渠道: {gateway}（预留: {GATEWAYS}）")
        with self._lock:
            inv = self._invoices.get(invoice_id)
            if not inv:
                raise ValueError("账单不存在")
            if inv["status"] == "paid":
                return {"invoice_id": invoice_id, "already_paid": True,
                        "pay_url": None}
            # 模拟第三方收银台下单（预留真实对接）
            pay_token = self._next_id("PAY")
            inv["pay_token"] = pay_token
            inv["gateway"] = gateway
            return {"invoice_id": invoice_id, "gateway": gateway,
                    "pay_token": pay_token,
                    "pay_url": f"https://pay.{gateway}.example/checkout/{pay_token}",
                    "status": "pending"}

    def confirm_payment(self, invoice_id: str) -> Dict[str, Any]:
        with self._lock:
            inv = self._invoices.get(invoice_id)
            if not inv:
                raise ValueError("账单不存在")
            inv["status"] = "paid"
            inv["paid_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            # 开票
            inv_id_invoice = self._next_id("BILL")
            inv["billing_id"] = inv_id_invoice
            return {"invoice_id": invoice_id, "status": "paid",
                    "billing_id": inv_id_invoice,
                    "message": "支付成功，已开具电子发票"}

    # ------------------------------------------------------------------ #
    # 账单 / 发票管理
    # ------------------------------------------------------------------ #
    def list_invoices(self, customer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._invoices.values())
            if customer_id:
                items = [i for i in items if i["customer_id"] == customer_id]
            return sorted(items, key=lambda x: x["created_at"], reverse=True)

    def get_invoice(self, invoice_id: str) -> Dict[str, Any]:
        with self._lock:
            inv = self._invoices.get(invoice_id)
            if not inv:
                raise ValueError("账单不存在")
            return inv

    def account(self, customer_id: str) -> Dict[str, Any]:
        with self._lock:
            acc = self._ensure(customer_id)
            invs = [i for i in self._invoices.values()
                    if i["customer_id"] == customer_id]
            paid = sum(i["amount"] for i in invs if i["status"] == "paid")
            return {"account": acc, "invoices_total": len(invs),
                    "paid_amount": round(paid, 2), "currency": "CNY"}

    def admin_stats(self) -> Dict[str, Any]:
        with self._lock:
            paid = [i for i in self._invoices.values() if i["status"] == "paid"]
            return {"customers": len(self._accounts),
                    "invoices": len(self._invoices),
                    "paid_invoices": len(paid),
                    "mrr_est": round(sum(i["amount"] for i in paid
                                         if i["period"] == "monthly"), 2)}


_billing: BillingSystemPro | None = None


def get_billing_system_pro() -> BillingSystemPro:
    global _billing
    if _billing is None:
        _billing = BillingSystemPro()
    return _billing
