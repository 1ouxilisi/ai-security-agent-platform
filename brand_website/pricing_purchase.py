# -*- coding: utf-8 -*-
"""
brand_website/pricing_purchase.py — 定价与购买模块。

覆盖：定价页面、购买流程、支付集成、优惠券、免费试用、企业定制。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _pid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


PRICING_PLANS: Dict[str, Dict[str, Any]] = {}
ORDERS: Dict[str, Dict[str, Any]] = {}
PAYMENT_RECORDS: Dict[str, Dict[str, Any]] = {}
COUPONS: Dict[str, Dict[str, Any]] = {}
TRIALS: Dict[str, Dict[str, Any]] = {}
CUSTOM_ENT: Dict[str, Dict[str, Any]] = {}


def _seed() -> None:
    if not PRICING_PLANS:
        PRICING_PLANS["free"] = {"id": "free", "name": "社区版",
                                 "monthly": 0, "quarterly": 0, "yearly": 0,
                                 "per_user": 0, "modules": ["基础扫描"]}
        PRICING_PLANS["pro"] = {"id": "pro", "name": "专业版",
                                "monthly": 2999, "quarterly": 8397, "yearly": 28790,
                                "per_user": 99, "modules": ["全部功能模块"]}
        PRICING_PLANS["ent"] = {"id": "ent", "name": "企业版",
                                "monthly": 19999, "quarterly": 55997, "yearly": 191990,
                                "per_user": 0, "modules": ["全部功能", "定制开发", "专属支持"]}
    if not COUPONS:
        COUPONS["WELCOME2026"] = {
            "code": "WELCOME2026", "type": "percentage", "value": 0.10,
            "min_amount": 1000, "expire": "2026-12-31",
            "max_uses": 1000, "used": 128, "status": "active",
        }
        COUPONS["NEWUSER50"] = {
            "code": "NEWUSER50", "type": "fixed", "value": 50,
            "min_amount": 0, "expire": "2026-10-01",
            "max_uses": 500, "used": 301, "status": "active",
        }


_seed()


class PricingPurchase:
    # ---- 定价页面 ----
    def list_plans(self) -> List[Dict[str, Any]]:
        return list(PRICING_PLANS.values())

    def plan_detail(self, pid: str) -> Optional[Dict[str, Any]]:
        return PRICING_PLANS.get(pid)

    # ---- 购买流程 ----
    def create_order(self, plan_id: str, period: str = "yearly",
                     users: int = 1, coupon: str = "",
                     contact: str = "") -> Dict[str, Any]:
        plan = PRICING_PLANS.get(plan_id)
        if not plan:
            return {"error": "套餐不存在"}
        base = plan.get(period, plan["monthly"]) * users if plan["per_user"] else plan.get(period, plan["monthly"])
        discount = 0.0
        cp = COUPONS.get(coupon)
        if cp and cp["status"] == "active" and base >= cp["min_amount"]:
            if cp["type"] == "percentage":
                discount = base * cp["value"]
            else:
                discount = min(cp["value"], base)
        total = max(0, base - discount)
        oid = _pid("ord")
        order = {
            "id": oid, "plan": plan_id, "period": period, "users": users,
            "coupon": coupon, "base": base, "discount": discount,
            "total": total, "status": "待支付", "contact": contact,
            "created_at": _now(),
        }
        ORDERS[oid] = order
        return order

    def confirm_pay(self, order_id: str, channel: str = "alipay") -> Dict[str, Any]:
        o = ORDERS.get(order_id)
        if not o:
            return {"error": "订单不存在"}
        o["status"] = "已支付"
        o["paid_at"] = _now()
        rid = _pid("pay")
        PAYMENT_RECORDS[rid] = {
            "id": rid, "order_id": order_id, "channel": channel,
            "amount": o["total"], "status": "成功", "paid_at": _now(),
            "invoice_status": "未申请",
        }
        return {"order": o, "payment": PAYMENT_RECORDS[rid]}

    def list_orders(self) -> List[Dict[str, Any]]:
        return sorted(ORDERS.values(), key=lambda x: x["created_at"], reverse=True)

    def payment_records(self) -> List[Dict[str, Any]]:
        return list(PAYMENT_RECORDS.values())

    def refund(self, record_id: str, reason: str = "") -> Dict[str, Any]:
        r = PAYMENT_RECORDS.get(record_id)
        if not r:
            return {"error": "支付记录不存在"}
        r["status"] = "已退款"
        r["refund_reason"] = reason
        r["refunded_at"] = _now()
        return r

    # ---- 优惠券 ----
    def list_coupons(self) -> List[Dict[str, Any]]:
        return list(COUPONS.values())

    def create_coupon(self, code: str, ctype: str, value: float,
                      min_amount: float = 0, expire: str = "",
                      max_uses: int = 100) -> Dict[str, Any]:
        COUPONS[code] = {
            "code": code, "type": ctype, "value": value,
            "min_amount": min_amount, "expire": expire or "2026-12-31",
            "max_uses": max_uses, "used": 0, "status": "active",
            "created_at": _now(),
        }
        return COUPONS[code]

    def batch_generate(self, prefix: str, count: int = 10,
                       value: float = 50) -> List[str]:
        codes = []
        for _ in range(count):
            code = f"{prefix}_{uuid.uuid4().hex[:6].upper()}"
            self.create_coupon(code, "fixed", value)
            codes.append(code)
        return codes

    # ---- 免费试用 ----
    def apply_trial(self, plan_id: str, contact: str,
                    days: int = 14) -> Dict[str, Any]:
        tid = _pid("trial")
        license_key = f"TRIAL-{uuid.uuid4().hex[:16].upper()}"
        trial = {
            "id": tid, "license": license_key, "plan": plan_id,
            "contact": contact, "days": days,
            "started_at": _now(), "status": "试用中",
            "features": ["全功能体验", "技术支持响应"],
        }
        TRIALS[tid] = trial
        return trial

    def list_trials(self) -> List[Dict[str, Any]]:
        return list(TRIALS.values())

    def trial_stats(self) -> Dict[str, Any]:
        items = list(TRIALS.values())
        converting = [t for t in items if t["status"] == "已转化"]
        return {
            "total": len(items),
            "active": len([t for t in items if t["status"] == "试用中"]),
            "converted": len(converting),
            "conversion_rate": round(len(converting) / max(1, len(items)) * 100, 1),
        }

    # ---- 企业定制 ----
    def custom_request(self, company: str, requirements: str,
                       budget: str = "", contact: str = "") -> Dict[str, Any]:
        cid = _pid("ent")
        CUSTOM_ENT[cid] = {
            "id": cid, "company": company, "requirements": requirements,
            "budget": budget, "contact": contact,
            "status": "需求收集", "quote": "", "contract": "",
            "deliverable": "", "created_at": _now(),
        }
        return CUSTOM_ENT[cid]

    def list_custom(self) -> List[Dict[str, Any]]:
        return list(CUSTOM_ENT.values())

    def quote_custom(self, cid: str, amount: str,
                     scope: str = "") -> Optional[Dict[str, Any]]:
        c = CUSTOM_ENT.get(cid)
        if not c:
            return None
        c["status"] = "已报价"
        c["quote"] = amount
        c["scope"] = scope
        return c
