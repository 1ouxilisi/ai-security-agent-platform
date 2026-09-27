# -*- coding: utf-8 -*-
"""product_pricing.py — 产品与定价管理。

产品目录 / 定价策略 / 报价模板 / 合同模板 / 发票 / 收入确认。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from crm_system import DB, now_str, new_id, seed_if_needed


class ProductPricing:
    """产品、定价、模板、发票、收入确认一体化。"""

    # ------------------------------------------------------------------ #
    # 产品目录
    # ------------------------------------------------------------------ #
    def list_products(self, keyword: str = "", category: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.products.values())
        if keyword:
            rows = [r for r in rows if keyword.lower() in r.get("name", "").lower()]
        if category:
            rows = [r for r in rows if r.get("category") == category]
        return rows

    def create_product(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        pid = new_id("prod")
        prod = {
            "id": pid, "name": data.get("name", "新产品"),
            "category": data.get("category", "SaaS产品"),
            "description": data.get("description", ""),
            "price": float(data.get("price", 0)), "currency": "CNY",
            "status": data.get("status", "在售"),
            "pricing_strategy": data.get("pricing_strategy", "标准定价"),
            "specs": dict(data.get("specs", {})),
            "images": list(data.get("images", [])),
            "videos": list(data.get("videos", [])),
            "created_at": now_str(),
        }
        with DB.lock:
            DB.products[pid] = prod
        return prod

    # ------------------------------------------------------------------ #
    # 定价策略
    # ------------------------------------------------------------------ #
    def list_pricing_strategies(self) -> List[Dict[str, Any]]:
        seed_if_needed()
        return list(DB.pricing_strategies)

    def apply_discount(self, base_price: float, strategy: str,
                       qty: int = 1, users: int = 1) -> Dict[str, Any]:
        """根据策略计算折后价。"""
        price = float(base_price)
        discount = 0.0
        note = ""
        if strategy == "年付优惠":
            discount = 0.15
            note = "年付85折"
        elif strategy == "阶梯定价":
            if qty >= 10:
                discount = 0.25
            elif qty >= 5:
                discount = 0.15
            note = f"采购量{qty}"
        elif strategy == "按用户定价":
            if users >= 50:
                discount = 0.2
            elif users >= 20:
                discount = 0.1
            note = f"席位{users}"
        elif strategy == "按量定价":
            discount = 0.0
            note = "按用量结算"
        elif strategy == "自定义定价":
            discount = 0.3
            note = "一单一议"
        final = round(price * (1 - discount), 2)
        return {"base_price": price, "strategy": strategy,
                "discount": discount, "final_price": final, "note": note}

    # ------------------------------------------------------------------ #
    # 模板
    # ------------------------------------------------------------------ #
    def list_quote_templates(self) -> List[Dict[str, Any]]:
        seed_if_needed()
        return list(DB.quote_templates)

    def list_contract_templates(self) -> List[Dict[str, Any]]:
        seed_if_needed()
        return list(DB.contract_templates)

    # ------------------------------------------------------------------ #
    # 发票
    # ------------------------------------------------------------------ #
    def create_invoice(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        iid = new_id("inv")
        inv = {
            "id": iid, "number": f"INV-{time_short()}-{iid[-6:]}",
            "customer_id": data.get("customer_id", ""),
            "order_id": data.get("order_id", ""),
            "type": data.get("type", "增值税专用发票"),
            "title": data.get("title", ""),
            "tax_number": data.get("tax_number", ""),
            "amount": float(data.get("amount", 0)),
            "status": "待开具",
            "mail_address": data.get("mail_address", ""),
            "items": list(data.get("items", [])),
            "history": [{"time": now_str(), "event": "创建"}],
            "created_at": now_str(),
        }
        with DB.lock:
            DB.invoices[iid] = inv
        return inv

    def list_invoices(self, customer_id: str = "", status: str = "") -> List[Dict[str, Any]]:
        seed_if_needed()
        with DB.lock:
            rows = list(DB.invoices.values())
        if customer_id:
            rows = [r for r in rows if r.get("customer_id") == customer_id]
        if status:
            rows = [r for r in rows if r.get("status") == status]
        return rows

    def update_invoice_status(self, iid: str, status: str) -> Optional[Dict[str, Any]]:
        with DB.lock:
            inv = DB.invoices.get(iid)
            if not inv:
                return None
            inv["status"] = status
            inv["history"].append({"time": now_str(), "event": f"状态->{status}"})
            return inv

    # ------------------------------------------------------------------ #
    # 收入确认
    # ------------------------------------------------------------------ #
    def recognize_revenue(self, data: Dict[str, Any]) -> Dict[str, Any]:
        seed_if_needed()
        rec = {
            "id": new_id("rev"),
            "customer_id": data.get("customer_id", ""),
            "order_id": data.get("order_id", ""),
            "type": data.get("type", "新购"),
            "amount": float(data.get("amount", 0)),
            "recognize_time": data.get("recognize_time", now_str()),
            "installments": int(data.get("installments", 1)),
            "is_refund": bool(data.get("is_refund", False)),
            "created_at": now_str(),
        }
        with DB.lock:
            DB.revenue_records.append(rec)
        return rec

    def revenue_summary(self) -> Dict[str, Any]:
        rows = list(DB.revenue_records)
        # 若尚无确认收入，用订单金额模拟
        if not rows:
            with DB.lock:
                orders = list(DB.orders.values())
            total = sum(float(o.get("amount", 0)) for o in orders if o.get("pay_status") == "已支付")
            return {
                "total_revenue": round(total, 2),
                "new_sales": round(total, 2),
                "renewal": 0.0, "expansion": 0.0, "refund": 0.0,
                "gross_margin": 0.62,
                "records": [],
            }
        new = sum(r["amount"] for r in rows if r["type"] == "新购" and not r["is_refund"])
        renewal = sum(r["amount"] for r in rows if r["type"] == "续费" and not r["is_refund"])
        expansion = sum(r["amount"] for r in rows if r["type"] == "增购" and not r["is_refund"])
        refund = sum(r["amount"] for r in rows if r["is_refund"])
        total = new + renewal + expansion - refund
        return {
            "total_revenue": round(total, 2),
            "new_sales": round(new, 2),
            "renewal": round(renewal, 2),
            "expansion": round(expansion, 2),
            "refund": round(refund, 2),
            "gross_margin": 0.62,
            "records": rows[-50:],
        }


def time_short() -> str:
    return now_str()[:10].replace("-", "")


pricing = ProductPricing()

__all__ = ["ProductPricing", "pricing"]
