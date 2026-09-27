#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_ultra_pro/customer_management.py — 客户管理。

- 客户档案：基本信息/等级/来源/状态/标签/备注
- 合同管理：CRUD/附件/到期提醒/续签/统计
- 账单管理：生成/明细/支付关联/逾期提醒/统计
- 发票管理：申请/开具/作废/附件/邮寄/统计
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional


LEVELS = ["普通", "重要", "战略", "VIP"]
SOURCES = ["官网", "销售", "推荐", "活动"]
STATUSES = ["潜在", "试用", "活跃", "流失"]
CONTRACT_TYPES = ["年框", "项目制", "订阅", "试用"]
INVOICE_TYPES = ["增值税普通发票", "增值税专用发票", "电子普通发票"]


class CustomerManager:
    """客户管理（内存存储）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._customers: Dict[str, Dict[str, Any]] = {}
        self._contracts: Dict[str, Dict[str, Any]] = {}
        self._bills: Dict[str, Dict[str, Any]] = {}
        self._invoices: Dict[str, Dict[str, Any]] = {}
        self._seq = 0

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}{time.strftime('%Y%m%d')}-{self._seq:05d}"

    def _now(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    # ================================================================== #
    # 客户档案
    # ================================================================== #
    def create_customer(self, name: str, contact: str = "", phone: str = "",
                         email: str = "", address: str = "", industry: str = "",
                         scale: str = "", level: str = "普通",
                         source: str = "官网", status: str = "潜在",
                         tags: Optional[List[str]] = None,
                         note: str = "") -> Dict[str, Any]:
        if level not in LEVELS:
            raise ValueError(f"等级必须为 {LEVELS}")
        if source not in SOURCES:
            raise ValueError(f"来源必须为 {SOURCES}")
        if status not in STATUSES:
            raise ValueError(f"状态必须为 {STATUSES}")
        with self._lock:
            cid = self._next_id("CUS")
            cust = {
                "customer_id": cid, "name": name, "contact": contact,
                "phone": phone, "email": email, "address": address,
                "industry": industry, "scale": scale, "level": level,
                "source": source, "status": status,
                "tags": tags or [], "note": note,
                "created_at": self._now(),
            }
            self._customers[cid] = cust
            return cust

    def update_customer(self, customer_id: str, **fields: Any) -> Dict[str, Any]:
        with self._lock:
            c = self._customers.get(customer_id)
            if not c:
                raise ValueError("客户不存在")
            for k, v in fields.items():
                if v is not None and k in ("name", "contact", "phone", "email",
                                            "address", "industry", "scale", "level",
                                            "source", "status", "note"):
                    c[k] = v
                elif k == "tags" and isinstance(v, list):
                    c["tags"] = v
            return c

    def get_customer(self, customer_id: str) -> Dict[str, Any]:
        with self._lock:
            c = self._customers.get(customer_id)
            if not c:
                raise ValueError("客户不存在")
            return c

    def list_customers(self, level: Optional[str] = None,
                        status: Optional[str] = None,
                        source: Optional[str] = None,
                        keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._customers.values())
            if level:
                out = [c for c in out if c["level"] == level]
            if status:
                out = [c for c in out if c["status"] == status]
            if source:
                out = [c for c in out if c["source"] == source]
            if keyword:
                out = [c for c in out if keyword in c["name"]
                        or keyword in c.get("contact", "")]
            return sorted(out, key=lambda x: x["created_at"], reverse=True)

    def delete_customer(self, customer_id: str) -> bool:
        with self._lock:
            if customer_id in self._customers:
                del self._customers[customer_id]
                return True
            return False

    # ================================================================== #
    # 合同管理
    # ================================================================== #
    def create_contract(self, customer_id: str, name: str, ctype: str = "年框",
                         amount: float = 0.0, start_date: str = "",
                         end_date: str = "", attach: str = "",
                         note: str = "") -> Dict[str, Any]:
        if ctype not in CONTRACT_TYPES:
            raise ValueError(f"合同类型必须为 {CONTRACT_TYPES}")
        with self._lock:
            if customer_id not in self._customers:
                raise ValueError("客户不存在")
            contract_id = self._next_id("HT")
            c = {
                "contract_id": contract_id, "customer_id": customer_id,
                "name": name, "type": ctype, "amount": round(float(amount), 2),
                "start_date": start_date, "end_date": end_date,
                "status": "生效中", "attach": attach, "note": note,
                "created_at": self._now(),
            }
            self._contracts[contract_id] = c
            return c

    def renew_contract(self, contract_id: str, new_end_date: str,
                        new_amount: Optional[float] = None) -> Dict[str, Any]:
        with self._lock:
            c = self._contracts.get(contract_id)
            if not c:
                raise ValueError("合同不存在")
            c["end_date"] = new_end_date
            if new_amount is not None:
                c["amount"] = round(float(new_amount), 2)
            c["status"] = "已续签"
            return c

    def list_contracts(self, customer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._contracts.values())
            if customer_id:
                out = [c for c in out if c["customer_id"] == customer_id]
            return sorted(out, key=lambda x: x["created_at"], reverse=True)

    def contract_expiry_reminders(self, within_days: int = 30) -> List[Dict[str, Any]]:
        """合同到期提醒。"""
        out = []
        today = time.strftime("%Y-%m-%d")
        with self._lock:
            for c in self._contracts.values():
                if c["end_date"] and c["end_date"] >= today:
                    # 简单日期比较（YYYY-MM-DD 可字典序）
                    days = self._days_between(today, c["end_date"])
                    if 0 <= days <= within_days:
                        out.append({"contract_id": c["contract_id"],
                                    "customer_id": c["customer_id"],
                                    "name": c["name"], "days_left": days,
                                    "end_date": c["end_date"]})
        return sorted(out, key=lambda x: x["days_left"])

    @staticmethod
    def _days_between(a: str, b: str) -> int:
        from datetime import datetime
        try:
            da = datetime.strptime(a, "%Y-%m-%d")
            db = datetime.strptime(b, "%Y-%m-%d")
            return (db - da).days
        except ValueError:
            return -1

    # ================================================================== #
    # 账单管理
    # ================================================================== #
    def generate_bill(self, customer_id: str, period: str = "",
                      items: Optional[List[Dict[str, Any]]] = None,
                      note: str = "") -> Dict[str, Any]:
        """items: [{'name','qty','price'}]，自动计算金额。"""
        with self._lock:
            if customer_id not in self._customers:
                raise ValueError("客户不存在")
            items = items or []
            detail = []
            total = 0.0
            for it in items:
                qty = float(it.get("qty", 1))
                price = float(it.get("price", 0))
                amt = round(qty * price, 2)
                total += amt
                detail.append({"name": it.get("name", ""), "qty": qty,
                               "price": price, "amount": amt})
            bill_id = self._next_id("BILL")
            bill = {
                "bill_id": bill_id, "customer_id": customer_id,
                "period": period or time.strftime("%Y-%m"),
                "items": detail, "amount": round(total, 2),
                "status": "unpaid", "pay_order_id": "",
                "overdue": False, "note": note,
                "created_at": self._now(),
            }
            self._bills[bill_id] = bill
            return bill

    def pay_bill(self, bill_id: str, pay_order_id: str = "") -> Dict[str, Any]:
        with self._lock:
            b = self._bills.get(bill_id)
            if not b:
                raise ValueError("账单不存在")
            b["status"] = "paid"
            b["pay_order_id"] = pay_order_id
            b["paid_at"] = self._now()
            return b

    def list_bills(self, customer_id: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._bills.values())
            if customer_id:
                out = [b for b in out if b["customer_id"] == customer_id]
            if status:
                out = [b for b in out if b["status"] == status]
            return sorted(out, key=lambda x: x["created_at"], reverse=True)

    def overdue_reminders(self) -> List[Dict[str, Any]]:
        """逾期账单提醒（内存：status=unpaid 且创建超过 30 天视为逾期）。"""
        out = []
        with self._lock:
            for b in self._bills.values():
                if b["status"] == "unpaid":
                    b["overdue"] = True
                    out.append({"bill_id": b["bill_id"],
                                "customer_id": b["customer_id"],
                                "amount": b["amount"], "period": b["period"]})
        return out

    # ================================================================== #
    # 发票管理
    # ================================================================== #
    def apply_invoice(self, customer_id: str, invoice_type: str = "增值税普通发票",
                       title: str = "", tax_no: str = "",
                       amount: float = 0.0) -> Dict[str, Any]:
        if invoice_type not in INVOICE_TYPES:
            raise ValueError(f"发票类型必须为 {INVOICE_TYPES}")
        with self._lock:
            if customer_id not in self._customers:
                raise ValueError("客户不存在")
            inv_id = self._next_id("INV")
            inv = {
                "invoice_id": inv_id, "customer_id": customer_id,
                "type": invoice_type, "title": title, "tax_no": tax_no,
                "amount": round(float(amount), 2), "status": "待开具",
                "pdf_attach": "", "mail_status": "未邮寄",
                "created_at": self._now(),
            }
            self._invoices[inv_id] = inv
            return inv

    def issue_invoice(self, invoice_id: str, pdf_attach: str = "") -> Dict[str, Any]:
        with self._lock:
            inv = self._invoices.get(invoice_id)
            if not inv:
                raise ValueError("发票不存在")
            inv["status"] = "已开具"
            inv["pdf_attach"] = pdf_attach or f"/invoices/{invoice_id}.pdf"
            inv["issued_at"] = self._now()
            return inv

    def void_invoice(self, invoice_id: str) -> Dict[str, Any]:
        with self._lock:
            inv = self._invoices.get(invoice_id)
            if not inv:
                raise ValueError("发票不存在")
            inv["status"] = "已作废"
            inv["voided_at"] = self._now()
            return inv

    def mail_invoice(self, invoice_id: str, address: str = "") -> Dict[str, Any]:
        with self._lock:
            inv = self._invoices.get(invoice_id)
            if not inv:
                raise ValueError("发票不存在")
            inv["mail_status"] = "已邮寄" if address else "待邮寄地址"
            inv["mail_address"] = address
            return inv

    def list_invoices(self, customer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            out = list(self._invoices.values())
            if customer_id:
                out = [i for i in out if i["customer_id"] == customer_id]
            return sorted(out, key=lambda x: x["created_at"], reverse=True)

    # ================================================================== #
    # 统计
    # ================================================================== #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_level: Dict[str, int] = {}
            by_status: Dict[str, int] = {}
            for c in self._customers.values():
                by_level[c["level"]] = by_level.get(c["level"], 0) + 1
                by_status[c["status"]] = by_status.get(c["status"], 0) + 1
            contract_amount = sum(c["amount"] for c in self._contracts.values())
            bill_amount = sum(b["amount"] for b in self._bills.values()
                              if b["status"] == "paid")
            inv_amount = sum(i["amount"] for i in self._invoices.values()
                             if i["status"] == "已开具")
            return {
                "customers": len(self._customers),
                "by_level": by_level, "by_status": by_status,
                "contracts": len(self._contracts),
                "contract_amount": round(contract_amount, 2),
                "bills": len(self._bills),
                "paid_bill_amount": round(bill_amount, 2),
                "invoices": len(self._invoices),
                "issued_invoice_amount": round(inv_amount, 2),
                "contract_expiring": len(self.contract_expiry_reminders()),
                "overdue_bills": len(self.overdue_reminders()),
            }


_cust_mgr: CustomerManager | None = None


def get_customer_manager() -> CustomerManager:
    global _cust_mgr
    if _cust_mgr is None:
        _cust_mgr = CustomerManager()
    return _cust_mgr
