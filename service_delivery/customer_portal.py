#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
customer_portal.py — 客户门户。

覆盖：
    - 客户注册/管理（4 级客户分层）
    - 项目查看、报告下载
    - 沟通记录、工单提交（含状态流转）
    - 满意度评价（1~5 星）
    - 发票管理、合同管理、SLA 查看
    - 客户资产台账
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


CUSTOMER_TIERS: Dict[str, Dict[str, Any]] = {
    "strategic": {"name": "战略客户", "color": "#ff4d4f", "discount": 0.85,
                  "service_hours": "7x24", "dedicated_manager": True},
    "enterprise": {"name": "企业客户", "color": "#1890ff", "discount": 0.90,
                   "service_hours": "5x8", "dedicated_manager": True},
    "business": {"name": "商业客户", "color": "#52c41a", "discount": 0.95,
                 "service_hours": "5x8", "dedicated_manager": False},
    "starter": {"name": "入门客户", "color": "#faad14", "discount": 1.00,
                "service_hours": "工单", "dedicated_manager": False},
}

TICKET_STATUSES: List[str] = ["open", "in_progress", "resolved", "closed"]


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class CustomerPortal:
    """客户门户：客户 / 合同 / 发票 / 工单 / 沟通 / 满意度 / 资产。"""

    def __init__(self) -> None:
        self.customers: Dict[str, Dict[str, Any]] = {}
        self.contracts: Dict[str, Dict[str, Any]] = {}
        self.invoices: Dict[str, Dict[str, Any]] = {}
        self.tickets: Dict[str, Dict[str, Any]] = {}
        self.communications: Dict[str, List[Dict[str, Any]]] = {}
        self.satisfaction: Dict[str, List[Dict[str, Any]]] = {}
        self.assets: Dict[str, List[Dict[str, Any]]] = {}
        self._seed()

    def _seed(self) -> None:
        seeds = [
            ("CUS-001", "某股份制银行总行", "strategic", "王主任",
             "wang@bank.com", "010-88880001", "北京"),
            ("CUS-002", "某新能源车企", "enterprise", "李总",
             "li@auto.cn", "021-66660002", "上海"),
            ("CUS-003", "某电商平台", "enterprise", "陈经理",
             "chen@mall.com", "0755-22220003", "深圳"),
            ("CUS-004", "某证券公司", "business", "赵总",
             "zhao@sec.com", "021-55550004", "上海"),
        ]
        for cid, name, tier, contact, email, phone, city in seeds:
            self._create_customer(cid, name, tier, contact, email, phone, city)

    def _create_customer(self, cid: str, name: str, tier: str,
                         contact: str, email: str, phone: str,
                         city: str) -> Dict[str, Any]:
            c = {
                "customer_id": cid, "name": name, "tier": tier,
                "tier_name": CUSTOMER_TIERS.get(tier, {}).get("name", tier),
                "contact": contact, "email": email, "phone": phone,
                "city": city, "status": "active",
                "created_at": _now(), "projects": [],
            }
            self.customers[cid] = c
            # 示例合同
            self.contracts[_uid("CTR")] = {
                "contract_id": _uid("CTR"), "customer_id": cid,
                "title": f"{name}年度安全服务框架协议",
                "amount": 800000.0, "start": "2026-01-01", "end": "2026-12-31",
                "status": "active", "sign_date": "2026-01-05",
            }
            # 示例发票
            self.invoices[_uid("INV")] = {
                "invoice_id": _uid("INV"), "customer_id": cid,
                "title": f"{name}Q3服务费", "amount": 200000.0,
                "tax_rate": 0.06, "status": "paid",
                "issue_date": "2026-09-01", "due_date": "2026-09-30",
            }
            # 示例工单
            self.tickets[_uid("TK")] = {
                "ticket_id": _uid("TK"), "customer_id": cid,
                "subject": "咨询报告加密发送方式", "priority": "medium",
                "status": "open", "created_at": _now(),
                "assignee": "客户经理",
            }
            self.communications[cid] = [
                {"time": _now(), "direction": "out", "channel": "email",
                 "from": "客户经理", "to": contact,
                 "content": "发送项目周报与交付计划"},
            ]
            self.satisfaction[cid] = [
                {"score": 5, "comment": "交付质量稳定", "project_id": "PRJ-001",
                 "time": _now()},
            ]
            self.assets[cid] = [
                {"asset_id": _uid("AST"), "name": "核心业务系统",
                 "type": "application", "criticality": "high",
                 "owner": "科技部"},
                {"asset_id": _uid("AST"), "name": "边界防火墙",
                 "type": "network", "criticality": "medium",
                 "owner": "网络组"},
            ]
            return c

    # ------------------------- 客户 CRUD ------------------------- #
    def register_customer(self, name: str, tier: str, contact: str,
                          email: str, phone: str, city: str) -> Dict[str, Any]:
        cid = _uid("CUS")
        return self._create_customer(cid, name, tier, contact, email, phone, city)

    def list_customers(self, tier: Optional[str] = None,
                       status: Optional[str] = None) -> List[Dict[str, Any]]:
        out = list(self.customers.values())
        if tier:
            out = [c for c in out if c["tier"] == tier]
        if status:
            out = [c for c in out if c["status"] == status]
        return out

    def get_customer(self, cid: str) -> Optional[Dict[str, Any]]:
        return self.customers.get(cid)

    # ------------------------- 合同 / 发票 ------------------------- #
    def list_contracts(self, cid: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.contracts.values())
        if cid:
            items = [x for x in items if x["customer_id"] == cid]
        return items

    def list_invoices(self, cid: Optional[str] = None,
                      status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.invoices.values())
        if cid:
            items = [x for x in items if x["customer_id"] == cid]
        if status:
            items = [x for x in items if x["status"] == status]
        return items

    def create_invoice(self, cid: str, title: str, amount: float,
                       due_date: str) -> Dict[str, Any]:
        inv = {"invoice_id": _uid("INV"), "customer_id": cid,
               "title": title, "amount": amount, "tax_rate": 0.06,
               "status": "unpaid", "issue_date": _now()[:10],
               "due_date": due_date}
        self.invoices[inv["invoice_id"]] = inv
        return inv

    # ------------------------- 工单 ------------------------- #
    def submit_ticket(self, cid: str, subject: str, priority: str = "medium",
                      content: str = "") -> Dict[str, Any]:
        tk = {"ticket_id": _uid("TK"), "customer_id": cid,
              "subject": subject, "priority": priority, "status": "open",
              "content": content, "created_at": _now(), "assignee": None}
        self.tickets[tk["ticket_id"]] = tk
        return tk

    def update_ticket(self, tid: str, status: str,
                      assignee: Optional[str] = None) -> Optional[Dict[str, Any]]:
        tk = self.tickets.get(tid)
        if not tk:
            return None
        if status in TICKET_STATUSES:
            tk["status"] = status
        if assignee:
            tk["assignee"] = assignee
        return tk

    def list_tickets(self, cid: Optional[str] = None,
                     status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.tickets.values())
        if cid:
            items = [x for x in items if x["customer_id"] == cid]
        if status:
            items = [x for x in items if x["status"] == status]
        return items

    # ------------------------- 沟通 / 满意度 / 资产 ------------------------- #
    def log_communication(self, cid: str, direction: str, channel: str,
                          sender: str, receiver: str, content: str) -> Dict[str, Any]:
        rec = {"time": _now(), "direction": direction, "channel": channel,
               "from": sender, "to": receiver, "content": content}
        self.communications.setdefault(cid, []).append(rec)
        return rec

    def get_communications(self, cid: str) -> List[Dict[str, Any]]:
        return self.communications.get(cid, [])

    def add_satisfaction(self, cid: str, score: int, comment: str,
                         project_id: str) -> Dict[str, Any]:
        rec = {"score": max(1, min(5, int(score))), "comment": comment,
               "project_id": project_id, "time": _now()}
        self.satisfaction.setdefault(cid, []).append(rec)
        return rec

    def get_satisfaction(self, cid: Optional[str] = None) -> Dict[str, Any]:
        if cid:
            items = self.satisfaction.get(cid, [])
        else:
            items = [x for arr in self.satisfaction.values() for x in arr]
        avg = round(sum(x["score"] for x in items) / len(items), 2) if items else 0
        return {"average": avg, "count": len(items), "records": items}

    def list_assets(self, cid: str) -> List[Dict[str, Any]]:
        return self.assets.get(cid, [])

    # ------------------------- 客户仪表盘 ------------------------- #
    def customer_dashboard(self) -> Dict[str, Any]:
        customers = list(self.customers.values())
        by_tier: Dict[str, int] = {}
        for c in customers:
            by_tier[c["tier_name"]] = by_tier.get(c["tier_name"], 0) + 1
        unpaid = [i for i in self.invoices.values() if i["status"] == "unpaid"]
        open_tk = [t for t in self.tickets.values() if t["status"] in ("open", "in_progress")]
        sat = self.get_satisfaction()
        return {
            "total_customers": len(customers),
            "by_tier": by_tier,
            "open_tickets": len(open_tk),
            "unpaid_invoices": len(unpaid),
            "unpaid_amount": sum(i["amount"] for i in unpaid),
            "avg_satisfaction": sat["average"],
            "updated_at": _now(),
        }
