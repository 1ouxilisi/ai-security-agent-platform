#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
commercial_ultra_pro/admin_dashboard.py — 商业管理后台仪表盘聚合。

聚合：收入/客户/订单/工单/SLA/系统状态/API/租户。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from commercial_ultra_pro.payment_system import get_payment_system
from commercial_ultra_pro.subscription_management import get_subscription_manager
from commercial_ultra_pro.customer_management import get_customer_manager
from commercial_ultra_pro.sla_monitor import get_sla_monitor
from commercial_ultra_pro.ticket_system import get_ticket_system
from commercial_ultra_pro.api_billing import get_api_billing
from commercial_ultra_pro.multi_tenant import get_multi_tenant


class AdminDashboard:
    """商业管理后台仪表盘（聚合各子系统）。"""

    def overview(self) -> Dict[str, Any]:
        pay = get_payment_system().stats()
        sub = get_subscription_manager().stats()
        cust = get_customer_manager().stats()
        sla = get_sla_monitor().dashboard()
        ticket = get_ticket_system().stats()
        api = get_api_billing().stats()
        tenant = get_multi_tenant().stats()
        revenue = pay["total_amount"] + api["total_bill_amount"]
        return {
            "revenue": {
                "total": round(revenue, 2),
                "payments": pay["total_amount"],
                "api_billing": api["total_bill_amount"],
            },
            "customers": cust,
            "payments": pay,
            "subscriptions": sub,
            "tickets": {
                "total": ticket["total"],
                "open": ticket["by_status"].get("处理中", 0)
                         + ticket["by_status"].get("新建", 0),
                "sla_rate": ticket["sla_rate"],
                "avg_rating": ticket["avg_rating"],
            },
            "sla": {
                "services": sla["services"],
                "incidents_open": sla["incidents_open"],
                "alerts_unacked": sla["alerts_unacked"],
                "availability": sla["availability"],
            },
            "api": api,
            "tenants": tenant,
        }

    def revenue_detail(self) -> Dict[str, Any]:
        pay = get_payment_system().stats()
        api = get_api_billing().stats()
        return {
            "payment": {
                "total_amount": pay["total_amount"],
                "orders": pay["total_orders"],
                "success_rate": pay["success_rate"],
                "by_channel": pay["by_channel"],
            },
            "api_billing": {
                "bills": api["bills"],
                "total_amount": api["total_bill_amount"],
                "calls": api["total_calls"],
            },
            "refunds": pay["refund_amount"],
        }

    def customer_view(self) -> Dict[str, Any]:
        return get_customer_manager().stats()

    def sla_view(self) -> Dict[str, Any]:
        return get_sla_monitor().sla_report()

    def ticket_view(self) -> Dict[str, Any]:
        return get_ticket_system().stats()

    def tenant_view(self) -> Dict[str, Any]:
        return get_multi_tenant().stats()

    def system_health(self) -> Dict[str, Any]:
        return {
            "now": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
            "modules": {
                "payment_system": "loaded",
                "subscription_management": "loaded",
                "customer_management": "loaded",
                "sla_monitor": "loaded",
                "ticket_system": "loaded",
                "api_billing": "loaded",
                "multi_tenant": "loaded",
            },
            "storage": "in-memory dict",
        }


_dash: AdminDashboard | None = None


def get_admin_dashboard() -> AdminDashboard:
    global _dash
    if _dash is None:
        _dash = AdminDashboard()
    return _dash
