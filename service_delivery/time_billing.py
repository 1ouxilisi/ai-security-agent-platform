#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
time_billing.py — 工时与计费。

覆盖：
    - 工时记录（按任务 / 按项目 / 按人员）
    - 5 级人员费率：初级 / 中级 / 高级 / 专家 / 顾问
    - 项目预算、费用跟踪、发票生成、收款管理
    - 利润率分析、报价管理
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


STAFF_RATES: Dict[str, Dict[str, Any]] = {
    "junior": {"name": "初级工程师", "rate_per_hour": 300,
               "color": "#52c41a", "typical_yoe": "0-2 年"},
    "mid": {"name": "中级工程师", "rate_per_hour": 600,
            "color": "#1890ff", "typical_yoe": "2-5 年"},
    "senior": {"name": "高级工程师", "rate_per_hour": 1000,
               "color": "#722ed1", "typical_yoe": "5-8 年"},
    "expert": {"name": "专家", "rate_per_hour": 1800,
               "color": "#fa541c", "typical_yoe": "8-12 年"},
    "consultant": {"name": "顾问", "rate_per_hour": 3000,
                   "color": "#ff4d4f", "typical_yoe": "12 年以上"},
}

BUDGET_STATUS: Dict[str, str] = {
    "under": "预算内",
    "warning": "接近超支",
    "over": "已超支",
}


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class TimeBillingEngine:
    """工时 / 费率 / 预算 / 发票 / 利润率。"""

    def __init__(self) -> None:
        self.timesheets: Dict[str, Dict[str, Any]] = {}
        self.budgets: Dict[str, Dict[str, Any]] = {}
        self.invoices: Dict[str, Dict[str, Any]] = {}
        self.payments: Dict[str, Dict[str, Any]] = {}
        self.quotes: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self) -> None:
        for pid in ("PRJ-DEMO-001", "PRJ-DEMO-002", "PRJ-DEMO-003"):
            self.budgets[pid] = {
                "project_id": pid, "approved": 200000.0,
                "committed": 120000.0, "actual": 68000.0,
                "currency": "CNY", "status": "under",
            }
        # 示例工时
        self.timesheets["TS-001"] = {
            "ts_id": "TS-001", "project_id": "PRJ-DEMO-001",
            "person": "李工", "level": "senior",
            "task": "现场渗透测试", "hours": 16.0,
            "date": "2026-09-12", "note": "工作日晚间",
        }
        self.timesheets["TS-002"] = {
            "ts_id": "TS-002", "project_id": "PRJ-DEMO-001",
            "person": "王工", "level": "mid",
            "task": "报告撰写", "hours": 8.0,
            "date": "2026-09-13", "note": "",
        }

    # ------------------------- 工时 ------------------------- #
    def log_time(self, project_id: str, person: str, level: str,
                 task: str, hours: float, date: str,
                 note: str = "") -> Dict[str, Any]:
        rate = STAFF_RATES.get(level, {}).get("rate_per_hour", 500)
        ts = {"ts_id": _uid("TS"), "project_id": project_id, "person": person,
              "level": level, "task": task, "hours": float(hours),
              "date": date, "note": note, "rate": rate,
              "cost": round(float(hours) * rate, 2), "created_at": _now()}
        self.timesheets[ts["ts_id"]] = ts
        # 更新项目实际成本
        bud = self.budgets.get(project_id)
        if bud:
            bud["actual"] = float(bud.get("actual", 0)) + ts["cost"]
            self._refresh_budget_status(project_id)
        return ts

    def list_timesheets(self, project_id: Optional[str] = None,
                        person: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.timesheets.values())
        if project_id:
            items = [x for x in items if x["project_id"] == project_id]
        if person:
            items = [x for x in items if x["person"] == person]
        return items

    # ------------------------- 预算 ------------------------- #
    def set_budget(self, project_id: str, approved: float,
                   committed: float = 0.0) -> Dict[str, Any]:
        bud = {"project_id": project_id, "approved": float(approved),
               "committed": float(committed),
               "actual": float(self.budgets.get(project_id, {}).get("actual", 0)),
               "currency": "CNY", "status": "under"}
        self.budgets[project_id] = bud
        self._refresh_budget_status(project_id)
        return bud

    def _refresh_budget_status(self, pid: str) -> None:
        b = self.budgets.get(pid)
        if not b:
            return
        ratio = b["actual"] / b["approved"] if b["approved"] else 0
        if ratio >= 1.0:
            b["status"] = "over"
        elif ratio >= 0.85:
            b["status"] = "warning"
        else:
            b["status"] = "under"

    def get_budget(self, pid: str) -> Optional[Dict[str, Any]]:
        return self.budgets.get(pid)

    def list_budgets(self) -> List[Dict[str, Any]]:
        return list(self.budgets.values())

    # ------------------------- 发票 / 收款 ------------------------- #
    def generate_invoice(self, project_id: str, customer_id: str,
                         title: str, amount: float,
                         due_date: str) -> Dict[str, Any]:
        inv = {"invoice_id": _uid("BILL"), "project_id": project_id,
               "customer_id": customer_id, "title": title,
               "amount": float(amount), "tax_rate": 0.06,
               "status": "unpaid", "issue_date": _now()[:10],
               "due_date": due_date, "created_at": _now()}
        self.invoices[inv["invoice_id"]] = inv
        return inv

    def record_payment(self, invoice_id: str, amount: float,
                       method: str = "bank_transfer") -> Optional[Dict[str, Any]]:
        inv = self.invoices.get(invoice_id)
        if not inv:
            return None
        pay = {"payment_id": _uid("PAY"), "invoice_id": invoice_id,
               "amount": float(amount), "method": method,
               "paid_at": _now()}
        self.payments[pay["payment_id"]] = pay
        inv["status"] = "paid"
        inv["paid_amount"] = inv.get("paid_amount", 0) + float(amount)
        return pay

    def list_invoices(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.invoices.values())
        if project_id:
            items = [x for x in items if x["project_id"] == project_id]
        return items

    # ------------------------- 报价 ------------------------- #
    def create_quote(self, customer_id: str, project_type: str,
                    estimated_hours: float, level: str = "senior",
                    margin: float = 0.35) -> Dict[str, Any]:
        rate = STAFF_RATES.get(level, {}).get("rate_per_hour", 1000)
        labor = estimated_hours * rate
        price = round(labor * (1 + margin), 2)
        q = {"quote_id": _uid("Q"), "customer_id": customer_id,
             "project_type": project_type, "estimated_hours": estimated_hours,
             "level": level, "labor_cost": round(labor, 2),
             "margin": margin, "quoted_price": price,
             "status": "draft", "created_at": _now()}
        self.quotes[q["quote_id"]] = q
        return q

    def list_quotes(self) -> List[Dict[str, Any]]:
        return list(self.quotes.values())

    # ------------------------- 利润率分析 ------------------------- #
    def profitability(self) -> Dict[str, Any]:
        per_project: Dict[str, Dict[str, Any]] = {}
        for ts in self.timesheets.values():
            pid = ts["project_id"]
            agg = per_project.setdefault(pid, {"cost": 0.0, "hours": 0.0,
                                               "revenue": 0.0})
            agg["cost"] += ts["cost"]
            agg["hours"] += ts["hours"]
        for inv in self.invoices.values():
            pid = inv.get("project_id")
            if pid:
                agg = per_project.setdefault(pid, {"cost": 0.0, "hours": 0.0,
                                                   "revenue": 0.0})
                agg["revenue"] += inv["amount"]
        rows = []
        for pid, agg in per_project.items():
            profit = agg["revenue"] - agg["cost"]
            margin = round(profit / agg["revenue"], 3) if agg["revenue"] else 0
            rows.append({"project_id": pid, **agg,
                         "gross_profit": round(profit, 2),
                         "margin": margin})
        total_cost = sum(r["cost"] for r in rows)
        total_rev = sum(r["revenue"] for r in rows)
        return {
            "per_project": rows,
            "total_cost": round(total_cost, 2),
            "total_revenue": round(total_rev, 2),
            "total_profit": round(total_rev - total_cost, 2),
            "overall_margin": round((total_rev - total_cost) / total_rev, 3)
                if total_rev else 0,
            "rates": STAFF_RATES,
        }

    def billing_dashboard(self) -> Dict[str, Any]:
        invs = list(self.invoices.values())
        unpaid = [i for i in invs if i["status"] == "unpaid"]
        return {
            "total_invoices": len(invs),
            "unpaid_invoices": len(unpaid),
            "unpaid_amount": round(sum(i["amount"] for i in unpaid), 2),
            "total_logged_hours": round(sum(t["hours"] for t in self.timesheets.values()), 1),
            "active_budgets": len(self.budgets),
            "over_budget_projects": sum(1 for b in self.budgets.values()
                                         if b["status"] == "over"),
            "updated_at": _now(),
        }
