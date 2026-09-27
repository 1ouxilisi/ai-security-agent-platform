# -*- coding: utf-8 -*-
"""usage_billing.py — 用量与计费。

能力：
- API 调用统计、用量分析、配额
- 速率限制、套餐管理、计费规则、用量告警
- 账单生成、支付集成（模拟）、免费额度
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


PLANS: List[Dict[str, Any]] = [
    {
        "plan_id": "free",
        "name": "免费版",
        "price_per_month": 0.0,
        "quota_calls_month": 1000,
        "rate_limit_per_min": 30,
        "features": ["社区支持", "1 个应用", "基础扫描"],
    },
    {
        "plan_id": "pro",
        "name": "专业版",
        "price_per_month": 99.0,
        "quota_calls_month": 100000,
        "rate_limit_per_min": 300,
        "features": ["邮件支持", "10 个应用", "全部扫描模块", "Sandbox"],
    },
    {
        "plan_id": "enterprise",
        "name": "企业版",
        "price_per_month": 999.0,
        "quota_calls_month": 5000000,
        "rate_limit_per_min": 5000,
        "features": ["专属经理", "无限应用", "SLA 99.9%", "VPC 部署"],
    },
]


PRICING_RULES: List[Dict[str, Any]] = [
    {"meter": "scanner.start", "unit_price": 0.05, "unit": "次"},
    {"meter": "report.export", "unit_price": 0.20, "unit": "份"},
    {"meter": "intel.ioc", "unit_price": 0.001, "unit": "次"},
    {"meter": "asset.write", "unit_price": 0.005, "unit": "次"},
]


class UsageBilling:
    """用量与计费。"""

    def __init__(self) -> None:
        self.usage: Dict[str, Dict[str, Any]] = {}      # app_id -> 用量
        self.bills: Dict[str, Dict[str, Any]] = {}      # bill_id -> 账单
        self.alarms: List[Dict[str, Any]] = []
        self.subscriptions: Dict[str, str] = {}         # app_id -> plan_id

    # ------------------------------------------------------------------ #
    # 用量
    # ------------------------------------------------------------------ #
    def record_call(self, app_id: str, meter: str, cost_units: int = 1) -> Dict[str, Any]:
        u = self.usage.setdefault(app_id, {
            "app_id": app_id,
            "calls_total": 0,
            "calls_today": 0,
            "by_meter": {},
            "billed_amount": 0.0,
            "last_call_at": None,
        })
        u["calls_total"] += cost_units
        u["calls_today"] += cost_units
        u["by_meter"][meter] = u["by_meter"].get(meter, 0) + cost_units
        rule = next((r for r in PRICING_RULES if r["meter"] == meter), None)
        if rule:
            u["billed_amount"] += round(rule["unit_price"] * cost_units, 4)
        u["last_call_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        # 简单告警：超过 80% 配额
        plan = self.subscriptions.get(app_id, "free")
        plan_obj = next((p for p in PLANS if p["plan_id"] == plan), PLANS[0])
        if u["calls_total"] >= plan_obj["quota_calls_month"] * 0.8:
            self.alarms.append({
                "alarm_id": "al_" + uuid.uuid4().hex[:8],
                "app_id": app_id,
                "level": "warning",
                "message": f"已使用本月配额 {u['calls_total']}/{plan_obj['quota_calls_month']}",
                "at": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
        return u

    def get_usage(self, app_id: str) -> Dict[str, Any]:
        u = self.usage.get(app_id, {
            "app_id": app_id, "calls_total": 0, "calls_today": 0,
            "by_meter": {}, "billed_amount": 0.0,
        })
        plan = self.subscriptions.get(app_id, "free")
        plan_obj = next((p for p in PLANS if p["plan_id"] == plan), PLANS[0])
        return {
            **u,
            "plan": plan,
            "quota_month": plan_obj["quota_calls_month"],
            "quota_used_pct": round(
                u.get("calls_total", 0) / max(plan_obj["quota_calls_month"], 1) * 100, 2),
        }

    def quota_reset(self, app_id: str) -> Dict[str, Any]:
        u = self.usage.get(app_id)
        if not u:
            return {}
        u["calls_today"] = 0
        u["calls_total"] = 0
        u["by_meter"] = {}
        u["billed_amount"] = 0.0
        u["reset_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return u

    # ------------------------------------------------------------------ #
    # 套餐
    # ------------------------------------------------------------------ #
    def list_plans(self) -> List[Dict[str, Any]]:
        return PLANS

    def subscribe(self, app_id: str, plan_id: str) -> Dict[str, Any]:
        if not any(p["plan_id"] == plan_id for p in PLANS):
            return {"success": False, "error": "plan not found"}
        self.subscriptions[app_id] = plan_id
        return {"success": True, "app_id": app_id, "plan": plan_id,
                "since": time.strftime("%Y-%m-%d %H:%M:%S")}

    def rate_limit_check(self, app_id: str, calls_in_window: int) -> Dict[str, Any]:
        plan = self.subscriptions.get(app_id, "free")
        plan_obj = next((p for p in PLANS if p["plan_id"] == plan), PLANS[0])
        allowed = calls_in_window <= plan_obj["rate_limit_per_min"]
        return {
            "allowed": allowed,
            "limit_per_min": plan_obj["rate_limit_per_min"],
            "current": calls_in_window,
        }

    # ------------------------------------------------------------------ #
    # 账单 / 支付
    # ------------------------------------------------------------------ #
    def generate_bill(self, app_id: str, period: str) -> Dict[str, Any]:
        u = self.usage.get(app_id, {})
        bill_id = "bill_" + uuid.uuid4().hex[:10]
        items = [
            {"meter": m, "units": cnt,
             "unit_price": next((r["unit_price"] for r in PRICING_RULES if r["meter"] == m), 0),
             "amount": round(cnt * next((r["unit_price"] for r in PRICING_RULES if r["meter"] == m), 0), 4)}
            for m, cnt in u.get("by_meter", {}).items()
        ]
        total = round(sum(i["amount"] for i in items), 2)
        bill = {
            "bill_id": bill_id,
            "app_id": app_id,
            "period": period,
            "items": items,
            "total_amount": total,
            "currency": "CNY",
            "status": "unpaid",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.bills[bill_id] = bill
        return bill

    def list_bills(self, app_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.bills.values())
        if app_id:
            items = [b for b in items if b.get("app_id") == app_id]
        return items

    def pay_bill(self, bill_id: str, method: str = "alipay") -> Dict[str, Any]:
        b = self.bills.get(bill_id)
        if not b:
            return {"success": False, "error": "bill not found"}
        b["status"] = "paid"
        b["paid_via"] = method
        b["paid_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        b["transaction_id"] = "txn_" + uuid.uuid4().hex[:12]
        return {"success": True, "bill": b}

    def free_quota(self) -> Dict[str, Any]:
        return {
            "new_user_free_calls": 1000,
            "new_user_free_days": 30,
            "description": "新注册开发者自动获得 1000 次免费调用",
        }

    def list_alarms(self, app_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if app_id:
            return [a for a in self.alarms if a.get("app_id") == app_id]
        return self.alarms


_billing: Optional[UsageBilling] = None


def get_usage_billing() -> UsageBilling:
    global _billing
    if _billing is None:
        _billing = UsageBilling()
    return _billing
