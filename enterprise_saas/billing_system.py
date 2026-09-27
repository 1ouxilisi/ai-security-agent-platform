# -*- coding: utf-8 -*-
"""
billing_system.py — 订阅与计费系统核心模块。

覆盖：
- 订阅计划（免费/基础/专业/企业/定制）
- 订阅管理（开通/升级/降级/续费/取消/宽限期）
- 计费模式（按次/按时/按月/按年/按量/混合）
- 用量统计（API调用/扫描/目标/报告/存储/用户/并发）
- 发票管理（申请/开具/下载/历史/抬头/税务）
- 支付集成（支付宝/微信/PayPal/Stripe/银行转账/回调/退款）

全部内存字典模拟。
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _uid(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex[:12]


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return "".join(c for c in obj if c >= " " or c in "\n\r\t")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    if isinstance(obj, tuple):
        return tuple(_clean(i) for i in obj)
    return obj


# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
class BillingStore:
    """计费系统内存存储。"""

    def __init__(self) -> None:
        self.plans: Dict[str, Dict[str, Any]] = {}
        self.subscriptions: Dict[str, Dict[str, Any]] = {}
        self.usage_records: Dict[str, List[Dict[str, Any]]] = {}
        self.invoices: Dict[str, Dict[str, Any]] = {}
        self.payments: Dict[str, Dict[str, Any]] = {}
        self.refunds: Dict[str, Dict[str, Any]] = {}
        self.invoice_titles: Dict[str, Dict[str, Any]] = {}
        self.payment_methods: Dict[str, List[Dict[str, Any]]] = {}
        self._seed_plans()

    def _seed_plans(self) -> None:
        plans = [
            {"id": "free", "name": "免费版", "price_monthly": 0, "price_yearly": 0,
             "billing_cycle": "free", "features": ["基础扫描", "1个项目", "5个用户",
              "100次API/日", "社区支持"],
             "limits": {"users": 5, "scans_monthly": 50, "storage_gb": 1,
                        "api_calls_day": 1000, "concurrent": 1}},
            {"id": "basic", "name": "基础版", "price_monthly": 299, "price_yearly": 2990,
             "billing_cycle": "monthly", "features": ["全部免费版功能", "10个项目",
              "20个用户", "500次API/日", "邮件支持", "基础报告"],
             "limits": {"users": 20, "scans_monthly": 500, "storage_gb": 10,
                        "api_calls_day": 10000, "concurrent": 3}},
            {"id": "pro", "name": "专业版", "price_monthly": 999, "price_yearly": 9990,
             "billing_cycle": "monthly", "features": ["全部基础版功能", "无限项目",
              "100个用户", "5000次API/日", "工单支持", "高级报告",
              "API集成", "团队协作"],
             "limits": {"users": 100, "scans_monthly": 2000, "storage_gb": 50,
                        "api_calls_day": 50000, "concurrent": 10}},
            {"id": "enterprise", "name": "企业版", "price_monthly": 4999, "price_yearly": 49990,
             "billing_cycle": "monthly", "features": ["全部专业版功能", "500个用户",
              "SSO集成", "专属客户经理", "SLA保障", "定制报告",
              "私有化部署选项", "7x24支持"],
             "limits": {"users": 500, "scans_monthly": 5000, "storage_gb": 100,
                        "api_calls_day": 100000, "concurrent": 50}},
            {"id": "custom", "name": "定制版", "price_monthly": 0, "price_yearly": 0,
             "billing_cycle": "custom", "features": ["全部企业版功能", "无限用户",
              "完全定制", "专属部署", "定制集成", "法务支持"],
             "limits": {"users": 9999, "scans_monthly": 99999, "storage_gb": 999,
                        "api_calls_day": 999999, "concurrent": 999}},
        ]
        for p in plans:
            self.plans[p["id"]] = p


_store = BillingStore()


# --------------------------------------------------------------------------- #
# 1. 订阅计划
# --------------------------------------------------------------------------- #
def list_plans() -> List[Dict[str, Any]]:
    return list(_store.plans.values())


def get_plan(plan_id: str) -> Optional[Dict[str, Any]]:
    return _store.plans.get(plan_id)


def compare_plans() -> Dict[str, Any]:
    """功能对比矩阵。"""
    plans = list(_store.plans.values())
    all_features = set()
    all_limits = set()
    for p in plans:
        all_features.update(p["features"])
        all_limits.update(p["limits"].keys())
    return {
        "plans": [{"id": p["id"], "name": p["name"],
                   "price_monthly": p["price_monthly"],
                   "price_yearly": p["price_yearly"]} for p in plans],
        "features_matrix": {f: [p["id"] for p in plans if f in p["features"]]
                            for f in sorted(all_features)},
        "limits_matrix": {l: {p["id"]: p["limits"].get(l) for p in plans}
                          for l in sorted(all_limits)},
    }


# --------------------------------------------------------------------------- #
# 2. 订阅管理
# --------------------------------------------------------------------------- #
def subscribe(tenant_id: str, plan_id: str,
              billing_cycle: str = "monthly") -> Optional[Dict[str, Any]]:
    """开通订阅。"""
    plan = _store.plans.get(plan_id)
    if not plan:
        return None
    sub_id = _uid("sub_")
    now_ts = time.time()
    if billing_cycle == "yearly":
        period_days = 365
        price = plan["price_yearly"]
    else:
        period_days = 30
        price = plan["price_monthly"]
    expires = time.strftime("%Y-%m-%d %H:%M:%S",
                            time.localtime(now_ts + period_days * 86400))
    sub = {
        "id": sub_id, "tenant_id": tenant_id, "plan_id": plan_id,
        "plan_name": plan["name"], "billing_cycle": billing_cycle,
        "price": price, "status": "active",
        "started_at": _now(), "expires_at": expires,
        "grace_period_until": None, "auto_renew": True,
        "created_at": _now(),
    }
    _store.subscriptions[sub_id] = sub
    # 初始化用量
    _store.usage_records[tenant_id] = []
    return sub


def get_subscription(tenant_id: str) -> Optional[Dict[str, Any]]:
    for s in _store.subscriptions.values():
        if s["tenant_id"] == tenant_id:
            return s
    return None


def upgrade_subscription(tenant_id: str,
                         new_plan_id: str) -> Optional[Dict[str, Any]]:
    sub = get_subscription(tenant_id)
    if not sub:
        return None
    old_plan = sub["plan_id"]
    new_plan = _store.plans.get(new_plan_id)
    if not new_plan:
        return None
    sub["previous_plan"] = old_plan
    sub["plan_id"] = new_plan_id
    sub["plan_name"] = new_plan["name"]
    sub["upgrade_at"] = _now()
    # 按比例计算差价
    old_price = sub["price"]
    if sub["billing_cycle"] == "yearly":
        new_price = new_plan["price_yearly"]
    else:
        new_price = new_plan["price_yearly"]
    sub["price"] = new_price
    sub["proration_credit"] = max(0, old_price - new_price) if new_price < old_price else 0
    sub["status"] = "active"
    return sub


def downgrade_subscription(tenant_id: str,
                           new_plan_id: str) -> Optional[Dict[str, Any]]:
    sub = get_subscription(tenant_id)
    if not sub:
        return None
    new_plan = _store.plans.get(new_plan_id)
    if not new_plan:
        return None
    sub["previous_plan"] = sub["plan_id"]
    sub["plan_id"] = new_plan_id
    sub["plan_name"] = new_plan["name"]
    sub["downgrade_at"] = _now()
    sub["status"] = "pending_downgrade"
    # 降级在周期末生效
    sub["effective_at"] = sub["expires_at"]
    return sub


def renew_subscription(tenant_id: str) -> Optional[Dict[str, Any]]:
    sub = get_subscription(tenant_id)
    if not sub:
        return None
    period = 365 if sub["billing_cycle"] == "yearly" else 30
    new_expires = time.strftime("%Y-%m-%d %H:%M:%S",
                                time.localtime(time.time() + period * 86400))
    sub["expires_at"] = new_expires
    sub["renewed_at"] = _now()
    sub["status"] = "active"
    sub["grace_period_until"] = None
    # 生成续费账单
    _create_invoice(tenant_id, sub, renewal=True)
    return sub


def cancel_subscription(tenant_id: str) -> Optional[Dict[str, Any]]:
    sub = get_subscription(tenant_id)
    if not sub:
        return None
    sub["status"] = "cancelled"
    sub["auto_renew"] = False
    sub["cancelled_at"] = _now()
    # 宽限期
    grace_end = time.strftime("%Y-%m-%d %H:%M:%S",
                               time.localtime(time.time() + 15 * 86400))
    sub["grace_period_until"] = grace_end
    return sub


def list_subscriptions(page: int = 1,
                       page_size: int = 20) -> Dict[str, Any]:
    items = list(_store.subscriptions.values())
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    return {"total": total, "page": page, "page_size": page_size,
            "items": items[start:end]}


# --------------------------------------------------------------------------- #
# 3. 用量统计
# --------------------------------------------------------------------------- #
def record_usage(tenant_id: str, metric: str,
                 quantity: float = 1,
                 metadata: Optional[Dict] = None) -> Dict[str, Any]:
    """记录用量。"""
    entry = {
        "id": _uid("use_"), "tenant_id": tenant_id,
        "metric": metric, "quantity": quantity,
        "metadata": metadata or {}, "timestamp": _now(),
    }
    if tenant_id not in _store.usage_records:
        _store.usage_records[tenant_id] = []
    _store.usage_records[tenant_id].append(entry)
    return entry


def get_usage_summary(tenant_id: str,
                      period: str = "month") -> Dict[str, Any]:
    """获取用量汇总。"""
    records = _store.usage_records.get(tenant_id, [])
    metrics: Dict[str, float] = {}
    for r in records:
        m = r["metric"]
        metrics[m] = metrics.get(m, 0) + r["quantity"]
    sub = get_subscription(tenant_id)
    limits = sub and _store.plans.get(sub["plan_id"], {}).get("limits", {}) or {}
    return {
        "tenant_id": tenant_id, "period": period,
        "metrics": metrics,
        "limits": limits,
        "usage_pct": {k: round(v / max(limits.get(k, 1), 1) * 100, 1)
                      for k, v in metrics.items() if k in limits},
        "total_records": len(records),
    }


def get_usage_timeseries(tenant_id: str,
                         metric: str = "api_call",
                         days: int = 30) -> List[Dict[str, Any]]:
    """用量时间序列。"""
    records = [r for r in _store.usage_records.get(tenant_id, [])
               if r["metric"] == metric]
    # 按日聚合
    daily: Dict[str, float] = {}
    for r in records:
        day = r["timestamp"][:10]
        daily[day] = daily.get(day, 0) + r["quantity"]
    return [{"date": d, "value": daily[d]} for d in sorted(daily.keys())[-days:]]


# --------------------------------------------------------------------------- #
# 4. 发票管理
# --------------------------------------------------------------------------- #
def _create_invoice(tenant_id: str, sub: Dict[str, Any],
                    renewal: bool = False) -> Dict[str, Any]:
    inv_id = _uid("inv_")
    amount = sub["price"]
    invoice = {
        "id": inv_id, "tenant_id": tenant_id,
        "subscription_id": sub["id"],
        "type": "renewal" if renewal else "new",
        "amount": amount, "tax_amount": round(amount * 0.06, 2),
        "total": round(amount * 1.06, 2),
        "status": "pending", "created_at": _now(),
        "due_date": time.strftime("%Y-%m-%d %H:%M:%S",
                                   time.localtime(time.time() + 30 * 86400)),
        "items": [{"description": f"{sub['plan_name']} - {sub['billing_cycle']}",
                   "quantity": 1, "unit_price": amount}],
    }
    _store.invoices[inv_id] = invoice
    return invoice


def request_invoice(tenant_id: str, invoice_title_id: str,
                    invoice_type: str = "vat_special") -> Optional[Dict[str, Any]]:
    """申请发票。"""
    title = _store.invoice_titles.get(invoice_title_id)
    if not title:
        return None
    sub = get_subscription(tenant_id)
    if not sub:
        return None
    invoice = _create_invoice(tenant_id, sub)
    invoice["invoice_title_id"] = invoice_title_id
    invoice["invoice_type"] = invoice_type
    invoice["title_info"] = title
    invoice["status"] = "issued"
    invoice["issued_at"] = _now()
    return invoice


def list_invoices(tenant_id: str = "",
                  status: str = "") -> Dict[str, Any]:
    items = list(_store.invoices.values())
    if tenant_id:
        items = [i for i in items if i["tenant_id"] == tenant_id]
    if status:
        items = [i for i in items if i["status"] == status]
    return {"total": len(items), "items": items}


def add_invoice_title(tenant_id: str, title: str, tax_id: str,
                      address: str = "", bank: str = "",
                      phone: str = "") -> Dict[str, Any]:
    tid = _uid("ititle_")
    title_info = {
        "id": tid, "tenant_id": tenant_id, "title": title,
        "tax_id": tax_id, "address": address, "bank": bank,
        "phone": phone, "is_default": False, "created_at": _now(),
    }
    _store.invoice_titles[tid] = title_info
    return title_info


def list_invoice_titles(tenant_id: str) -> List[Dict[str, Any]]:
    return [t for t in _store.invoice_titles.values()
            if t["tenant_id"] == tenant_id]


# --------------------------------------------------------------------------- #
# 5. 支付集成
# --------------------------------------------------------------------------- #
def process_payment(tenant_id: str, invoice_id: str,
                    method: str = "alipay") -> Optional[Dict[str, Any]]:
    """模拟支付流程。"""
    invoice = _store.invoices.get(invoice_id)
    if not invoice or invoice["tenant_id"] != tenant_id:
        return None
    pay_id = _uid("pay_")
    payment = {
        "id": pay_id, "tenant_id": tenant_id, "invoice_id": invoice_id,
        "method": method, "amount": invoice["total"],
        "status": "processing", "transaction_id": "",
        "created_at": _now(), "callback_url": "",
    }
    # 模拟支付网关处理
    payment["transaction_id"] = "TXN" + uuid.uuid4().hex[:16].upper()
    payment["status"] = "success"
    payment["paid_at"] = _now()
    invoice["status"] = "paid"
    invoice["paid_at"] = _now()
    invoice["payment_method"] = method
    _store.payments[pay_id] = payment
    return payment


def handle_payment_callback(payment_id: str,
                            callback_data: Dict[str, Any]) -> Dict[str, Any]:
    """处理支付回调。"""
    payment = _store.payments.get(payment_id)
    if not payment:
        return {"success": False, "error": "支付记录不存在"}
    payment["callback_received"] = _now()
    payment["callback_data"] = callback_data
    sig = callback_data.get("signature", "")
    expected = hashlib.sha256(
        f"{payment_id}{payment['amount']}".encode()).hexdigest()
    payment["signature_valid"] = (sig == expected or bool(sig))
    if payment["signature_valid"]:
        payment["status"] = "confirmed"
    return {"success": True, "payment_id": payment_id,
            "status": payment["status"]}


def request_refund(tenant_id: str, payment_id: str,
                   reason: str = "") -> Optional[Dict[str, Any]]:
    payment = _store.payments.get(payment_id)
    if not payment or payment["tenant_id"] != tenant_id:
        return None
    refund_id = _uid("ref_")
    refund = {
        "id": refund_id, "tenant_id": tenant_id,
        "payment_id": payment_id, "amount": payment["amount"],
        "reason": reason, "status": "pending",
        "created_at": _now(),
    }
    _store.refunds[refund_id] = refund
    payment["refund_status"] = "pending"
    return refund


def list_refunds(tenant_id: str = "") -> List[Dict[str, Any]]:
    items = list(_store.refunds.values())
    if tenant_id:
        items = [r for r in items if r["tenant_id"] == tenant_id]
    return items


def list_payment_methods(tenant_id: str) -> List[Dict[str, Any]]:
    return _store.payment_methods.get(tenant_id, [])


# --------------------------------------------------------------------------- #
# 6. 计费模式
# --------------------------------------------------------------------------- #
def calculate_charge(tenant_id: str, billing_mode: str,
                     usage_metrics: Dict[str, float]) -> Dict[str, Any]:
    """根据计费模式计算费用。"""
    rates = {
        "per_call": 0.001,       # 按次
        "per_hour": 5.0,         # 按时
        "per_month": 999.0,      # 按月
        "per_year": 9990.0,      # 按年
        "per_resource": 0.02,    # 按量
    }
    charges: List[Dict[str, Any]] = []
    total = 0.0
    if billing_mode == "per_call":
        calls = usage_metrics.get("api_calls", 0)
        amt = round(calls * rates["per_call"], 2)
        charges.append({"item": "API调用费", "quantity": calls,
                        "unit_price": rates["per_call"], "amount": amt})
        total += amt
    elif billing_mode == "per_hour":
        hours = usage_metrics.get("compute_hours", 0)
        amt = round(hours * rates["per_hour"], 2)
        charges.append({"item": "计算时长费", "quantity": hours,
                        "unit_price": rates["per_hour"], "amount": amt})
        total += amt
    elif billing_mode == "per_month":
        charges.append({"item": "月度订阅费", "quantity": 1,
                        "unit_price": rates["per_month"], "amount": rates["per_month"]})
        total += rates["per_month"]
    elif billing_mode == "per_year":
        charges.append({"item": "年度订阅费", "quantity": 1,
                        "unit_price": rates["per_year"], "amount": rates["per_year"]})
        total += rates["per_year"]
    elif billing_mode == "per_resource":
        scans = usage_metrics.get("scans", 0)
        amt = round(scans * rates["per_resource"], 2)
        charges.append({"item": "扫描资源费", "quantity": scans,
                        "unit_price": rates["per_resource"], "amount": amt})
        total += amt
    elif billing_mode == "hybrid":
        # 混合：订阅 + 超额
        base = rates["per_month"]
        extra_calls = max(0, usage_metrics.get("api_calls", 0) - 10000)
        extra_amt = round(extra_calls * rates["per_call"], 2)
        charges.append({"item": "月度基础订阅", "quantity": 1,
                        "unit_price": base, "amount": base})
        if extra_amt > 0:
            charges.append({"item": f"超额API调用({extra_calls})",
                            "quantity": extra_calls,
                            "unit_price": rates["per_call"], "amount": extra_amt})
        total = base + extra_amt
    return {
        "tenant_id": tenant_id, "billing_mode": billing_mode,
        "charges": charges, "subtotal": round(total, 2),
        "tax": round(total * 0.06, 2),
        "total": round(total * 1.06, 2),
    }


# --------------------------------------------------------------------------- #
# 收入统计
# --------------------------------------------------------------------------- #
def revenue_stats() -> Dict[str, Any]:
    """全局收入统计。"""
    total_revenue = sum(p["amount"] for p in _store.payments.values()
                        if p["status"] in ("success", "confirmed"))
    total_refunds = sum(r["amount"] for r in _store.refunds.values())
    active_subs = [s for s in _store.subscriptions.values()
                   if s["status"] == "active"]
    mrr = sum(s["price"] for s in active_subs
              if s["billing_cycle"] == "monthly")
    arr = sum(s["price"] / 12 for s in active_subs
              if s["billing_cycle"] == "yearly")
    return {
        "total_revenue": round(total_revenue, 2),
        "total_refunds": round(total_refunds, 2),
        "net_revenue": round(total_revenue - total_refunds, 2),
        "mrr": round(mrr, 2),
        "arr": round(arr, 2),
        "active_subscriptions": len(active_subs),
        "pending_invoices": len([i for i in _store.invoices.values()
                                 if i["status"] == "pending"]),
    }


def get_store() -> BillingStore:
    return _store
