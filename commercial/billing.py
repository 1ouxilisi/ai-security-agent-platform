# -*- coding: utf-8 -*-
"""计费与订阅系统。

订阅计划：FREE / PRO / ENTERPRISE。
订单状态：pending / paid / failed / refunded / cancelled。
支付为模拟支付，但预留 ``PaymentGateway`` 抽象接口，便于后续接入真实网关。

持久化：
- 订阅 -> data/tenants/_meta/subscriptions.json
- 订单 -> data/tenants/_meta/orders.json
- 用量 -> data/tenants/_meta/billing_usage.json
"""
import os
import json
import time
import secrets
import threading
from typing import Any, Dict, List, Optional

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging
    log = logging.getLogger("commercial.billing")


# ============== 订阅计划定义 ==============

PLANS: Dict[str, Dict[str, Any]] = {
    "FREE": {
        "name": "免费版",
        "price_monthly": 0,
        "price_yearly": 0,
        "scan_count": 10,
        "users": 1,
        "api_keys": 1,
        "storage_mb": 500,
        "api_calls_daily": 500,
        "support": "社区支持",
    },
    "PRO": {
        "name": "专业版",
        "price_monthly": 999,
        "price_yearly": 9999,
        "scan_count": 100,
        "users": 10,
        "api_keys": 5,
        "storage_mb": 10240,   # 10GB
        "api_calls_daily": 50000,
        "support": "邮件支持",
    },
    "ENTERPRISE": {
        "name": "企业版",
        "price_monthly": 9999,
        "price_yearly": 9999,
        "scan_count": -1,       # -1 表示无限
        "users": -1,
        "api_keys": 50,
        "storage_mb": 102400,  # 100GB
        "api_calls_daily": -1,
        "support": "专属支持 + 定制",
    },
}

ORDER_STATUSES = {"pending", "paid", "failed", "refunded", "cancelled"}


# ============== 支付网关抽象 ==============

class PaymentGateway:
    """支付网关抽象基类。真实网关（微信/支付宝/Stripe）可继承并实现。"""

    name = "base"

    def create_payment(self, order: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def verify_payment(self, payment_id: str) -> bool:
        raise NotImplementedError


class SimulatedPaymentGateway(PaymentGateway):
    """模拟支付网关：直接返回成功链接，pay_order 直接标记成功。"""

    name = "simulated"

    def create_payment(self, order: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "gateway": self.name,
            "payment_url": f"https://pay.example.local/simulate/{order['order_id']}",
            "qr_payload": f"SIMULATED|PAY|{order['order_id']}|{order['amount']}",
            "note": "模拟支付环境，调用 pay_order 即视为支付成功",
        }

    def verify_payment(self, payment_id: str) -> bool:
        return True


# ============== 计费引擎 ==============

class BillingEngine:
    """计费与订阅引擎。"""

    def __init__(self, base_dir: str = "data/tenants", tenant_manager=None):
        self.meta_dir = os.path.join(base_dir, "_meta")
        self.sub_file = os.path.join(self.meta_dir, "subscriptions.json")
        self.orders_file = os.path.join(self.meta_dir, "orders.json")
        self.usage_file = os.path.join(self.meta_dir, "billing_usage.json")

        self._subs: Dict[str, Dict[str, Any]] = {}
        self._orders: Dict[str, Dict[str, Any]] = {}
        # billing_usage: {tenant_id: [ {ts, resource_type, amount} ]}
        self._usage: Dict[str, List[Dict[str, Any]]] = {}

        self._lock = threading.RLock()
        self.gateway: PaymentGateway = SimulatedPaymentGateway()

        # 关联的租户管理器（可选），用于订阅成功后同步配额
        self._tm = tenant_manager

        os.makedirs(self.meta_dir, exist_ok=True)
        self._load()

    # ---------------- 持久化 ----------------

    def _load(self):
        for path, attr in [(self.sub_file, "_subs"),
                           (self.orders_file, "_orders"),
                           (self.usage_file, "_usage")]:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        setattr(self, attr, json.load(f))
                except Exception as e:
                    log.warning(f"[billing] 加载 {path} 失败: {e}")

    def _save_subs(self):
        with open(self.sub_file, "w", encoding="utf-8") as f:
            json.dump(self._subs, f, ensure_ascii=False, indent=2)

    def _save_orders(self):
        with open(self.orders_file, "w", encoding="utf-8") as f:
            json.dump(self._orders, f, ensure_ascii=False, indent=2)

    def _save_usage(self):
        with open(self.usage_file, "w", encoding="utf-8") as f:
            json.dump(self._usage, f, ensure_ascii=False, indent=2)

    # ---------------- 订阅 ----------------

    def subscribe(self, tenant_id: str, plan: str,
                  cycle: str = "monthly") -> Dict[str, Any]:
        """创建/变更订阅（直接激活，免费计划无需支付）。"""
        if plan not in PLANS:
            raise ValueError(f"未知计划: {plan}")
        with self._lock:
            spec = PLANS[plan]
            now = time.time()
            if spec["price_monthly"] == 0 and plan == "FREE":
                period_days = 36500  # 免费版长期有效
            else:
                period_days = 366 if cycle == "yearly" else 30
            sub = {
                "tenant_id": tenant_id,
                "plan": plan,
                "cycle": cycle,
                "status": "active",
                "started_at": now,
                "expires_at": now + period_days * 86400,
                "auto_renew": True,
                "quotas": {k: v for k, v in spec.items() if k in
                           ("scan_count", "users", "api_keys", "storage_mb",
                            "api_calls_daily")},
                "support": spec["support"],
            }
            self._subs[tenant_id] = sub
            self._save_subs()
            self._sync_tenant_quotas(tenant_id, plan)
            log.info(f"[billing] 租户 {tenant_id} 订阅 {plan}/{cycle} 成功")
            return dict(sub)

    def unsubscribe(self, tenant_id: str) -> bool:
        """取消订阅（到期后失效，此处标记不自动续费）。"""
        with self._lock:
            sub = self._subs.get(tenant_id)
            if not sub:
                return False
            sub["auto_renew"] = False
            sub["cancel_requested_at"] = time.time()
            self._save_subs()
            return True

    def get_subscription(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        sub = self._subs.get(tenant_id)
        if not sub:
            return None
        sub = dict(sub)
        # 判断是否过期
        if sub.get("expires_at", 0) < time.time():
            sub["status"] = "expired" if sub.get("auto_renew") else "cancelled"
        return sub

    def _sync_tenant_quotas(self, tenant_id: str, plan: str):
        """订阅成功后把计划配额同步到 TenantManager。"""
        if self._tm is None:
            return
        spec = PLANS[plan]
        for q in ("scan_count", "users", "api_keys", "storage_mb",
                  "api_calls_daily"):
            val = spec.get(q)
            if val is not None:
                # -1 表示无限，落到租户层给一个足够大的值
                self._tm.update_quota(
                    tenant_id, q, 10 ** 9 if val == -1 else int(val))

    # ---------------- 订单 ----------------

    def create_order(self, tenant_id: str, plan: str,
                     cycle: str = "monthly") -> Dict[str, Any]:
        if plan not in PLANS:
            raise ValueError(f"未知计划: {plan}")
        with self._lock:
            spec = PLANS[plan]
            amount = spec["price_yearly"] if cycle == "yearly" else spec["price_monthly"]
            order_id = "ORD" + secrets.token_hex(8)
            order = {
                "order_id": order_id,
                "tenant_id": tenant_id,
                "plan": plan,
                "cycle": cycle,
                "amount": amount,
                "currency": "CNY",
                "status": "pending",
                "created_at": time.time(),
                "paid_at": 0,
                "payment_method": "",
            }
            pay_info = self.gateway.create_payment(order)
            order["payment_url"] = pay_info.get("payment_url", "")
            self._orders[order_id] = order
            self._save_orders()
            return {
                "order_id": order_id,
                "amount": amount,
                "currency": "CNY",
                "plan": plan,
                "cycle": cycle,
                "status": "pending",
                "payment_url": order["payment_url"],
            }

    def pay_order(self, order_id: str,
                  payment_method: str = "simulated") -> Dict[str, Any]:
        """模拟支付：标记成功并激活/延长订阅。"""
        with self._lock:
            order = self._orders.get(order_id)
            if not order:
                raise ValueError(f"订单 {order_id} 不存在")
            if order["status"] in ("paid", "cancelled", "refunded"):
                return {"order_id": order_id, "status": order["status"],
                        "message": f"订单已是 {order['status']} 状态"}
            order["status"] = "paid"
            order["paid_at"] = time.time()
            order["payment_method"] = payment_method
            self._save_orders()

            # 激活/延长订阅
            tenant_id = order["tenant_id"]
            plan = order["plan"]
            cycle = order["cycle"]
            now = time.time()
            period_days = 366 if cycle == "yearly" else 30
            old = self._subs.get(tenant_id)
            base = max(now, old.get("expires_at", now)) if old else now
            sub = {
                "tenant_id": tenant_id,
                "plan": plan,
                "cycle": cycle,
                "status": "active",
                "started_at": old.get("started_at", now) if old else now,
                "expires_at": base + period_days * 86400,
                "auto_renew": True,
                "quotas": {k: v for k, v in PLANS[plan].items() if k in
                           ("scan_count", "users", "api_keys", "storage_mb",
                            "api_calls_daily")},
                "support": PLANS[plan]["support"],
            }
            self._subs[tenant_id] = sub
            self._save_subs()
            self._sync_tenant_quotas(tenant_id, plan)
            return {"order_id": order_id, "status": "paid",
                    "tenant_id": tenant_id, "plan": plan,
                    "expires_at": sub["expires_at"]}

    def get_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        o = self._orders.get(order_id)
        return dict(o) if o else None

    def list_orders(self, tenant_id: str) -> List[Dict[str, Any]]:
        return [dict(o) for o in self._orders.values()
                if o["tenant_id"] == tenant_id]

    # ---------------- 发票 ----------------

    def generate_invoice(self, order_id: str) -> str:
        """生成发票（文本+HTML），存到租户 reports/ 目录，返回 HTML 路径。"""
        order = self._orders.get(order_id)
        if not order:
            raise ValueError(f"订单 {order_id} 不存在")
        tenant_id = order["tenant_id"]
        invoice_no = "INV" + secrets.token_hex(6).upper()
        issue_date = time.strftime("%Y-%m-%d", time.localtime(order.get("paid_at") or time.time()))
        plan_name = PLANS.get(order["plan"], {}).get("name", order["plan"])

        text = (
            "========================================\n"
            f"电子发票 / INVOICE\n"
            f"发票号码: {invoice_no}\n"
            f"开票日期: {issue_date}\n"
            f"租户    : {tenant_id}\n"
            f"订单号  : {order_id}\n"
            f"订购内容: {plan_name} ({order['cycle']})\n"
            f"金额    : {order['amount']} {order['currency']}\n"
            f"状态    : {order['status']}\n"
            "========================================\n"
        )

        html = f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
<title>发票 {invoice_no}</title></head>
<body style="font-family:sans-serif;max-width:640px;margin:40px auto;color:#222">
<h2>电子发票 / INVOICE</h2>
<table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%">
<tr><td>发票号码</td><td>{invoice_no}</td></tr>
<tr><td>开票日期</td><td>{issue_date}</td></tr>
<tr><td>租户</td><td>{tenant_id}</td></tr>
<tr><td>订单号</td><td>{order_id}</td></tr>
<tr><td>订购内容</td><td>{plan_name} ({order['cycle']})</td></tr>
<tr><td>金额</td><td>{order['amount']} {order['currency']}</td></tr>
<tr><td>状态</td><td>{order['status']}</td></tr>
</table>
</body></html>"""

        # 存到租户 reports 目录
        if self._tm is not None:
            tenant_dir = self._tm.get_tenant_path(tenant_id, "reports")
        else:
            tenant_dir = os.path.join("data/tenants", tenant_id, "reports")
        os.makedirs(tenant_dir, exist_ok=True)
        html_path = os.path.join(tenant_dir, f"invoice_{invoice_no}.html")
        txt_path = os.path.join(tenant_dir, f"invoice_{invoice_no}.txt")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(text)
        log.info(f"[billing] 发票 {invoice_no} 已生成: {html_path}")
        return html_path

    # ---------------- 用量与超额 ----------------

    def record_usage(self, tenant_id: str, resource_type: str,
                     amount: int = 1) -> None:
        with self._lock:
            self._usage.setdefault(tenant_id, []).append({
                "ts": time.time(),
                "resource_type": resource_type,
                "amount": amount,
            })
            # 同时累计到 TenantManager 的配额
            quota_map = {"scan": "scan_count", "api_call": "api_calls_daily",
                         "storage_mb": "storage_mb"}
            if self._tm and resource_type in quota_map:
                self._tm.record_usage(tenant_id, quota_map[resource_type], amount)
            self._save_usage()

    def get_usage(self, tenant_id: str, period: Optional[str] = None) -> Dict[str, Any]:
        """获取用量统计。period 为 'day'/'month' 或 None（全部）。"""
        records = self._usage.get(tenant_id, [])
        now = time.time()
        cutoff = 0
        if period == "day":
            cutoff = now - 86400
        elif period == "month":
            cutoff = now - 30 * 86400
        total: Dict[str, int] = {}
        for r in records:
            if cutoff and r["ts"] < cutoff:
                continue
            total[r["resource_type"]] = total.get(r["resource_type"], 0) + r["amount"]
        return {"tenant_id": tenant_id, "period": period or "all",
                "total_records": len(records), "by_resource": total}

    def check_overage(self, tenant_id: str) -> List[Dict[str, Any]]:
        """检查是否超额，返回超额项列表。"""
        overages: List[Dict[str, Any]] = []
        sub = self.get_subscription(tenant_id)
        quotas = (sub or {}).get("quotas", {})
        if self._tm is None:
            return overages
        snap = self._tm.usage_snapshot(tenant_id)
        for qtype, usage in snap.items():
            limit = quotas.get(qtype, usage["limit"])
            if limit in (-1, None):
                continue
            if usage["used"] > int(limit):
                overages.append({
                    "quota_type": qtype,
                    "used": usage["used"],
                    "limit": int(limit),
                    "over_by": usage["used"] - int(limit),
                })
        return overages

    def send_overage_alert(self, tenant_id: str) -> Dict[str, Any]:
        """超额告警：写日志 + 租户 logs/ 目录告警文件。"""
        overages = self.check_overage(tenant_id)
        result = {"tenant_id": tenant_id, "alerted": False, "overages": overages}
        if not overages:
            return result
        msg = (f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 租户 {tenant_id} 超额告警: "
               + "; ".join(f"{o['quota_type']} 已用{o['used']}/上限{o['limit']}"
                           for o in overages))
        log.warning(msg)
        if self._tm is not None:
            log_dir = self._tm.get_tenant_path(tenant_id, "logs")
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, "overage_alerts.log"),
                      "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        result["alerted"] = True
        return result


# 模块级单例
_default_billing: Optional[BillingEngine] = None


def get_billing_engine(base_dir: str = "data/tenants",
                       tenant_manager=None) -> BillingEngine:
    global _default_billing
    if _default_billing is None:
        _default_billing = BillingEngine(base_dir, tenant_manager)
    return _default_billing
