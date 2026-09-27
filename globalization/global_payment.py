# -*- coding: utf-8 -*-
"""
global_payment.py — 国际支付与计费（第25轮升级方向4 / 模块3）。

包含：
  - 支付方式集成：支付宝/微信/PayPal/Stripe/信用卡/借记卡/银行转账/Apple Pay/Google Pay/加密货币（10+）
  - 多货币支持：CNY/USD/EUR/JPY/GBP/KRW/HKD/AUD/CAD/CHF（10+）+ 实时汇率 + 汇率历史
  - 税务管理：VAT/销售税/GST/消费税/企业所得税/预提税/计算/报告/发票
  - 发票管理：电子发票/纸质发票/增值税发票/形式发票/模板/开具/发送/归档/查询
  - 订阅计费：按月/按年/按用量/按用户/按功能/混合/免费试用/折扣/优惠券/促销/续费/升降级/取消
  - 财务报告：收入/支出/利润/现金流/应收/应付/税务/分析/预测

全部内存字典模拟，不建数据库表。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


# ==================== 支付方式 ====================

PAYMENT_METHODS: Dict[str, Dict[str, Any]] = {
    "alipay": {"name": "支付宝", "type": "wallet", "regions": ["CN", "MY", "SG"], "currencies": ["CNY", "USD"], "fees": "0.6%", "settlement": "T+1", "verified": True},
    "wechat_pay": {"name": "微信支付", "type": "wallet", "regions": ["CN", "HK", "MY"], "currencies": ["CNY", "HKD"], "fees": "0.6%", "settlement": "T+1", "verified": True},
    "paypal": {"name": "PayPal", "type": "wallet", "regions": ["US", "EU", "UK", "JP", "AU", "BR"], "currencies": ["USD", "EUR", "GBP", "JPY", "BRL"], "fees": "3.4%+固定", "settlement": "T+3", "verified": True},
    "stripe": {"name": "Stripe", "type": "card_processor", "regions": ["US", "EU", "UK", "CA", "AU", "SG", "HK", "JP"], "currencies": ["USD", "EUR", "GBP", "CAD", "AUD", "SGD", "HKD", "JPY"], "fees": "2.9%+$0.30", "settlement": "T+2", "verified": True},
    "credit_card": {"name": "信用卡", "type": "card", "regions": ["US", "EU", "UK", "JP", "KR", "SG", "AU", "CN"], "currencies": ["USD", "EUR", "GBP", "JPY", "KRW", "SGD", "AUD", "CNY"], "fees": "1.5%-2.5%", "settlement": "T+2", "verified": True},
    "debit_card": {"name": "借记卡", "type": "card", "regions": ["US", "EU", "UK", "CN"], "currencies": ["USD", "EUR", "GBP", "CNY"], "fees": "0.8%-1.5%", "settlement": "T+1", "verified": True},
    "bank_transfer": {"name": "银行转账", "type": "bank", "regions": ["EU", "UK", "CN", "JP", "AU", "CA"], "currencies": ["EUR", "GBP", "CNY", "JPY", "AUD", "CAD", "CHF"], "fees": "固定费用", "settlement": "T+3-T+5", "verified": True},
    "apple_pay": {"name": "Apple Pay", "type": "mobile_wallet", "regions": ["US", "EU", "UK", "JP", "SG", "AU", "HK", "CN"], "currencies": ["USD", "EUR", "GBP", "JPY", "SGD", "AUD", "HKD", "CNY"], "fees": "与信用卡相同", "settlement": "T+2", "verified": True},
    "google_pay": {"name": "Google Pay", "type": "mobile_wallet", "regions": ["US", "EU", "UK", "JP", "SG", "AU", "BR", "IN"], "currencies": ["USD", "EUR", "GBP", "JPY", "SGD", "AUD", "BRL", "INR"], "fees": "与信用卡相同", "settlement": "T+2", "verified": True},
    "crypto": {"name": "加密货币", "type": "crypto", "regions": ["Global"], "currencies": ["BTC", "ETH", "USDT", "USDC"], "fees": "网络费用", "settlement": "即时确认", "verified": False},
    "sepa": {"name": "SEPA转账", "type": "bank", "regions": ["EU"], "currencies": ["EUR"], "fees": "免费/低费", "settlement": "T+1", "verified": True},
    "konbini": {"name": "便利店支付", "type": "cash", "regions": ["JP"], "currencies": ["JPY"], "fees": "300日元", "settlement": "T+1", "verified": False},
}


# ==================== 多货币与汇率 ====================

CURRENCIES: Dict[str, Dict[str, Any]] = {
    "CNY": {"name": "人民币", "symbol": "¥", "precision": 2, "country": "中国"},
    "USD": {"name": "美元", "symbol": "$", "precision": 2, "country": "美国"},
    "EUR": {"name": "欧元", "symbol": "€", "precision": 2, "country": "欧元区"},
    "JPY": {"name": "日元", "symbol": "¥", "precision": 0, "country": "日本"},
    "GBP": {"name": "英镑", "symbol": "£", "precision": 2, "country": "英国"},
    "KRW": {"name": "韩元", "symbol": "₩", "precision": 0, "country": "韩国"},
    "HKD": {"name": "港币", "symbol": "HK$", "precision": 2, "country": "香港"},
    "AUD": {"name": "澳元", "symbol": "A$", "precision": 2, "country": "澳大利亚"},
    "CAD": {"name": "加元", "symbol": "C$", "precision": 2, "country": "加拿大"},
    "CHF": {"name": "瑞郎", "symbol": "Fr", "precision": 2, "country": "瑞士"},
    "SGD": {"name": "新元", "symbol": "S$", "precision": 2, "country": "新加坡"},
    "BRL": {"name": "雷亚尔", "symbol": "R$", "precision": 2, "country": "巴西"},
}


class ExchangeRateManager:
    """汇率管理器"""

    # 模拟实时汇率（vs USD）
    RATES: Dict[str, float] = {
        "CNY": 7.24, "USD": 1.0, "EUR": 0.92, "JPY": 149.5,
        "GBP": 0.79, "KRW": 1372.0, "HKD": 7.82, "AUD": 1.53,
        "CAD": 1.36, "CHF": 0.88, "SGD": 1.35, "BRL": 5.05,
    }
    RATE_HISTORY: Dict[str, List[Dict[str, Any]]] = {}

    def __init__(self):
        self._seed_history()

    def _seed_history(self):
        for cur in self.RATES:
            self.RATE_HISTORY[cur] = [
                {"date": f"2026-04-{d:02d}", "rate": round(self.RATES[cur] * (1 + (d - 15) * 0.001), 4)}
                for d in range(1, 16)
            ]

    def convert(self, amount: float, from_currency: str, to_currency: str) -> Dict[str, Any]:
        if from_currency not in self.RATES or to_currency not in self.RATES:
            return {"error": "不支持的货币"}
        usd_amount = amount / self.RATES[from_currency]
        result = usd_amount * self.RATES[to_currency]
        return {
            "original_amount": amount, "from_currency": from_currency,
            "converted_amount": round(result, 2), "to_currency": to_currency,
            "rate": round(self.RATES[from_currency] / self.RATES[to_currency], 4),
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }

    def get_rates(self, base: str = "USD") -> Dict[str, float]:
        if base not in self.RATES:
            return dict(self.RATES)
        base_rate = self.RATES[base]
        return {cur: round(rate / base_rate, 4) for cur, rate in self.RATES.items()}

    def history(self, currency: str, days: int = 30) -> List[Dict[str, Any]]:
        return self.RATE_HISTORY.get(currency, [])[-days:]


# ==================== 税务管理 ====================

TAX_RATES: Dict[str, Dict[str, Any]] = {
    "CN_VAT": {"name": "中国增值税", "type": "VAT", "rate": 0.13, "region": "CN", "threshold": 0},
    "US_SALES_CA": {"name": "加州销售税", "type": "Sales Tax", "rate": 0.0725, "region": "US-CA", "threshold": 0},
    "US_SALES_NY": {"name": "纽约销售税", "type": "Sales Tax", "rate": 0.08875, "region": "US-NY", "threshold": 0},
    "EU_VAT_DE": {"name": "德国VAT", "type": "VAT", "rate": 0.19, "region": "DE", "threshold": 0},
    "EU_VAT_FR": {"name": "法国VAT", "type": "VAT", "rate": 0.20, "region": "FR", "threshold": 0},
    "EU_VAT_IE": {"name": "爱尔兰VAT", "type": "VAT", "rate": 0.23, "region": "IE", "threshold": 0},
    "UK_VAT": {"name": "英国VAT", "type": "VAT", "rate": 0.20, "region": "UK", "threshold": 0},
    "JP_CONSUMPTION": {"name": "日本消费税", "type": "Consumption Tax", "rate": 0.10, "region": "JP", "threshold": 0},
    "AU_GST": {"name": "澳大利亚GST", "type": "GST", "rate": 0.10, "region": "AU", "threshold": 75000},
    "SG_GST": {"name": "新加坡GST", "type": "GST", "rate": 0.09, "region": "SG", "threshold": 100000},
    "KR_VAT": {"name": "韩国VAT", "type": "VAT", "rate": 0.10, "region": "KR", "threshold": 0},
    "BR_ICMS": {"name": "巴西流转税", "type": "ICMS", "rate": 0.18, "region": "BR", "threshold": 0},
    "CA_HST_ON": {"name": "加拿大HST(安省)", "type": "HST", "rate": 0.13, "region": "CA-ON", "threshold": 30000},
}


class TaxManager:
    """税务计算与报告"""

    def __init__(self):
        self.reports: Dict[str, Dict[str, Any]] = {}

    def calculate(self, amount: float, region: str, tax_type: str = "auto") -> Dict[str, Any]:
        applicable = []
        for tax_id, tax in TAX_RATES.items():
            if region in tax["region"] or tax["region"] == region:
                if amount >= tax["threshold"]:
                    tax_amount = amount * tax["rate"]
                    applicable.append({
                        "tax_id": tax_id, "name": tax["name"], "type": tax["type"],
                        "rate": tax["rate"], "tax_amount": round(tax_amount, 2),
                    })
        total_tax = sum(a["tax_amount"] for a in applicable)
        return {
            "subtotal": amount, "total_tax": round(total_tax, 2),
            "grand_total": round(amount + total_tax, 2),
            "breakdown": applicable, "region": region,
        }

    def tax_report(self, period: str = "2026-Q2") -> Dict[str, Any]:
        return {
            "period": period, "currency": "USD",
            "total_sales": 125000.00, "total_tax_collected": 18750.00,
            "by_region": {"CN": {"sales": 45000, "tax": 5850}, "US": {"sales": 35000, "tax": 2537}, "EU": {"sales": 28000, "tax": 5320}, "APAC": {"sales": 17000, "tax": 1530}},
            "filing_due": "2026-07-31", "status": "pending",
        }


# ==================== 发票管理 ====================

@dataclass
class Invoice:
    invoice_id: str
    customer: str
    amount: float
    currency: str
    tax_amount: float = 0.0
    status: str = "draft"  # draft / sent / paid / overdue / void
    type: str = "electronic"  # electronic / paper / vat / proforma
    items: List[Dict[str, Any]] = field(default_factory=list)
    issued_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    due_date: str = ""
    sent_at: str = ""
    pdf_url: str = ""


class InvoiceManager:
    """发票管理器"""

    def __init__(self):
        self.invoices: Dict[str, Invoice] = {}
        self.templates: Dict[str, Dict[str, str]] = {}
        self._seed()

    def _seed(self):
        for i in range(10):
            inv_id = f"INV-2026-{i:04d}"
            self.invoices[inv_id] = Invoice(
                invoice_id=inv_id, customer=f"customer_{i:03d}@example.com",
                amount=99.0 + i * 50, currency="USD", tax_amount=round((99.0 + i * 50) * 0.08, 2),
                status=["draft", "sent", "paid", "overdue"][i % 4],
                type=["electronic", "electronic", "vat", "proforma"][i % 4],
                items=[{"name": "SaaS订阅", "qty": 1, "unit_price": 99.0}],
                due_date=(datetime.now() + timedelta(days=30)).isoformat()[:10],
            )

    def create(self, customer: str, amount: float, currency: str, items: List[Dict], inv_type: str = "electronic") -> Dict[str, Any]:
        inv_id = f"INV-2026-{uuid.uuid4().hex[:6].upper()}"
        inv = Invoice(invoice_id=inv_id, customer=customer, amount=amount, currency=currency, type=inv_type,
                      items=items, due_date=(datetime.now() + timedelta(days=30)).isoformat()[:10])
        self.invoices[inv_id] = inv
        return {"invoice_id": inv_id, "status": "draft", "amount": amount, "currency": currency}

    def send(self, invoice_id: str, method: str = "email") -> Dict[str, Any]:
        inv = self.invoices.get(invoice_id)
        if not inv:
            return {"error": "发票不存在"}
        inv.status = "sent"
        inv.sent_at = datetime.now().isoformat(timespec="seconds")
        inv.pdf_url = f"/invoices/{invoice_id}.pdf"
        return {"invoice_id": invoice_id, "status": "sent", "method": method}

    def list_invoices(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        result = []
        for inv in self.invoices.values():
            if status and inv.status != status:
                continue
            result.append({
                "invoice_id": inv.invoice_id, "customer": inv.customer,
                "amount": inv.amount, "currency": inv.currency, "tax_amount": inv.tax_amount,
                "status": inv.status, "type": inv.type, "issued_at": inv.issued_at, "due_date": inv.due_date,
            })
        return result


# ==================== 订阅计费 ====================

SUBSCRIPTION_PLANS: Dict[str, Dict[str, Any]] = {
    "free": {"name": "免费版", "price_monthly": 0, "price_yearly": 0, "features": ["基础扫描", "1个资产", "社区支持"], "limits": {"scans_per_month": 10, "assets": 1}},
    "basic": {"name": "基础版", "price_monthly": 29, "price_yearly": 290, "features": ["全扫描类型", "10个资产", "邮件支持", "月度报告"], "limits": {"scans_per_month": 100, "assets": 10}},
    "pro": {"name": "专业版", "price_monthly": 99, "price_yearly": 990, "features": ["无限扫描", "100个资产", "优先支持", "实时报告", "API访问", "团队协作"], "limits": {"scans_per_month": -1, "assets": 100}},
    "enterprise": {"name": "企业版", "price_monthly": 499, "price_yearly": 4990, "features": ["无限资产", "SLA支持", "定制报告", "SSO集成", "私有部署", "专属客户经理"], "limits": {"scans_per_month": -1, "assets": -1}},
}


class SubscriptionManager:
    """订阅计费管理器"""

    def __init__(self):
        self.subscriptions: Dict[str, Dict[str, Any]] = {}
        self.coupons: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self):
        plans = ["free", "basic", "pro", "enterprise"]
        for i in range(12):
            sid = f"SUB-{uuid.uuid4().hex[:8]}"
            plan = plans[i % len(plans)]
            p = SUBSCRIPTION_PLANS[plan]
            self.subscriptions[sid] = {
                "subscription_id": sid, "customer_email": f"user_{i:03d}@example.com",
                "plan": plan, "billing_cycle": "monthly" if i % 2 == 0 else "yearly",
                "status": ["active", "active", "trialing", "cancelled", "past_due"][i % 5],
                "amount": p["price_monthly"] if i % 2 == 0 else p["price_yearly"],
                "currency": "USD", "started_at": datetime.now().isoformat(timespec="seconds"),
                "next_renewal": (datetime.now() + timedelta(days=30)).isoformat(timespec="seconds"),
            }
        self.coupons = {
            "WELCOME10": {"code": "WELCOME10", "type": "percentage", "value": 10, "max_uses": 1000, "used": 156, "expires": "2026-12-31", "status": "active"},
            "SAVE50": {"code": "SAVE50", "type": "percentage", "value": 50, "max_uses": 100, "used": 87, "expires": "2026-09-30", "status": "active"},
            "FLAT20": {"code": "FLAT20", "type": "fixed", "value": 20, "currency": "USD", "max_uses": 500, "used": 203, "expires": "2026-11-30", "status": "active"},
        }

    def subscribe(self, customer_email: str, plan: str, billing_cycle: str = "monthly", coupon: str = "") -> Dict[str, Any]:
        if plan not in SUBSCRIPTION_PLANS:
            return {"error": "无效的套餐"}
        p = SUBSCRIPTION_PLANS[plan]
        amount = p["price_yearly"] if billing_cycle == "yearly" else p["price_monthly"]
        # 应用优惠券
        discount = 0.0
        if coupon and coupon in self.coupons:
            c = self.coupons[coupon]
            if c["type"] == "percentage":
                discount = amount * c["value"] / 100
            else:
                discount = c["value"]
            c["used"] += 1
        final_amount = amount - discount
        sid = f"SUB-{uuid.uuid4().hex[:8]}"
        self.subscriptions[sid] = {
            "subscription_id": sid, "customer_email": customer_email, "plan": plan,
            "billing_cycle": billing_cycle, "status": "active",
            "amount": final_amount, "original_amount": amount, "discount": discount,
            "currency": "USD", "coupon_used": coupon,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "next_renewal": (datetime.now() + timedelta(days=365 if billing_cycle == "yearly" else 30)).isoformat(timespec="seconds"),
        }
        return {"subscription_id": sid, "plan": plan, "amount": final_amount, "discount": discount, "status": "active"}

    def change_plan(self, subscription_id: str, new_plan: str) -> Dict[str, Any]:
        sub = self.subscriptions.get(subscription_id)
        if not sub:
            return {"error": "订阅不存在"}
        old_plan = sub["plan"]
        sub["plan"] = new_plan
        p = SUBSCRIPTION_PLANS[new_plan]
        sub["amount"] = p["price_yearly"] if sub["billing_cycle"] == "yearly" else p["price_monthly"]
        sub["changed_at"] = datetime.now().isoformat(timespec="seconds")
        return {"subscription_id": subscription_id, "old_plan": old_plan, "new_plan": new_plan, "status": "updated"}

    def cancel(self, subscription_id: str) -> Dict[str, Any]:
        sub = self.subscriptions.get(subscription_id)
        if not sub:
            return {"error": "订阅不存在"}
        sub["status"] = "cancelled"
        sub["cancelled_at"] = datetime.now().isoformat(timespec="seconds")
        return {"subscription_id": subscription_id, "status": "cancelled", "refund_proration": True}

    def stats(self) -> Dict[str, Any]:
        total = len(self.subscriptions)
        active = sum(1 for s in self.subscriptions.values() if s["status"] == "active")
        mrr = sum(s["amount"] for s in self.subscriptions.values() if s["status"] == "active" and s["billing_cycle"] == "monthly")
        arr = sum(s["amount"] for s in self.subscriptions.values() if s["status"] == "active" and s["billing_cycle"] == "yearly") / 12
        by_plan: Dict[str, int] = {}
        for s in self.subscriptions.values():
            if s["status"] == "active":
                by_plan[s["plan"]] = by_plan.get(s["plan"], 0) + 1
        return {"total_subscriptions": total, "active": active, "mrr_usd": round(mrr, 2),
                "arr_usd": round(arr * 12, 2), "by_plan": by_plan, "coupons_active": len(self.coupons)}


# ==================== 财务报告 ====================

class FinancialReport:
    """财务报告与分析"""

    def __init__(self):
        self.transactions: List[Dict[str, Any]] = []
        self._seed()

    def _seed(self):
        self.transactions = [
            {"date": "2026-04-01", "type": "revenue", "category": "subscription", "amount": 12500.00, "currency": "USD", "customer": "acme-corp"},
            {"date": "2026-04-03", "type": "revenue", "category": "professional_services", "amount": 5000.00, "currency": "USD", "customer": "startup-x"},
            {"date": "2026-04-05", "type": "expense", "category": "cloud_infrastructure", "amount": 3200.00, "currency": "USD", "vendor": "aws"},
            {"date": "2026-04-08", "type": "revenue", "category": "subscription", "amount": 8900.00, "currency": "EUR", "customer": "gmbh-berlin"},
            {"date": "2026-04-10", "type": "expense", "category": "salaries", "amount": 15000.00, "currency": "USD", "vendor": "payroll"},
            {"date": "2026-04-12", "type": "revenue", "category": "subscription", "amount": 1200000.00, "currency": "JPY", "customer": "kk-tokyo"},
            {"date": "2026-04-15", "type": "expense", "category": "marketing", "amount": 2000.00, "currency": "USD", "vendor": "google-ads"},
            {"date": "2026-04-18", "type": "revenue", "category": "consulting", "amount": 7500.00, "currency": "USD", "customer": "enterprise-ltd"},
            {"date": "2026-04-20", "type": "expense", "category": "payment_fees", "amount": 450.00, "currency": "USD", "vendor": "stripe"},
            {"date": "2026-04-22", "type": "revenue", "category": "subscription", "amount": 6700.00, "currency": "GBP", "customer": "london-co"},
        ]

    def income_statement(self) -> Dict[str, Any]:
        total_revenue = sum(t["amount"] for t in self.transactions if t["type"] == "revenue")
        total_expense = sum(t["amount"] for t in self.transactions if t["type"] == "expense")
        return {
            "period": "2026-04", "currency": "USD(汇总)",
            "total_revenue": round(total_revenue, 2),
            "total_expenses": round(total_expense, 2),
            "net_profit": round(total_revenue - total_expense, 2),
            "profit_margin": round((total_revenue - total_expense) / total_revenue * 100, 1) if total_revenue else 0,
            "revenue_breakdown": {"subscription": 12500 + 8900 + 1200000 + 6700, "professional_services": 5000, "consulting": 7500},
        }

    def cash_flow(self) -> Dict[str, Any]:
        inflow = sum(t["amount"] for t in self.transactions if t["type"] == "revenue")
        outflow = sum(t["amount"] for t in self.transactions if t["type"] == "expense")
        return {
            "period": "2026-04", "operating_inflow": round(inflow, 2),
            "operating_outflow": round(outflow, 2), "net_cash_flow": round(inflow - outflow, 2),
            "beginning_balance": 50000, "ending_balance": round(50000 + inflow - outflow, 2),
        }

    def forecast(self, months: int = 6) -> Dict[str, Any]:
        return {
            "horizon_months": months,
            "projection": [
                {"month": f"2026-{4+i+1:02d}", "projected_revenue": round(25000 * (1 + i * 0.08), 2), "projected_expenses": 18000}
                for i in range(months)
            ],
            "confidence": "medium", "assumptions": ["月增长8%", "费用稳定"],
        }


# ==================== 主管理器 ====================

class GlobalPaymentManager:
    """国际支付管理主类"""

    def __init__(self):
        self.exchange = ExchangeRateManager()
        self.tax = TaxManager()
        self.invoices = InvoiceManager()
        self.subscriptions = SubscriptionManager()
        self.financial = FinancialReport()

    def overview(self) -> Dict[str, Any]:
        return {
            "total_payment_methods": len(PAYMENT_METHODS),
            "total_currencies": len(CURRENCIES),
            "payment_methods": [{"id": k, **v} for k, v in PAYMENT_METHODS.items()],
            "currencies": [{"code": k, **v} for k, v in CURRENCIES.items()],
            "subscription_plans": SUBSCRIPTION_PLANS,
            "active_subscriptions": self.subscriptions.stats(),
            "recent_invoices": len(self.invoices.invoices),
            "tax_regions": len(TAX_RATES),
            "current_rates_vs_usd": self.exchange.get_rates("USD"),
        }


# 全局单例
global_payment = GlobalPaymentManager()
