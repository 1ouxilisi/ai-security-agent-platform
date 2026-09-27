# -*- coding: utf-8 -*-
"""
enterprise_dashboard.py — 企业管理控制台核心模块。

覆盖：
- 企业总览（租户/用户/活跃度/收入/用量/告警/趋势）
- 租户管理（列表/详情/配置/配额/状态/操作）
- 用户管理（列表/详情/状态/角色/分组/操作）
- 计费管理（订阅/账单/发票/支付/退款/收入统计）
- 运营分析（增长/活跃/留存/转化/churn/NPS/健康度）
- 系统设置（全局配置/默认配额/通知模板/邮件模板/品牌/域名/安全/审计）

全部内存字典模拟。
"""

from __future__ import annotations

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
    return obj


# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
class DashboardStore:
    def __init__(self) -> None:
        self.global_config: Dict[str, Any] = {}
        self.notification_templates: Dict[str, Dict[str, Any]] = {}
        self.email_templates: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = []
        self.brand_config: Dict[str, Any] = {}
        self.domain_config: Dict[str, Any] = {}
        self.security_policies: Dict[str, Any] = {}
        self.audit_config: Dict[str, Any] = {}
        self.metrics_history: List[Dict[str, Any]] = []
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        self.global_config = {
            "platform_name": "AI Hacking Agent 企业版",
            "default_plan": "free",
            "default_timezone": "Asia/Shanghai",
            "session_timeout_min": 60,
            "max_login_attempts": 5,
            "password_min_length": 12,
        }
        self.brand_config = {
            "logo_url": "", "primary_color": "#6366f1",
            "secondary_color": "#8b5cf6",
            "company_name": "AI Hacking Agent",
            "support_email": "support@aihacking.io",
        }
        self.domain_config = {
            "primary_domain": "app.aihacking.io",
            "custom_domains": [], "ssl_enabled": True,
        }
        self.security_policies = {
            "mfa_required": False,
            "ip_whitelist": [],
            "password_policy": {"min_length": 12, "require_mixed": True,
                                "expire_days": 90},
            "session_policy": {"timeout_min": 60,
                               "max_concurrent": 3},
        }
        self.audit_config = {
            "log_retention_days": 365,
            "log_level": "info",
            "hash_chain_enabled": True,
            "real_time_alert": True,
        }
        self.notification_templates = {
            "subscription_renewal": {
                "name": "订阅续费提醒", "channel": "email",
                "subject": "您的订阅即将到期",
                "body": "尊敬的{{name}}，您的{{plan}}订阅将于{{date}}到期，请及时续费。",
                "enabled": True,
            },
            "quota_warning": {
                "name": "配额告警", "channel": "in_app",
                "subject": "配额使用警告",
                "body": "您的{{metric}}已使用{{pct}}%，请关注用量。",
                "enabled": True,
            },
            "security_alert": {
                "name": "安全告警", "channel": "sms",
                "subject": "安全异常提醒",
                "body": "检测到异常登录：{{detail}}",
                "enabled": True,
            },
        }
        self.email_templates = {
            "welcome": {
                "name": "欢迎邮件", "subject": "欢迎使用AI Hacking Agent",
                "body": "欢迎{{name}}，您已成功注册...",
            },
            "invoice": {
                "name": "发票邮件", "subject": "您的电子发票",
                "body": "请查收您的发票：{{invoice_url}}",
            },
        }


_store = DashboardStore()


# --------------------------------------------------------------------------- #
# 1. 企业总览
# --------------------------------------------------------------------------- #
def get_overview() -> Dict[str, Any]:
    """企业级总览仪表盘数据。"""
    from . import multi_tenant, billing_system, sso_identity

    tenants = list(multi_tenant._store.tenants.values())
    users = list(multi_tenant._store.users.values())
    active_users = [u for u in users if u["status"] == "active"]
    active_tenants = [t for t in tenants if t["status"] == "active"]

    revenue = billing_system.revenue_stats()
    sso_sessions = sso_identity.get_active_sessions()

    # 模拟趋势数据
    trend_7d = [
        {"date": f"2026-09-{d:02d}",
         "new_users": 5 + (d % 3) * 2,
         "new_tenants": (d % 2),
         "revenue": 2000 + d * 150}
        for d in range(9, 16)
    ]

    return {
        "kpis": {
            "total_tenants": len(tenants),
            "active_tenants": len(active_tenants),
            "total_users": len(users),
            "active_users": len(active_users),
            "active_sessions": len(sso_sessions),
            "total_revenue": revenue["total_revenue"],
            "mrr": revenue["mrr"],
            "arr": revenue["arr"],
        },
        "trend_7d": trend_7d,
        "alerts": _store.alerts[-10:],
        "quota_alerts": [
            {"tenant": t["name"], "metric": "API调用",
             "pct": 85 + (i % 10), "level": "warning"}
            for i, t in enumerate(active_tenants[:3])
        ],
    }


# --------------------------------------------------------------------------- #
# 2. 租户管理
# --------------------------------------------------------------------------- #
def tenant_management_list(status: str = "",
                            page: int = 1,
                            page_size: int = 20) -> Dict[str, Any]:
    from . import multi_tenant
    return multi_tenant.list_tenants(status=status, page=page,
                                      page_size=page_size)


def tenant_detail(tenant_id: str) -> Dict[str, Any]:
    from . import multi_tenant, billing_system
    t = multi_tenant.get_tenant(tenant_id)
    if not t:
        return {}
    stats = multi_tenant.tenant_stats(tenant_id)
    sub = billing_system.get_subscription(tenant_id)
    usage = billing_system.get_usage_summary(tenant_id)
    return {
        "tenant": t, "stats": stats,
        "subscription": sub, "usage": usage,
    }


# --------------------------------------------------------------------------- #
# 3. 用户管理
# --------------------------------------------------------------------------- #
def user_management_list(tenant_id: str = "",
                         status: str = "",
                         page: int = 1,
                         page_size: int = 20) -> Dict[str, Any]:
    from . import multi_tenant
    return multi_tenant.list_users(tenant_id=tenant_id, status=status,
                                   page=page, page_size=page_size)


# --------------------------------------------------------------------------- #
# 4. 计费管理
# --------------------------------------------------------------------------- #
def billing_overview() -> Dict[str, Any]:
    from . import billing_system
    revenue = billing_system.revenue_stats()
    subs = billing_system.list_subscriptions()
    pending_invoices = billing_system.list_invoices(status="pending")
    return {
        "revenue": revenue,
        "subscriptions": subs,
        "pending_invoices": pending_invoices,
        "refunds": billing_system.list_refunds(),
    }


# --------------------------------------------------------------------------- #
# 5. 运营分析
# --------------------------------------------------------------------------- #
def operational_analytics(period: str = "30d") -> Dict[str, Any]:
    """运营分析数据。"""
    from . import multi_tenant
    users = list(multi_tenant._store.users.values())
    tenants = list(multi_tenant._store.tenants.values())

    # 模拟运营指标
    return {
        "period": period,
        "user_growth": {
            "new_users_30d": 45, "total_users": len(users),
            "growth_rate_pct": 12.5,
        },
        "engagement": {
            "daily_active_users": 120,
            "weekly_active_users": 340,
            "monthly_active_users": len(users),
            "avg_session_min": 22,
        },
        "retention": {
            "day1": 85.2, "day7": 62.8, "day30": 45.1,
            "churn_rate_pct": 3.2,
        },
        "conversion": {
            "free_to_paid_pct": 8.5,
            "trial_to_paid_pct": 15.2,
        },
        "nps": {"score": 42, "promoters_pct": 55,
                "passives_pct": 28, "detractors_pct": 17},
        "customer_health": {
            "healthy": len([t for t in tenants if t["status"] == "active"]) * 2,
            "at_risk": 3,
            "churn_risk": 1,
        },
        "mrr_growth": [
            {"month": "2026-04", "mrr": 12000},
            {"month": "2026-05", "mrr": 15500},
            {"month": "2026-06", "mrr": 18200},
            {"month": "2026-07", "mrr": 21000},
            {"month": "2026-08", "mrr": 24800},
            {"month": "2026-09", "mrr": 28500},
        ],
    }


# --------------------------------------------------------------------------- #
# 6. 系统设置
# --------------------------------------------------------------------------- #
def get_system_settings() -> Dict[str, Any]:
    return {
        "global_config": _store.global_config,
        "brand": _store.brand_config,
        "domain": _store.domain_config,
        "security_policies": _store.security_policies,
        "audit_config": _store.audit_config,
        "notification_templates": _store.notification_templates,
        "email_templates": _store.email_templates,
    }


def update_system_settings(section: str,
                           updates: Dict[str, Any]) -> Dict[str, Any]:
    mapping = {
        "global": _store.global_config,
        "brand": _store.brand_config,
        "domain": _store.domain_config,
        "security": _store.security_policies,
        "audit": _store.audit_config,
    }
    target = mapping.get(section)
    if target is None:
        return {"success": False, "error": f"未知配置段: {section}"}
    target.update(updates)
    return {"success": True, "section": section,
            "updated": True, "data": target}


def update_notification_template(template_id: str,
                                  updates: Dict[str, Any]) -> Dict[str, Any]:
    t = _store.notification_templates.get(template_id)
    if not t:
        return {"success": False, "error": "模板不存在"}
    t.update(updates)
    return {"success": True, "template": t}


def get_alerts() -> List[Dict[str, Any]]:
    return list(_store.alerts)


def create_alert(level: str, title: str, message: str) -> Dict[str, Any]:
    alert = {
        "id": _uid("alr_"), "level": level,
        "title": title, "message": message,
        "status": "active", "created_at": _now(),
    }
    _store.alerts.append(alert)
    return alert


def get_store() -> DashboardStore:
    return _store
