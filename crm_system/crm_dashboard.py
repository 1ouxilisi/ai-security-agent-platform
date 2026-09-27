# -*- coding: utf-8 -*-
"""crm_dashboard.py — CRM 管理控制台。

销售 / 客户 / 收入 / 服务 / 营销仪表盘 + 系统设置。
"""

from __future__ import annotations

from typing import Any, Dict, List

from crm_system import DB, seed_if_needed, now_str
from crm_system.customer_manager import manager as customer_mgr
from crm_system.sales_pipeline import pipeline
from crm_system.communication_activity import comm
from crm_system.product_pricing import pricing
from crm_system.customer_service import service as service_mgr


class CRMDashboard:
    """六大仪表盘聚合。"""

    # ------------------------------------------------------------------ #
    # 销售仪表盘
    # ------------------------------------------------------------------ #
    def sales_dashboard(self) -> Dict[str, Any]:
        funnel = pipeline.funnel()
        opps = pipeline.list_opportunities()
        owners: Dict[str, float] = {}
        for o in opps:
            if o.get("status") == "open":
                owners[o.get("owner", "未分配")] = owners.get(o.get("owner", "未分配"), 0) + float(o.get("amount", 0))
        ranking = sorted(owners.items(), key=lambda x: x[1], reverse=True)
        target = 1000000.0
        return {
            "sales_target": target,
            "achieved": funnel["won_amount"],
            "completion_rate": round(funnel["won_amount"] / target, 3),
            "open_deals": funnel["total_open"],
            "open_amount": funnel["total_open_amount"],
            "weighted_forecast": funnel["weighted_forecast"],
            "conversion_rate": funnel["overall_win_rate"],
            "avg_cycle_days": 32,
            "funnel": funnel["stages"],
            "owner_ranking": [{"owner": k, "amount": round(v, 2)} for k, v in ranking],
            "trend": self._mock_trend(funnel["won_amount"]),
        }

    # ------------------------------------------------------------------ #
    # 客户仪表盘
    # ------------------------------------------------------------------ #
    def customer_dashboard(self) -> Dict[str, Any]:
        seg = customer_mgr.segments()
        customers = customer_mgr.list_customers()
        vip = [c for c in customers if c.get("level") == "A"]
        churned = [c for c in customers if c.get("stage") == "流失"]
        healthy = [c for c in customers if c.get("health_score", 0) >= 80]
        return {
            "total": seg["total"],
            "new_this_month": 3,
            "churned": len(churned),
            "vip_count": len(vip),
            "healthy_count": len(healthy),
            "by_stage": seg["by_stage"],
            "by_industry": seg["by_industry"],
            "by_region": seg["by_region"],
            "by_level": seg["by_level"],
            "health_distribution": {
                "健康": len(healthy),
                "关注": len([c for c in customers if 60 <= c.get("health_score", 0) < 80]),
                "风险": len([c for c in customers if 40 <= c.get("health_score", 0) < 60]),
                "流失预警": len([c for c in customers if c.get("health_score", 0) < 40]),
            },
        }

    # ------------------------------------------------------------------ #
    # 收入仪表盘
    # ------------------------------------------------------------------ #
    def revenue_dashboard(self) -> Dict[str, Any]:
        rev = pricing.revenue_summary()
        customers = customer_mgr.list_customers()
        paid = [c for c in customers if c.get("stage") in ("付费", "续费", "增购")]
        arpu = round(rev["total_revenue"] / max(1, len(paid)), 2)
        ltv = round(arpu * 2.6, 2)
        rev["arpu"] = arpu
        rev["ltv"] = ltv
        rev["forecast_next_quarter"] = round(rev["total_revenue"] * 1.15, 2)
        rev["trend"] = self._mock_trend(rev["total_revenue"])
        return rev

    # ------------------------------------------------------------------ #
    # 服务仪表盘
    # ------------------------------------------------------------------ #
    def service_dashboard(self) -> Dict[str, Any]:
        report = service_mgr.service_report()
        return {
            "tickets": {
                "total": report["total_tickets"],
                "resolved": report["resolved"],
                "open": report["open"],
            },
            "avg_response_time_min": report["avg_response_time_min"],
            "avg_resolution_time_hours": report["avg_resolution_time_hours"],
            "sla_compliance": report["sla_compliance"],
            "first_contact_resolution": report["first_contact_resolution"],
            "satisfaction_avg": report["avg_rating"],
            "by_priority": report["by_priority"],
            "by_category": report["by_category"],
            "trend": self._mock_trend(report["resolved"] * 100),
        }

    # ------------------------------------------------------------------ #
    # 营销仪表盘
    # ------------------------------------------------------------------ #
    def marketing_dashboard(self) -> Dict[str, Any]:
        seg = customer_mgr.segments()
        acts = comm.list_activities()
        estats = comm.email_stats()
        total_cost = sum(float(a.get("cost", 0)) for a in acts)
        total_rev = sum(float(a.get("revenue_generated", 0)) for a in acts)
        return {
            "leads_total": seg["by_source"].get("官网咨询", 0) + seg["by_source"].get("广告投放", 0),
            "by_source": seg["by_source"],
            "conversion_to_paid": round(
                seg["by_stage"].get("付费", 0) / max(1, seg["total"]), 3),
            "activities": len(acts),
            "activity_cost": total_cost,
            "activity_revenue": total_rev,
            "activity_roi": round((total_rev - total_cost) / max(1.0, total_cost), 3),
            "email": estats,
            "call": comm.call_stats(),
            "marketing_cost_total": round(total_cost * 1.2, 2),
        }

    # ------------------------------------------------------------------ #
    # 系统设置
    # ------------------------------------------------------------------ #
    def system_settings(self) -> Dict[str, Any]:
        seed_if_needed()
        with DB.lock:
            users = list(DB.users)
            audit = list(DB.audit_log[-20:])
        return {
            "users": users,
            "roles": [
                {"name": "销售经理", "permissions": ["customer:read", "deal:write"]},
                {"name": "销售总监", "permissions": ["customer:*", "deal:*"]},
                {"name": "客服主管", "permissions": ["ticket:*", "customer:read"]},
                {"name": "管理员", "permissions": ["*"]},
            ],
            "departments": ["销售一部", "销售二部", "客户成功部", "市场部", "客服部"],
            "custom_fields": [
                {"key": "行业标签", "type": "select"},
                {"key": "客群", "type": "select"},
            ],
            "workflows": [
                {"name": "新客户自动分配", "trigger": "创建客户", "action": "按区域分配销售"},
                {"name": "高风险客户预警", "trigger": "健康度<40", "action": "通知客户成功经理"},
            ],
            "integrations": ["邮件", "企业微信", "电子签", "电话"],
            "audit_log": audit,
            "server_time": now_str(),
        }

    # ------------------------------------------------------------------ #
    @staticmethod
    def _mock_trend(value: float) -> List[Dict[str, Any]]:
        import random
        random.seed(int(value) if value else 42)
        out = []
        for m in range(6):
            out.append({"month": f"{m + 1}月",
                        "value": round(value * (0.6 + random.random() * 0.5), 2)})
        return out


dashboard = CRMDashboard()

__all__ = ["CRMDashboard", "dashboard"]
