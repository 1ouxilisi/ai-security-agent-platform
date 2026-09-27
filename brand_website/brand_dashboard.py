# -*- coding: utf-8 -*-
"""
brand_website/brand_dashboard.py — 品牌官网控制台总览模块。

聚合内容、产品、商业、支持、营销五大域的数据，输出运营仪表盘。
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from . import content_manager as cm
from . import product_showcase as ps
from . import pricing_purchase as pp
from . import docs_support as ds
from . import blog_marketing as bm


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


class BrandDashboard:
    """聚合控制台数据。"""

    def overview(self) -> Dict[str, Any]:
        orders = list(pp.ORDERS.values())
        paid = [o for o in orders if o["status"] == "已支付"]
        revenue = sum(float(o["total"]) for o in paid)
        trials = list(pp.TRIALS.values())
        visitors = bm.ANALYTICS.get("daily", [])
        uv_30d = sum(v["uv"] for v in visitors)
        pv_30d = sum(v["pv"] for v in visitors)
        registrations = bm.ANALYTICS.get("funnel", [{}])
        reg_count = registrations[1]["count"] if len(registrations) > 1 else 0
        trial_count = registrations[2]["count"] if len(registrations) > 2 else 0
        pay_count = registrations[3]["count"] if len(registrations) > 3 else 0
        conversion = round(pay_count / max(1, reg_count) * 100, 2)
        return {
            "updated_at": _now(),
            "kpis": {
                "visits_30d": pv_30d,
                "uv_30d": uv_30d,
                "registrations": reg_count,
                "trials": trial_count,
                "purchases": pay_count,
                "revenue_cny": revenue,
                "conversion_rate": conversion,
            },
            "content_counts": {
                "pages": len(cm.PAGES),
                "media": len(cm.MEDIA),
                "posts": len(bm.POSTS),
                "docs": len(ds.DOCS),
            },
            "product_counts": {
                "products": len(ps.PRODUCTS),
                "features": len(ps.FEATURES),
                "cases": len(ps.CASES),
                "partners": len(ps.PARTNERS),
            },
            "business_counts": {
                "orders": len(orders),
                "paid_orders": len(paid),
                "coupons": len(pp.COUPONS),
                "trials": len(trials),
                "custom_requests": len(pp.CUSTOM_ENT),
            },
            "support_counts": {
                "kb_articles": len(ds.KB),
                "threads": len(ds.THREADS),
                "tickets": len(ds.TICKETS),
                "videos": len(ds.VIDEOS),
            },
        }

    def content_health(self) -> Dict[str, Any]:
        pages = list(cm.PAGES.values())
        published = [p for p in pages if p["status"] == "已发布"]
        drafts = [p for p in pages if p["status"] == "草稿"]
        return {
            "total_pages": len(pages),
            "published": len(published),
            "drafts": len(drafts),
            "offline": len([p for p in pages if p["status"] == "已下线"]),
            "media_total": len(cm.MEDIA),
            "nav_menus": list(cm.NAV_MENUS.keys()),
            "languages": cm.I18nManager().list_languages(),
        }

    def business_stats(self) -> Dict[str, Any]:
        orders = list(pp.ORDERS.values())
        paid = [o for o in orders if o["status"] == "已支付"]
        revenue = sum(float(o["total"]) for o in paid)
        trial_stat = pp.PricingPurchase().trial_stats()
        return {
            "total_orders": len(orders),
            "paid_orders": len(paid),
            "revenue_cny": revenue,
            "avg_order_value": round(revenue / max(1, len(paid)), 2),
            "coupons_active": len([c for c in pp.COUPONS.values()
                                   if c["status"] == "active"]),
            "trial": trial_stat,
            "custom_pipeline": len(pp.CUSTOM_ENT),
        }

    def support_satisfaction(self) -> Dict[str, Any]:
        tickets = list(ds.TICKETS.values())
        closed = [t for t in tickets if t["status"] == "已关闭"]
        return {
            "tickets_total": len(tickets),
            "tickets_open": len([t for t in tickets if t["status"] == "待受理"]),
            "tickets_resolved": len(closed),
            "kb_articles": len(ds.KB),
            "forum_threads": len(ds.THREADS),
            "videos": len(ds.VIDEOS),
            "chat_sessions": len(ds.CHATS),
            "resolution_rate": round(len(closed) / max(1, len(tickets)) * 100, 1),
        }

    def marketing_roi(self) -> Dict[str, Any]:
        analytics = bm.BlogMarketing().analytics()
        campaigns = list(bm.EMAIL_CAMPAIGNS.values())
        open_rate = round(sum(c["open_rate"] for c in campaigns) / max(1, len(campaigns)), 3)
        ctr = round(sum(c["ctr"] for c in campaigns) / max(1, len(campaigns)), 3)
        return {
            "seo": bm.SEO_REPORT,
            "social": [{"platform": s["platform"], "followers": s["followers"]}
                      for s in bm.SOCIAL_ACCOUNTS.values()],
            "email": {"campaigns": len(campaigns),
                      "avg_open_rate": open_rate, "avg_ctr": ctr},
            "analytics_summary": analytics["summary"],
            "funnel": analytics["funnel"],
        }

    def traffic_trend(self, days: int = 30) -> Dict[str, Any]:
        daily = bm.ANALYTICS.get("daily", [])[-days:]
        return {
            "days": [d["date"] for d in daily],
            "pv": [d["pv"] for d in daily],
            "uv": [d["uv"] for d in daily],
        }
