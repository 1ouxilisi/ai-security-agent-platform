# -*- coding: utf-8 -*-
"""
commercial_ultra/commercial_ultra_dashboard.py — 商业极致仪表盘聚合。

聚合品牌官网 / 产品演示 / 客户门户 / 计费 / SLA / 备份 / 帮助中心。
"""

from __future__ import annotations

from typing import Any, Dict

from commercial_ultra.brand_website import get_brand_website
from commercial_ultra.product_demo import get_product_demo
from commercial_ultra.customer_portal_pro import get_customer_portal_pro
from commercial_ultra.billing_system_pro import get_billing_system_pro
from commercial_ultra.sla_monitor_pro import get_sla_monitor_pro
from commercial_ultra.backup_recovery import get_backup_recovery
from commercial_ultra.help_center import get_help_center


class CommercialUltraDashboard:
    """商业产品体验极致 · 聚合仪表盘。"""

    def overview(self) -> Dict[str, Any]:
        return {
            "brand": get_brand_website().analytics(),
            "portal": get_customer_portal_pro().overview("C-DEMO-00001"),
            "billing": get_billing_system_pro().admin_stats(),
            "sla": get_sla_monitor_pro().availability(),
            "backup": get_backup_recovery().summary(),
            "demo_scenes": len(get_product_demo().scenes()),
            "help_docs": len(get_help_center().docs()),
        }

    def scorecard(self) -> Dict[str, Dict[str, Any]]:
        sla = get_sla_monitor_pro().availability()
        bill = get_billing_system_pro().admin_stats()
        bak = get_backup_recovery().summary()
        return {
            "website": {"label": "品牌官网", "ok": True,
                        "detail": "首页/功能/定价/文档/联系 五页齐备"},
            "demo": {"label": "一键演示", "ok": True,
                     "detail": f"{len(get_product_demo().scenes())} 步引导 + 预置数据"},
            "portal": {"label": "客户门户", "ok": True,
                       "detail": "注册/项目/报告/账单/资料"},
            "billing": {"label": "计费系统", "ok": bill["invoices"] > 0,
                        "detail": f"按量+订阅，已开 {bill['invoices']} 张单"},
            "sla": {"label": "SLA 监控", "ok": sla["meets_target"],
                     "detail": f"可用性 {sla['availability_pct']}%（目标99.95%）"},
            "backup": {"label": "备份恢复", "ok": bak["backups"] > 0,
                       "detail": f"{bak['backups']} 个备份，保留 {bak['policy']['retain']} 份"},
            "help": {"label": "帮助中心", "ok": True,
                     "detail": f"文档 {len(get_help_center().docs())} / FAQ {len(get_help_center().faq())} / 视频 {len(get_help_center().videos())}"},
        }

    def all_in_one(self) -> Dict[str, Any]:
        """批量接口合并：一次拿全。"""
        return {
            "overview": self.overview(),
            "scorecard": self.scorecard(),
            "pricing": get_billing_system_pro().pricing(),
            "status_page": get_sla_monitor_pro().status_page(),
            "backup_policy": get_backup_recovery().get_policy(),
            "help_search_examples": ["扫描", "报告", "退款"],
        }


_dash: CommercialUltraDashboard | None = None


def get_commercial_ultra_dashboard() -> CommercialUltraDashboard:
    global _dash
    if _dash is None:
        _dash = CommercialUltraDashboard()
    return _dash
