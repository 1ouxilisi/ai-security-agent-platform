#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
super_homepage/ux_dashboard.py — 超级首页数据聚合层。

聚合：快速统计（已扫描目标/已发现漏洞/待处理报告）、最近操作记录、
功能卡片、导航分组、智能引导状态、快速操作。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

from .homepage_config import get_homepage_config
from .smart_guide import get_smart_guide_manager
from .global_search import get_global_search
from .quick_actions import get_quick_actions_manager


# 最近操作记录（演示数据，运行时由接口追加）
UX_LATEST_ACTIVITY: List[Dict[str, Any]] = [
    {"id": "act_1", "icon": "🔍", "text": "对 shop.example.com 发起 Web 扫描",
     "time": "2 分钟前", "route": "/web-pentest-full"},
    {"id": "act_2", "icon": "🐛", "text": "确认 1 个高危漏洞：SQL 注入",
     "time": "18 分钟前", "route": "/vuln-management"},
    {"id": "act_3", "icon": "📑", "text": "生成《Q3 季度渗透报告》",
     "time": "1 小时前", "route": "/report-pro"},
    {"id": "act_4", "icon": "🎯", "text": "新增目标 api.example.com",
     "time": "3 小时前", "route": "/web-pentest-full"},
    {"id": "act_5", "icon": "✅", "text": "处理完毕 3 个中危漏洞",
     "time": "昨天 18:42", "route": "/vuln-management"},
]


class UxDashboard:
    """超级首页聚合器。"""

    def __init__(self) -> None:
        self.cfg = get_homepage_config()
        self.guide = get_smart_guide_manager()
        self.search = get_global_search()
        self.quick = get_quick_actions_manager()
        self._activity: List[Dict[str, Any]] = list(UX_LATEST_ACTIVITY)

    # ---- 快速统计（模拟实时数字）----
    def quick_stats(self) -> List[Dict[str, Any]]:
        # 模拟口径数字
        values = {
            "targets_scanned": 1286,
            "vulns_discovered": 4523,
            "reports_pending": 5,
            "assets_managed": 764,
        }
        out = []
        for s in self.cfg.quick_stats:
            item = dict(s)
            item["value"] = values.get(s["id"], 0)
            out.append(item)
        return out

    # ---- 最近操作 ----
    def recent_activity(self, limit: int = 8) -> List[Dict[str, Any]]:
        return list(reversed(self._activity))[:limit]

    def add_activity(self, icon: str, text: str, route: str = "") -> Dict[str, Any]:
        rec = {
            "id": f"act_{int(time.time()*1000)}",
            "icon": icon, "text": text,
            "time": "刚刚", "route": route,
        }
        self._activity.append(rec)
        if len(self._activity) > 50:
            self._activity = self._activity[-50:]
        return rec

    # ---- 首页聚合 ----
    def homepage(self, user_id: str = "default") -> Dict[str, Any]:
        return {
            "hero": {
                "title": "安全作战指挥台",
                "subtitle": "打开就会用：扫描目标 → 查看结果 → 生成报告",
                "theme": self.cfg.theme,
            },
            "feature_cards": self.cfg.feature_cards,
            "quick_stats": self.quick_stats(),
            "quick_actions": self.quick.list(),
            "recent_activity": self.recent_activity(),
            "guide": self.guide.get_state(user_id),
            "nav_groups": self.cfg.nav_groups,
        }

    def overview(self) -> Dict[str, Any]:
        return {
            "theme": self.cfg.theme,
            "feature_cards": self.cfg.feature_cards,
            "quick_stats": self.quick_stats(),
            "quick_actions": self.quick.list(),
            "recent_activity": self.recent_activity(),
            "nav_groups": self.cfg.nav_groups,
            "nav_item_count": self.cfg.nav_item_count(),
            "guide_stats": self.guide.stats(),
            "search_stats": self.search.stats(),
            "quick_stats_exec": self.quick.stats(),
            "responsive": self.cfg.responsive,
        }


_dashboard: UxDashboard | None = None


def get_ux_dashboard() -> UxDashboard:
    global _dashboard
    if _dashboard is None:
        _dashboard = UxDashboard()
    return _dashboard
