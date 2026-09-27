# -*- coding: utf-8 -*-
"""
ux_upgrade/ux_upgrade_dashboard.py — UX 升级聚合

聚合：超级首页 V2 / 智能引导 V2 / 移动端适配 / 暗色主题 / 全局搜索 V2。
"""
from __future__ import annotations

from typing import Any, Dict

from .super_homepage_v2 import get_homepage_v2
from .smart_guide_v2 import get_smart_guide_v2
from .mobile_adaptive import get_mobile_adaptive, BREAKPOINT
from .dark_theme import get_dark_theme
from .global_search_v2 import get_global_search_v2


class UXUpgradeDashboard:
    """UX 升级能力聚合。"""

    def overview(self) -> Dict[str, Any]:
        theme = get_dark_theme().current()
        return {
            "module": "用户体验大升级",
            "version": "2.0",
            "target_score": 9.5,
            "theme_mode": theme["mode"],
            "palette": theme["palette"],
            "features": {
                "super_homepage": True,
                "smart_guide": True,
                "mobile_adaptive": True,
                "dark_theme": True,
                "global_search": True,
            },
            "search_index_size": get_global_search_v2().index_size(),
            "mobile_breakpoint": BREAKPOINT,
            "shortcuts": [
                {"key": "Ctrl+K", "action": "打开全局搜索"},
                {"key": "Esc", "action": "关闭浮层"},
            ],
        }


_ux_singleton: UXUpgradeDashboard | None = None


def get_ux_dashboard() -> UXUpgradeDashboard:
    global _ux_singleton
    if _ux_singleton is None:
        _ux_singleton = UXUpgradeDashboard()
    return _ux_singleton
