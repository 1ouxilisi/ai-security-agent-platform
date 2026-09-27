# -*- coding: utf-8 -*-
"""
ux_upgrade 包 — 方向5：用户体验大升级

超级首页 V2 / 智能引导 V2 / 移动端适配 / 暗色主题 / 全局搜索 V2 / UX 聚合。
"""
from __future__ import annotations

from .super_homepage_v2 import SuperHomepageV2, get_homepage_v2, ACTIVITY
from .smart_guide_v2 import (
    SmartGuideV2, get_smart_guide_v2, GUIDE_STEPS, TOOLTIPS, ERROR_FIX,
)
from .mobile_adaptive import (
    MobileAdaptive, get_mobile_adaptive, BREAKPOINT, RESPONSIVE_CONFIG,
)
from .dark_theme import DarkTheme, get_dark_theme, DARK_PALETTE
from .global_search_v2 import GlobalSearchV2, get_global_search_v2, INDEX
from .ux_upgrade_dashboard import UXUpgradeDashboard, get_ux_dashboard

__all__ = [
    "SuperHomepageV2", "get_homepage_v2", "ACTIVITY",
    "SmartGuideV2", "get_smart_guide_v2", "GUIDE_STEPS", "TOOLTIPS", "ERROR_FIX",
    "MobileAdaptive", "get_mobile_adaptive", "BREAKPOINT", "RESPONSIVE_CONFIG",
    "DarkTheme", "get_dark_theme", "DARK_PALETTE",
    "GlobalSearchV2", "get_global_search_v2", "INDEX",
    "UXUpgradeDashboard", "get_ux_dashboard",
]
