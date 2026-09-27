# -*- coding: utf-8 -*-
"""super_homepage — 方向3：极致用户体验（超级首页 / 智能引导 / 全局搜索 / 快速操作）。"""

from __future__ import annotations

__version__ = "3.0.0"
__direction__ = "D3-极致用户体验"

from .homepage_config import (
    get_homepage_config,
    THEME,
    FEATURE_CARDS,
    QUICK_STATS,
    NAV_GROUPS,
    RESPONSIVE,
)
from .smart_guide import get_smart_guide_manager, GUIDE_FLOW
from .global_search import get_global_search, SearchItem
from .quick_actions import get_quick_actions_manager, QUICK_ACTIONS
from .ux_dashboard import get_ux_dashboard, UX_LATEST_ACTIVITY

__all__ = [
    "get_homepage_config",
    "THEME",
    "FEATURE_CARDS",
    "QUICK_STATS",
    "NAV_GROUPS",
    "RESPONSIVE",
    "get_smart_guide_manager",
    "GUIDE_FLOW",
    "get_global_search",
    "SearchItem",
    "get_quick_actions_manager",
    "QUICK_ACTIONS",
    "get_ux_dashboard",
    "UX_LATEST_ACTIVITY",
]
