#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ux_docs_deep/ux_docs_dashboard.py — 文档与UX控制台数据聚合层。

聚合 8 个视图：
    1. 文档总览：文章数/部署文档/API端点/教程/文档管理/性能指标/趋势
    2. 用户手册视图：分册/章节/文章列表/统计
    3. 部署文档视图：分类/平台/硬件/配置项
    4. API文档视图：端点/分类/Token/变更日志
    5. 前端UX视图：改进项/性能/设计令牌/无障碍/语言
    6. 新手引导视图：引导流程/教程/视频/学习路径/工单
    7. 文档管理视图：文档CRUD/版本/评论/分析
    8. 系统设置视图：全局配置/维护/版本信息
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .user_manual import get_user_manual_manager
from .deployment_docs import get_deployment_docs_manager
from .api_docs import get_api_docs_manager
from .frontend_ux import get_frontend_ux_manager
from .onboarding_tutorials import get_onboarding_manager
from .docs_management import get_docs_manager


# --------------------------------------------------------------------------- #
# 系统设置
# --------------------------------------------------------------------------- #
SYSTEM_SETTINGS: Dict[str, Any] = {
    "docs_version": "v28.4.0",
    "docs_locale": "zh-CN",
    "docs_theme": "dark",
    "search_enabled": True,
    "feedback_enabled": True,
    "rating_enabled": True,
    "comment_enabled": True,
    "version_preview": True,
    "ai_summary_enabled": True,
    "maintenance_mode": False,
    "scheduled_maintenance": None,
}


# --------------------------------------------------------------------------- #
# 控制台聚合器
# --------------------------------------------------------------------------- #
class UxDocsDashboard:
    """文档与UX控制台聚合器。"""

    def __init__(self) -> None:
        self.manual = get_user_manual_manager()
        self.deploy = get_deployment_docs_manager()
        self.api_docs = get_api_docs_manager()
        self.ux = get_frontend_ux_manager()
        self.onboard = get_onboarding_manager()
        self.docs = get_docs_manager()

    # ---- 1. 总览 ----
    def overview(self) -> Dict[str, Any]:
        m_stats = self.manual.stats()
        d_stats = self.deploy.stats()
        a_stats = self.api_docs.stats()
        u_stats = self.ux.stats()
        o_stats = self.onboard.stats()
        dm_stats = self.docs.analytics()

        # 7天趋势
        trend = []
        for i in range(7):
            day = time.strftime("%m-%d",
                                time.localtime(time.time() - (6 - i) * 86400))
            trend.append({
                "date": day,
                "doc_views": 1200 + i * 80,
                "api_calls": 8000 + i * 500,
                "tutorial_completions": 20 + i * 3,
                "feedback_items": 5 + i,
            })

        return {
            "manual": m_stats,
            "deployment": d_stats,
            "api": a_stats,
            "frontend_ux": u_stats,
            "onboarding": o_stats,
            "docs_management": dm_stats,
            "trend_7d": trend,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---- 2. 用户手册视图 ----
    def manual_view(self) -> Dict[str, Any]:
        return {
            "sections": self.manual.list_sections(),
            "articles": self.manual.list_articles(),
            "stats": self.manual.stats(),
        }

    # ---- 3. 部署文档视图 ----
    def deployment_view(self) -> Dict[str, Any]:
        return {
            "docs": self.deploy.list_docs(),
            "platforms": self.deploy.list_platforms(),
            "hardware": self.deploy.list_hardware(),
            "config_categories": self.deploy.list_config_categories(),
            "deploy_records": self.deploy.list_deploy_records(),
            "stats": self.deploy.stats(),
        }

    # ---- 4. API文档视图 ----
    def api_view(self) -> Dict[str, Any]:
        return {
            "overview": self.api_docs.overview(),
            "endpoints": self.api_docs.list_endpoints(include_deprecated=True),
            "tokens": self.api_docs.list_tokens(),
            "changes": self.api_docs.list_changes(),
            "stats": self.api_docs.stats(),
        }

    # ---- 5. 前端UX视图 ----
    def ux_view(self) -> Dict[str, Any]:
        return {
            "improvements": self.ux.list_improvements(),
            "perf": self.ux.list_perf(),
            "design_tokens": self.ux.get_design_tokens(),
            "a11y_rules": self.ux.list_a11y_rules(),
            "languages": self.ux.list_i18n_languages(),
            "stats": self.ux.stats(),
        }

    # ---- 6. 新手引导视图 ----
    def onboarding_view(self) -> Dict[str, Any]:
        return {
            "guide_flows": self.onboard.list_guide_flows(),
            "tutorials": self.onboard.list_tutorials(),
            "videos": self.onboard.list_videos(),
            "video_categories": self.onboard.list_video_categories(),
            "labs": self.onboard.list_labs(),
            "paths": self.onboard.list_learning_paths(),
            "tickets": self.onboard.list_tickets(),
            "stats": self.onboard.stats(),
        }

    # ---- 7. 文档管理视图 ----
    def docs_view(self) -> Dict[str, Any]:
        return {
            "docs": self.docs.list_docs(),
            "categories": self.docs.list_categories(),
            "roles": self.docs.list_roles(),
            "analytics": self.docs.analytics(),
        }

    # ---- 8. 系统设置视图 ----
    def settings_view(self) -> Dict[str, Any]:
        return {
            "settings": SYSTEM_SETTINGS,
            "version": "v28.4.0",
            "build_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "modules": [
                "user_manual", "deployment_docs", "api_docs",
                "frontend_ux", "onboarding_tutorials",
                "docs_management", "ux_docs_dashboard",
            ],
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_dashboard: Optional[UxDocsDashboard] = None


def get_ux_docs_dashboard() -> UxDocsDashboard:
    global _dashboard
    if _dashboard is None:
        _dashboard = UxDocsDashboard()
    return _dashboard
