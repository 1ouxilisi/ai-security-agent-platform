#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
super_homepage/homepage_config.py — 超级首页静态配置。

包含：
    1. 深色专业主题配色（#0d1117 背景 / #161b22 卡片 / #58a6ff 强调色）
    2. 核心功能大卡片：Web渗透 / 内网渗透 / SRC挖洞 / 报告中心
    3. 快速统计口径
    4. 侧边栏导航分组（141 个页面收敛到 8 个导航组）
    5. 响应式断点（768px）
"""

from __future__ import annotations

from typing import Any, Dict, List


# --------------------------------------------------------------------------- #
# 1. 深色专业主题
# --------------------------------------------------------------------------- #
THEME: Dict[str, Any] = {
    "name": "dark-pro",
    "display_name": "深色专业安全",
    "mode": "dark",
    "colors": {
        "bg_base": "#0d1117",        # 全局背景
        "bg_elevated": "#161b22",    # 卡片 / 抬层
        "bg_inset": "#010409",       # 输入框 / 内嵌
        "border_default": "#30363d",
        "border_strong": "#8b949e",
        "accent": "#58a6ff",         # 主强调
        "accent_hover": "#79b8ff",
        "text_primary": "#e6edf3",
        "text_secondary": "#8b949e",
        "text_muted": "#6e7681",
        "success": "#3fb950",
        "warning": "#d29922",
        "danger": "#f85149",
        "critical": "#ff7b72",
        "info": "#39d2c0",
        "chip_bg": "#1c2129",
    },
    "radius": {
        "card": "14px",
        "button": "10px",
        "input": "10px",
    },
    "shadow": {
        "card": "0 8px 24px rgba(1,4,9,0.5)",
        "hover": "0 12px 32px rgba(88,166,255,0.18)",
    },
    "font": {
        "family": "'Inter','PingFang SC','Microsoft YaHei',system-ui,sans-serif",
        "hero_size": "clamp(28px,4vw,44px)",
        "card_title_size": "20px",
        "body_size": "15px",
    },
}


# --------------------------------------------------------------------------- #
# 2. 核心功能大卡片
# --------------------------------------------------------------------------- #
FEATURE_CARDS: List[Dict[str, Any]] = [
    {
        "id": "web_pentest",
        "title": "Web 渗透",
        "subtitle": "指纹 · 目录 · 漏洞 · 利用",
        "icon": "🌐",
        "accent": "#58a6ff",
        "route": "/web-pentest-full",
        "description": "从指纹识别到利用验证，一条龙完成 Web 应用渗透测试。",
        "quick_stats": {"running_tasks": 3, "today_findings": 17},
        "hot_keys": ["指纹识别", "目录扫描", "SQL注入", "XSS"],
    },
    {
        "id": "internal_pentest",
        "title": "内网渗透",
        "subtitle": "横向移动 · 权限维持",
        "icon": "🕸️",
        "accent": "#39d2c0",
        "route": "/internal-pentest",
        "description": "域内信息收集、横向移动、凭证窃取与权限维持全链路。",
        "quick_stats": {"running_tasks": 1, "lateral_hosts": 42},
        "hot_keys": ["域控定位", "票据传递", "横向移动", "持久化"],
    },
    {
        "id": "src_bounty",
        "title": "SRC 挖洞",
        "subtitle": "资产测绘 · 漏洞提交",
        "icon": "🎯",
        "accent": "#d29922",
        "route": "/src-workbench",
        "description": "批量资产测绘、自动挖洞、报告一键提交 SRC 平台。",
        "quick_stats": {"pending_reports": 5, "this_month_reward": 12800},
        "hot_keys": ["资产收集", "批量POC", "漏洞提交", "奖励跟踪"],
    },
    {
        "id": "report_center",
        "title": "报告中心",
        "subtitle": "生成 · 对比 · 导出",
        "icon": "📑",
        "accent": "#f85149",
        "route": "/report-pro",
        "description": "专业安全报告一键生成，支持历史对比与多格式导出。",
        "quick_stats": {"total_reports": 234, "pending_review": 5},
        "hot_keys": ["一键生成", "报告对比", "PDF导出", "图表分析"],
    },
]


# --------------------------------------------------------------------------- #
# 3. 快速统计口径
# --------------------------------------------------------------------------- #
QUICK_STATS: List[Dict[str, Any]] = [
    {
        "id": "targets_scanned",
        "label": "已扫描目标",
        "unit": "个",
        "icon": "🎯",
        "accent": "#58a6ff",
        "trend": "+12%",
    },
    {
        "id": "vulns_discovered",
        "label": "已发现漏洞",
        "unit": "个",
        "icon": "🐛",
        "accent": "#f85149",
        "trend": "+8%",
    },
    {
        "id": "reports_pending",
        "label": "待处理报告",
        "unit": "份",
        "icon": "📑",
        "accent": "#d29922",
        "trend": "-3",
    },
    {
        "id": "assets_managed",
        "label": "已纳管资产",
        "unit": "台",
        "icon": "🖥️",
        "accent": "#39d2c0",
        "trend": "+21",
    },
]


# --------------------------------------------------------------------------- #
# 4. 侧边栏导航分组（把 141 个页面收敛成 8 组）
# --------------------------------------------------------------------------- #
NAV_GROUPS: List[Dict[str, Any]] = [
    {
        "id": "home",
        "title": "总览",
        "icon": "🏠",
        "items": [
            {"id": "super_home", "title": "超级首页", "route": "/super-home", "is_default": True},
            {"id": "dashboard", "title": "仪表盘", "route": "/"},
            {"id": "perf_ultra", "title": "性能监控", "route": "/perf-ultra"},
        ],
    },
    {
        "id": "pentest",
        "title": "渗透测试",
        "icon": "⚔️",
        "items": [
            {"id": "web_pentest", "title": "Web 渗透", "route": "/web-pentest-full"},
            {"id": "internal", "title": "内网渗透", "route": "/internal-pentest"},
            {"id": "red_team", "title": "红队行动", "route": "/red-team"},
            {"id": "bug_bounty", "title": "SRC 挖洞", "route": "/src-workbench"},
        ],
    },
    {
        "id": "scan",
        "title": "扫描检测",
        "icon": "🔍",
        "items": [
            {"id": "scanner", "title": "漏洞扫描", "route": "/scanner"},
            {"id": "nuclei", "title": "Nuclei 引擎", "route": "/nuclei-engine"},
            {"id": "distributed", "title": "分布式扫描", "route": "/distributed-scan"},
            {"id": "fuzzing", "title": "模糊测试", "route": "/fuzzing-platform"},
        ],
    },
    {
        "id": "vuln",
        "title": "漏洞管理",
        "icon": "🐛",
        "items": [
            {"id": "vuln_mgmt", "title": "漏洞生命周期", "route": "/vuln-management"},
            {"id": "vuln_db", "title": "漏洞库", "route": "/vuln-database"},
            {"id": "exploit", "title": "EXP 库", "route": "/exploit"},
        ],
    },
    {
        "id": "report",
        "title": "报告中心",
        "icon": "📑",
        "items": [
            {"id": "report_pro", "title": "专业报告", "route": "/report-pro"},
            {"id": "report_engine", "title": "报告引擎", "route": "/report-engine"},
        ],
    },
    {
        "id": "soc",
        "title": "安全运营",
        "icon": "🛡️",
        "items": [
            {"id": "soc", "title": "SOC 平台", "route": "/soc"},
            {"id": "siem", "title": "SIEM", "route": "/siem"},
            {"id": "soar", "title": "SOAR 编排", "route": "/soar-deep"},
            {"id": "threat_hunt", "title": "威胁狩猎", "route": "/threat-hunt"},
        ],
    },
    {
        "id": "asset",
        "title": "资产情报",
        "icon": "🧭",
        "items": [
            {"id": "asset", "title": "资产管理", "route": "/asset-management"},
            {"id": "osint", "title": "OSINT", "route": "/osint"},
            {"id": "darkweb", "title": "暗网监控", "route": "/darkweb-monitor"},
        ],
    },
    {
        "id": "system",
        "title": "系统",
        "icon": "⚙️",
        "items": [
            {"id": "settings", "title": "系统设置", "route": "/settings"},
            {"id": "plugins", "title": "插件市场", "route": "/plugins"},
            {"id": "docs", "title": "帮助文档", "route": "/ux-docs-deep"},
        ],
    },
]


# --------------------------------------------------------------------------- #
# 5. 响应式断点
# --------------------------------------------------------------------------- #
RESPONSIVE: Dict[str, Any] = {
    "breakpoints": {
        "desktop": ">= 1280px",
        "tablet": "768px - 1279px",
        "mobile": "< 768px",
    },
    "tablet_breakpoint": 1280,
    "mobile_breakpoint": 768,
    "grid_desktop": "4 columns",
    "grid_tablet": "2 columns",
    "grid_mobile": "1 column",
    "sidebar_collapsed_on": "mobile",
    "top_bar_search_on_mobile": True,
}


# --------------------------------------------------------------------------- #
# 配置管理器（单例）
# --------------------------------------------------------------------------- #
class HomepageConfig:
    """超级首页静态配置访问器。"""

    def __init__(self) -> None:
        self.theme = THEME
        self.feature_cards = FEATURE_CARDS
        self.quick_stats = QUICK_STATS
        self.nav_groups = NAV_GROUPS
        self.responsive = RESPONSIVE

    def all(self) -> Dict[str, Any]:
        return {
            "theme": self.theme,
            "feature_cards": self.feature_cards,
            "quick_stats": self.quick_stats,
            "nav_groups": self.nav_groups,
            "responsive": self.responsive,
        }

    def feature_card(self, card_id: str) -> Dict[str, Any] | None:
        for c in self.feature_cards:
            if c["id"] == card_id:
                return c
        return None

    def nav_item_count(self) -> int:
        return sum(len(g["items"]) for g in self.nav_groups)


_manager: HomepageConfig | None = None


def get_homepage_config() -> HomepageConfig:
    global _manager
    if _manager is None:
        _manager = HomepageConfig()
    return _manager
