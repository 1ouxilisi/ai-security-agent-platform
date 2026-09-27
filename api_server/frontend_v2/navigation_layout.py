# -*- coding: utf-8 -*-
"""
navigation_layout.py — 统一导航与布局后端。

导航菜单 / 面包屑 / 全局搜索 / 主题配置 / 用户菜单 / 快捷操作。
"""
from __future__ import annotations

from typing import Any, Dict, List

from .common import now_str


MENU: List[Dict[str, Any]] = [
    {
        "group": "任务与报告",
        "icon": "🎯",
        "items": [
            {"key": "tasks", "label": "任务执行面板", "route": "/console#/tasks",
             "icon": "▶️", "perm": "operator"},
            {"key": "reports", "label": "交互式报告", "route": "/console#/reports",
             "icon": "📄", "perm": "analyst"},
            {"key": "data", "label": "数据管理", "route": "/console#/data",
             "icon": "🗃️", "perm": "analyst"},
        ],
    },
    {
        "group": "协同与感知",
        "icon": "🔔",
        "items": [
            {"key": "notifications", "label": "通知与活动流",
             "route": "/console#/notifications", "icon": "🔔", "perm": "operator"},
            {"key": "perf", "label": "性能与体验", "route": "/console#/perf",
             "icon": "⚡", "perm": "admin"},
        ],
    },
    {
        "group": "布局与演示",
        "icon": "🧭",
        "items": [
            {"key": "nav", "label": "导航与布局", "route": "/console#/nav",
             "icon": "🧭", "perm": "operator"},
        ],
    },
]

QUICK_ACTIONS: List[Dict[str, Any]] = [
    {"key": "new_task", "label": "新建扫描任务", "icon": "▶️",
     "route": "/console#/tasks", "hotkey": "Ctrl+N"},
    {"key": "view_report", "label": "查看最新报告", "icon": "📄",
     "route": "/console#/reports"},
    {"key": "import_asset", "label": "批量导入资产", "icon": "📥",
     "route": "/console#/data?tab=assets"},
    {"key": "mark_read", "label": "全部已读", "icon": "✅",
     "route": "/console#/notifications"},
    {"key": "cache_warm", "label": "缓存预热", "icon": "🔥",
     "route": "/console#/perf"},
]

THEME: Dict[str, Any] = {
    "mode": "dark",
    "primary_color": "#3ddc84",
    "font_size": "medium",
    "sidebar_collapsed": False,
}

USER_MENU: Dict[str, Any] = {
    "name": "sec-analyst",
    "role": "高级分析师",
    "avatar_color": "#3ddc84",
    "preferences": {"language": "zh-CN", "timezone": "Asia/Shanghai"},
}


def get_menu() -> List[Dict[str, Any]]:
    return MENU


def breadcrumbs(path: str = "") -> List[Dict[str, str]]:
    crumbs = [{"label": "首页", "route": "/console"}]
    mapping = {
        "tasks": "任务执行面板", "reports": "交互式报告",
        "data": "数据管理", "notifications": "通知与活动流",
        "perf": "性能与体验", "nav": "导航与布局",
    }
    segs = [s for s in path.strip("/#").split("/") if s]
    for seg in segs:
        crumbs.append({"label": mapping.get(seg, seg), "route": f"/console#/{seg}"})
    return crumbs


GLOBAL_INDEX: List[Dict[str, str]] = [
    {"type": "page", "title": "任务执行面板", "route": "/console#/tasks"},
    {"type": "page", "title": "交互式报告", "route": "/console#/reports"},
    {"type": "page", "title": "数据管理", "route": "/console#/data"},
    {"type": "vuln", "title": "SQL 注入(登录接口)", "route": "/console#/reports"},
    {"type": "vuln", "title": "反射型 XSS", "route": "/console#/reports"},
    {"type": "vuln", "title": "未授权访问(Redis)", "route": "/console#/reports"},
    {"type": "asset", "title": "api.example.com", "route": "/console#/data"},
    {"type": "asset", "title": "db-master-01", "route": "/console#/data"},
    {"type": "report", "title": "2026-Q3 Web 安全报告", "route": "/console#/reports"},
    {"type": "kb", "title": "如何修复 SQL 注入", "route": "/console#/data"},
    {"type": "kb", "title": "应急响应 SOP", "route": "/console#/data"},
]


def global_search(q: str, limit: int = 10) -> Dict[str, List[Dict[str, str]]]:
    if not q:
        return {"pages": [], "vulns": [], "assets": [], "reports": [], "kb": []}
    ql = q.lower()
    out: Dict[str, List[Dict[str, str]]] = {
        "pages": [], "vulns": [], "assets": [], "reports": [], "kb": []}
    bucket = {"page": "pages", "vuln": "vulns", "asset": "assets",
              "report": "reports", "kb": "kb"}
    for item in GLOBAL_INDEX:
        if ql in item["title"].lower():
            out[bucket.get(item["type"], "pages")].append(item)
    for k in out:
        out[k] = out[k][:limit]
    return out


def get_theme() -> Dict[str, Any]:
    return dict(THEME)


def update_theme(patch: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in patch.items():
        if k in THEME:
            THEME[k] = v
    return get_theme()


def get_user_menu() -> Dict[str, Any]:
    return USER_MENU


def recent_visited() -> List[Dict[str, str]]:
    return [
        {"route": "/console#/reports", "title": "交互式报告", "time": now_str()},
        {"route": "/console#/tasks", "title": "任务执行面板", "time": now_str()},
        {"route": "/console#/data?tab=assets", "title": "资产列表", "time": now_str()},
    ]


def favorites() -> List[Dict[str, str]]:
    return [
        {"route": "/console#/reports", "title": "Q3 Web 报告"},
        {"route": "/console#/notifications", "title": "告警中心"},
    ]


def quick_actions() -> Dict[str, Any]:
    return {"actions": QUICK_ACTIONS, "recent": recent_visited(),
            "favorites": favorites()}
