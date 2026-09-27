# -*- coding: utf-8 -*-
"""
simple_layout.py —— 极简布局配置

定义三栏布局结构、可见功能白名单、字体/按钮尺寸等 UI 常量。
参考 AegisAI：左侧任务列表，中间实时动态，右侧详情。
"""

from __future__ import annotations

from typing import Any, Dict, List


class SimpleLayout:
    """极简模式布局配置。"""

    # 只保留核心功能（白名单），其余 160+ 页面在极简模式下全部隐藏。
    CORE_FEATURES: List[Dict[str, Any]] = [
        {
            "id": "new_task",
            "name": "新建任务",
            "icon": "➕",
            "route": "/simple-console",
            "desc": "输入目标，一键开始安全测试",
            "priority": 1,
        },
        {
            "id": "task_list",
            "name": "任务列表",
            "icon": "📋",
            "route": "/simple-console",
            "desc": "查看所有任务状态与进度",
            "priority": 2,
        },
        {
            "id": "live_feed",
            "name": "实时动态",
            "icon": "📡",
            "route": "/simple-console",
            "desc": "当前任务的实时日志流",
            "priority": 3,
        },
        {
            "id": "detail",
            "name": "任务详情",
            "icon": "🔍",
            "route": "/simple-console",
            "desc": "选中任务的详细信息",
            "priority": 4,
        },
        {
            "id": "report",
            "name": "下载报告",
            "icon": "📄",
            "route": "/simple-console",
            "desc": "生成并下载任务报告",
            "priority": 5,
        },
        {
            "id": "target_lab",
            "name": "本地靶场",
            "icon": "🎯",
            "route": "/target-lab",
            "desc": "一键启动 DVWA / Juice Shop / WebGoat",
            "priority": 6,
        },
    ]

    # 三栏布局定义
    COLUMNS: Dict[str, Any] = {
        "left": {
            "title": "任务列表",
            "width_pct": 26,
            "blocks": ["new_task_button", "task_list", "filter_tabs"],
        },
        "middle": {
            "title": "实时动态",
            "width_pct": 42,
            "blocks": ["current_progress", "log_stream", "stage_bar"],
        },
        "right": {
            "title": "详情",
            "width_pct": 32,
            "blocks": ["task_meta", "vuln_summary", "report_download"],
        },
    }

    # 顶部极简导航
    TOP_NAV: List[Dict[str, Any]] = [
        {"id": "logo", "label": "AI 极简控制台", "type": "logo"},
        {"id": "current_task", "label": "当前任务", "type": "current_task"},
        {"id": "back_full", "label": "返回完整版", "type": "link", "route": "/"},
        {"id": "settings", "label": "设置", "type": "settings"},
    ]

    # 大字体 / 大按钮
    UI_CONSTANTS: Dict[str, Any] = {
        "font_size_base": 18,        # 基础字号（px）
        "font_size_heading": 26,     # 标题字号
        "button_height": 52,         # 大按钮高度
        "button_radius": 12,         # 按钮圆角
        "card_padding": 20,          # 卡片内边距
        "theme": "dark",             # 深色主题
        "accent": "#2ea043",         # 主色（绿）
    }

    def get_layout(self) -> Dict[str, Any]:
        """返回完整布局配置。"""
        return {
            "mode": "simple",
            "columns": self.COLUMNS,
            "top_nav": self.TOP_NAV,
            "ui": self.UI_CONSTANTS,
            "feature_count": len(self.CORE_FEATURES),
        }

    def get_core_features(self) -> List[Dict[str, Any]]:
        """返回核心功能白名单（已按优先级排序）。"""
        return sorted(self.CORE_FEATURES, key=lambda f: f["priority"])

    def is_feature_visible(self, feature_id: str) -> bool:
        """判断某功能在极简模式下是否可见。"""
        return any(f["id"] == feature_id for f in self.CORE_FEATURES)

    def get_hidden_count(self) -> Dict[str, int]:
        """返回被极简模式隐藏的功能数量（用于说明）。"""
        return {
            "hidden_modules": 156,   # 约 162 个页面减去 6 个核心
            "visible_modules": len(self.CORE_FEATURES),
            "total_before": 162,
        }


_singleton: SimpleLayout | None = None


def get_layout() -> SimpleLayout:
    """获取全局唯一布局配置实例。"""
    global _singleton
    if _singleton is None:
        _singleton = SimpleLayout()
    return _singleton
