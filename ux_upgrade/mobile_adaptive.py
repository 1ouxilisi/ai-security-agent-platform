# -*- coding: utf-8 -*-
"""
ux_upgrade/mobile_adaptive.py — 移动端适配

提供响应式配置（768px 断点）、移动端布局建议、仪表盘/报告在手机上的精简数据。
"""
from __future__ import annotations

from typing import Any, Dict, List

BREAKPOINT = 768

RESPONSIVE_CONFIG = {
    "breakpoint_px": BREAKPOINT,
    "rules": [
        {"name": "grid-collapse", "desc": "宽屏多列 -> 手机单列堆叠"},
        {"name": "font-scale", "desc": "手机放大核心数字，保证可读"},
        {"name": "touch-target", "desc": "按钮最小 48x48px，适合手指点按"},
        {"name": "table-scroll", "desc": "报告表格横向滚动，不挤压"},
        {"name": "nav-drawer", "desc": "顶栏收起为汉堡菜单"},
    ],
}

# 手机精简版仪表盘（隐藏次要图表，突出关键数字）
MOBILE_DASHBOARD = {
    "mode": "compact",
    "cards": [
        {"label": "今日扫描", "value": 17, "big": True},
        {"label": "严重漏洞", "value": 3, "color": "#f85149"},
        {"label": "进行中任务", "value": 5},
    ],
    "recent": ["SQL注入分析完成", "报告已生成", "SRC 攻击面已更新"],
}


class MobileAdaptive:
    def config(self) -> Dict[str, Any]:
        return RESPONSIVE_CONFIG

    def detect(self, viewport_width: int) -> Dict[str, Any]:
        is_mobile = viewport_width < BREAKPOINT
        return {
            "viewport_width": viewport_width,
            "is_mobile": is_mobile,
            "layout": "mobile" if is_mobile else "desktop",
            "use_compact_dashboard": is_mobile,
            "breakpoint": BREAKPOINT,
        }

    def mobile_dashboard(self) -> Dict[str, Any]:
        return MOBILE_DASHBOARD

    def mobile_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """手机端报告视图：只保留关键信息。"""
        return {
            "mode": "mobile-report",
            "title": report.get("target"),
            "summary": report.get("executive_summary", "")[:200],
            "top_3_findings": (report.get("findings") or [])[:3],
            "note": "横滑查看完整表格",
        }


_mobile_singleton: MobileAdaptive | None = None


def get_mobile_adaptive() -> MobileAdaptive:
    global _mobile_singleton
    if _mobile_singleton is None:
        _mobile_singleton = MobileAdaptive()
    return _mobile_singleton
