# -*- coding: utf-8 -*-
"""
ux_upgrade/super_homepage_v2.py — 超级首页 V2（增强版）

大字体大按钮、核心功能一目了然、一键操作、实时数据可视化、最近操作记录。
全部内存字典模拟。
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List

# 最近操作记录
ACTIVITY: List[Dict[str, Any]] = []

QUICK_ACTIONS = [
    {"id": "quick_scan", "icon": "🚀", "title": "一键扫描",
     "desc": "对目标发起全量智能扫描", "endpoint": "/api/v1/scan/run",
     "big": True},
    {"id": "quick_report", "icon": "📄", "title": "一键报告",
     "desc": "AI 自动生成渗透报告", "endpoint": "/api/v1/ai-upgrade/report/generate",
     "big": True},
    {"id": "quick_dashboard", "icon": "📊", "title": "一键仪表盘",
     "desc": "查看安全态势总览", "endpoint": "/api/v1/ai-upgrade/overview",
     "big": True},
    {"id": "quick_src", "icon": "🎯", "title": "挖 SRC",
     "desc": "AI 辅助找攻击面", "endpoint": "/api/v1/ux-upgrade/src", "big": False},
    {"id": "quick_qa", "icon": "💬", "title": "智能问答",
     "desc": "问 AI 任何安全问题", "endpoint": "/api/v1/ai-upgrade/qa/ask",
     "big": False},
]

FEATURE_CARDS = [
    {"id": "web", "title": "Web 渗透", "badge": "128 工具", "color": "#58a6ff"},
    {"id": "vuln", "title": "漏洞管理", "badge": "3 高危", "color": "#f85149"},
    {"id": "report", "title": "报告中心", "badge": "12 报告", "color": "#3fb950"},
    {"id": "src", "title": "SRC 众测", "badge": "4 进行中", "color": "#ff9800"},
]


def log_activity(action: str, detail: str, user_id: str = "default") -> Dict[str, Any]:
    entry = {
        "id": uuid.uuid4().hex[:8],
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user_id, "action": action, "detail": detail,
    }
    ACTIVITY.append(entry)
    if len(ACTIVITY) > 100:
        del ACTIVITY[: len(ACTIVITY) - 100]
    return entry


class SuperHomepageV2:
    """超级首页聚合数据。"""

    def get(self, user_id: str = "default") -> Dict[str, Any]:
        return {
            "title": "AI Hacking Agent",
            "greeting": self._greeting(),
            "quick_actions": QUICK_ACTIONS,
            "feature_cards": FEATURE_CARDS,
            "stats": self._live_stats(),
            "large_typography": True,
            "layout": "big-grid",
        }

    def _greeting(self) -> str:
        h = time.localtime().tm_hour
        if h < 6:
            return "夜深了，注意休息"
        if h < 12:
            return "早上好，开始今日渗透"
        if h < 18:
            return "下午好，保持专注"
        return "晚上好，收网时刻"

    def _live_stats(self) -> Dict[str, Any]:
        return {
            "scans_today": 17,
            "vulns_found": 23,
            "critical": 3,
            "reports": 12,
            "scan_progress": 68,
            "trend": [12, 18, 9, 23, 15, 23, 17],
        }

    def quick_action(self, action_id: str,
                     context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        target = next((a for a in QUICK_ACTIONS if a["id"] == action_id), None)
        log_activity(action_id,
                     f"触发快捷操作：{target['title'] if target else action_id}",
                     (context or {}).get("user_id", "default"))
        return {
            "action_id": action_id,
            "launched": True,
            "redirect": target["endpoint"] if target else None,
            "message": f"已启动「{target['title'] if target else action_id}」",
        }

    def recent_activity(self, limit: int = 10) -> List[Dict[str, Any]]:
        if not ACTIVITY:
            log_activity("login", "首次进入超级首页")
        return list(reversed(ACTIVITY[-limit:]))


_singleton: SuperHomepageV2 | None = None


def get_homepage_v2() -> SuperHomepageV2:
    global _singleton
    if _singleton is None:
        _singleton = SuperHomepageV2()
    return _singleton
