#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
super_homepage/quick_actions.py — 快速操作栏。

固定在侧边栏的常用一键操作：快速扫描 / 快速查报告 / 快速看仪表盘等。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List


# --------------------------------------------------------------------------- #
# 快速操作注册表
# --------------------------------------------------------------------------- #
QUICK_ACTIONS: List[Dict[str, Any]] = [
    {
        "id": "quick_scan",
        "label": "快速扫描",
        "icon": "⚡",
        "shortcut": "Ctrl+K S",
        "route": "/web-pentest-full",
        "desc": "输入目标立即发起 Web 漏洞扫描",
        "color": "#58a6ff",
    },
    {
        "id": "quick_report",
        "label": "快速查报告",
        "icon": "📑",
        "shortcut": "Ctrl+K R",
        "route": "/report-pro",
        "desc": "打开最近的渗透报告并导出",
        "color": "#f85149",
    },
    {
        "id": "quick_dashboard",
        "label": "快速看仪表盘",
        "icon": "📊",
        "shortcut": "Ctrl+K D",
        "route": "/",
        "desc": "回到全局安全态势仪表盘",
        "color": "#39d2c0",
    },
    {
        "id": "quick_vuln",
        "label": "待处理漏洞",
        "icon": "🐛",
        "shortcut": "Ctrl+K V",
        "route": "/vuln-management",
        "desc": "一键进入待处置漏洞队列",
        "color": "#d29922",
    },
    {
        "id": "quick_search",
        "label": "全局搜索",
        "icon": "🔎",
        "shortcut": "Ctrl+K",
        "route": "/super-home",
        "desc": "搜索任何功能 / 漏洞 / 报告 / 目标",
        "color": "#79b8ff",
    },
    {
        "id": "quick_perf",
        "label": "性能监控",
        "icon": "🚀",
        "shortcut": "Ctrl+K P",
        "route": "/perf-ultra",
        "desc": "查看启动/响应/缓存性能指标",
        "color": "#3fb950",
    },
]


class QuickActionsManager:
    """快速操作执行器（内存记录执行历史）。"""

    def __init__(self) -> None:
        self.actions = QUICK_ACTIONS
        self._exec_log: List[Dict[str, Any]] = []

    def list(self) -> List[Dict[str, Any]]:
        return self.actions

    def get(self, action_id: str) -> Dict[str, Any] | None:
        for a in self.actions:
            if a["id"] == action_id:
                return a
        return None

    def run(self, action_id: str, context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        action = self.get(action_id)
        if action is None:
            return {"success": False, "error": f"未知操作: {action_id}"}
        record = {
            "log_id": uuid.uuid4().hex[:10],
            "action_id": action_id,
            "label": action["label"],
            "route": action["route"],
            "context": context or {},
            "executed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._exec_log.append(record)
        if len(self._exec_log) > 200:
            self._exec_log = self._exec_log[-200:]
        return {"success": True, "action": action, "record": record}

    def history(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self._exec_log))[:limit]

    def stats(self) -> Dict[str, Any]:
        counter: Dict[str, int] = {}
        for r in self._exec_log:
            counter[r["action_id"]] = counter.get(r["action_id"], 0) + 1
        return {
            "total_actions": len(self.actions),
            "executions": len(self._exec_log),
            "by_action": counter,
        }


_manager: QuickActionsManager | None = None


def get_quick_actions_manager() -> QuickActionsManager:
    global _manager
    if _manager is None:
        _manager = QuickActionsManager()
    return _manager
