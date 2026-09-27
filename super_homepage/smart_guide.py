#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
super_homepage/smart_guide.py — 智能引导逻辑。

第一次进入超级首页自动弹出三步引导：
    1. 扫描目标
    2. 查看结果
    3. 生成报告

支持跳过；引导状态按用户（内存字典模拟，前端用 localStorage 持久化 key）。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 引导流程定义
# --------------------------------------------------------------------------- #
GUIDE_FLOW: Dict[str, Any] = {
    "id": "first_launch_wizard",
    "title": "三步上手超级首页",
    "version": "3.0",
    "storage_key": "shp_guide_completed_v3",   # 前端 localStorage key
    "steps": [
        {
            "step": 1,
            "id": "step_scan",
            "title": "第一步：扫描目标",
            "anchor": '[data-guide="feature-web_pentest"]',
            "badge": "1",
            "content": "点击「Web 渗透」大卡片，输入目标地址，一键发起扫描。",
            "tip": "建议先用 example.com 这类测试靶场练手。",
            "action": {"label": "开始扫描", "route": "/web-pentest-full"},
            "placement": "bottom",
        },
        {
            "step": 2,
            "id": "step_result",
            "title": "第二步：查看结果",
            "anchor": '[data-guide="stats-vulns_discovered"]',
            "badge": "2",
            "content": "扫描完成后，回到首页即可看到「已发现漏洞」实时统计。",
            "tip": "点击任意统计卡片可下钻到漏洞列表。",
            "action": {"label": "查看漏洞", "route": "/vuln-management"},
            "placement": "bottom",
        },
        {
            "step": 3,
            "id": "step_report",
            "title": "第三步：生成报告",
            "anchor": '[data-guide="feature-report_center"]',
            "badge": "3",
            "content": "确认漏洞后，点「报告中心」一键生成专业安全报告。",
            "tip": "支持 PDF / HTML / Markdown 三种导出。",
            "action": {"label": "生成报告", "route": "/report-pro"},
            "placement": "bottom",
        },
    ],
}


# --------------------------------------------------------------------------- #
# 引导管理器（内存字典模拟按用户状态）
# --------------------------------------------------------------------------- #
class SmartGuideManager:
    """智能引导状态管理器。"""

    def __init__(self) -> None:
        self.flow = GUIDE_FLOW
        # user_id -> state
        self._states: Dict[str, Dict[str, Any]] = {}
        # 引导事件日志
        self._events: List[Dict[str, Any]] = []

    # ---- 状态 ----
    def _ensure(self, user_id: str) -> Dict[str, Any]:
        if user_id not in self._states:
            self._states[user_id] = {
                "user_id": user_id,
                "completed": False,
                "skipped": False,
                "current_step": 0,
                "total_steps": len(GUIDE_FLOW["steps"]),
                "started_at": None,
                "finished_at": None,
                "last_action": None,
            }
        return self._states[user_id]

    def should_start(self, user_id: str) -> bool:
        """是否需要自动弹出引导（首次进入且未完成/未跳过）。"""
        st = self._states.get(user_id)
        if st is None:
            return True
        return not st["completed"] and not st["skipped"]

    def start(self, user_id: str) -> Dict[str, Any]:
        st = self._ensure(user_id)
        st["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        st["current_step"] = 1
        st["last_action"] = "start"
        self._log(user_id, "start")
        return st

    def next_step(self, user_id: str) -> Dict[str, Any]:
        st = self._ensure(user_id)
        if st["current_step"] < st["total_steps"]:
            st["current_step"] += 1
        st["last_action"] = "next"
        self._log(user_id, "next_step")
        return st

    def complete(self, user_id: str) -> Dict[str, Any]:
        st = self._ensure(user_id)
        st["completed"] = True
        st["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        st["current_step"] = st["total_steps"]
        st["last_action"] = "complete"
        self._log(user_id, "complete")
        return st

    def skip(self, user_id: str) -> Dict[str, Any]:
        st = self._ensure(user_id)
        st["skipped"] = True
        st["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        st["last_action"] = "skip"
        self._log(user_id, "skip")
        return st

    def reset(self, user_id: str) -> Dict[str, Any]:
        """重新播放引导。"""
        st = self._ensure(user_id)
        st["completed"] = False
        st["skipped"] = False
        st["current_step"] = 0
        st["started_at"] = None
        st["finished_at"] = None
        st["last_action"] = "reset"
        self._log(user_id, "reset")
        return st

    def get_state(self, user_id: str) -> Dict[str, Any]:
        st = self._ensure(user_id)
        st["should_autostart"] = self.should_start(user_id)
        return st

    # ---- 事件日志 ----
    def _log(self, user_id: str, action: str) -> None:
        self._events.append({
            "id": uuid.uuid4().hex[:8],
            "user_id": user_id,
            "action": action,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        if len(self._events) > 500:
            self._events = self._events[-500:]

    def events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self._events))[:limit]

    def stats(self) -> Dict[str, Any]:
        total_users = len(self._states)
        completed = sum(1 for s in self._states.values() if s["completed"])
        skipped = sum(1 for s in self._states.values() if s["skipped"])
        return {
            "tracked_users": total_users,
            "completed": completed,
            "skipped": skipped,
            "completion_rate": round(completed / total_users * 100, 1) if total_users else 0.0,
            "steps_total": len(GUIDE_FLOW["steps"]),
            "events_total": len(self._events),
        }


_manager: SmartGuideManager | None = None


def get_smart_guide_manager() -> SmartGuideManager:
    global _manager
    if _manager is None:
        _manager = SmartGuideManager()
    return _manager
