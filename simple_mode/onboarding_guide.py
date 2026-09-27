# -*- coding: utf-8 -*-
"""
onboarding_guide.py —— 新手引导

三步引导：新建任务 -> 查看进度 -> 下载报告。
按用户（简单用 device/session id 模拟）记录引导进度，可重置。
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional


STEPS: List[Dict[str, Any]] = [
    {
        "id": "step_new_task",
        "order": 1,
        "title": "第一步：新建任务",
        "body": "在左上角输入目标地址，点击「新建任务」按钮开始。",
        "anchor": "#btn-new-task",
        "action_hint": "点这里 ➕",
    },
    {
        "id": "step_watch_progress",
        "order": 2,
        "title": "第二步：查看实时进度",
        "body": "中间区域会实时显示任务进度条与日志流，耐心等待。",
        "anchor": "#feed-panel",
        "action_hint": "看中间 📡",
    },
    {
        "id": "step_download_report",
        "order": 3,
        "title": "第三步：下载报告",
        "body": "任务完成后，在右侧点击「下载报告」即可导出结果。",
        "anchor": "#report-panel",
        "action_hint": "点这里 📄",
    },
]


class OnboardingGuide:
    """新手引导状态机（内存模拟，按 session_id 隔离）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # session_id -> {"finished": bool, "current_step": int, "dismissed_at": str|None}
        self._state: Dict[str, Dict[str, Any]] = {}

    def get_state(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            st = self._state.get(session_id)
            if st is None:
                st = {"finished": False, "current_step": 1,
                      "dismissed_at": None}
                self._state[session_id] = st
            return dict(st)

    def should_start(self, session_id: str) -> bool:
        """是否需要自动弹出引导（首次进入且未完成）。"""
        st = self.get_state(session_id)
        return not st["finished"]

    def get_steps(self) -> Dict[str, Any]:
        return {"success": True, "data": {"steps": STEPS,
                                          "total": len(STEPS)}}

    def advance(self, session_id: str) -> Dict[str, Any]:
        """推进到下一步；已到末尾则标记完成。"""
        with self._lock:
            st = self._state.setdefault(
                session_id,
                {"finished": False, "current_step": 1, "dismissed_at": None},
            )
            if st["current_step"] >= len(STEPS):
                st["finished"] = True
            else:
                st["current_step"] += 1
            return {"success": True,
                    "data": {"state": dict(st),
                             "total": len(STEPS)}}

    def reset(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            self._state[session_id] = {
                "finished": False, "current_step": 1, "dismissed_at": None,
            }
        return {"success": True, "data": {"state": self.get_state(session_id)}}

    def finish(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            st = self._state.setdefault(
                session_id,
                {"finished": False, "current_step": 1, "dismissed_at": None},
            )
            st["finished"] = True
        return {"success": True, "data": {"state": dict(st)}}


_singleton: OnboardingGuide | None = None


def get_onboarding_guide() -> OnboardingGuide:
    global _singleton
    if _singleton is None:
        _singleton = OnboardingGuide()
    return _singleton
