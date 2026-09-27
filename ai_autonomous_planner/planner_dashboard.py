# -*- coding: utf-8 -*-
"""
planner_dashboard.py — 规划仪表盘聚合。

把 planner_engine / thinking_visualizer / dynamic_adjuster / task_decomposer
的状态聚合成前端仪表盘一次渲染所需的快照数据。
"""

from __future__ import annotations

from typing import Any, Dict, List

from .planner_engine import engine, PIPELINE
from .thinking_visualizer import visualizer
from .dynamic_adjuster import adjuster
from .task_decomposer import decomposer
from .autonomous_agent import agent


class PlannerDashboard:
    """聚合所有模块状态为仪表盘快照。"""

    def overview(self) -> Dict[str, Any]:
        return {
            "pipeline": PIPELINE,
            "engine": {
                "sessions": len(engine.list_sessions()),
                "running": len(agent.list_running()),
            },
            "decomposer": decomposer.stats(),
            "visualizer": visualizer.stats(),
            "adjuster": adjuster.stats(),
        }

    def session_detail(self, session_id: str) -> Dict[str, Any]:
        s = engine.get(session_id)
        if s is None:
            return {}
        d = s.to_dict()
        think_sid = getattr(s, "think_session", "")
        d["think_timeline"] = visualizer.get_timeline(think_sid)
        d["latest_thought"] = visualizer.latest_thought(think_sid)
        d["adjustments"] = adjuster.get_events(think_sid)
        dg = decomposer.get_goal(s.goal_id)
        d["goal"] = dg.to_dict() if dg else None
        d["agent_events"] = agent.events(session_id, limit=100)
        return d

    def sessions_list(self) -> List[Dict[str, Any]]:
        out = []
        for s in engine.list_sessions():
            think_sid = s.get("think_session", "")
            out.append({
                "session_id": s["session_id"],
                "target": s["target"],
                "status": s["status"],
                "stage_index": s["stage_index"],
                "progress": s["progress"],
                "step_count": s["step_count"],
                "findings_count": s["findings_count"],
                "latest_thought": visualizer.latest_thought(think_sid),
            })
        return out

    def thinking_panel(self, session_id: str) -> Dict[str, Any]:
        s = engine.get(session_id)
        if s is None:
            return {"session_id": session_id, "timeline": [], "latest": None}
        think_sid = getattr(s, "think_session", "")
        return {
            "session_id": think_sid,
            "timeline": visualizer.get_timeline(think_sid),
            "latest": visualizer.latest_thought(think_sid),
        }

    def adjustments_panel(self, session_id: str) -> Dict[str, Any]:
        s = engine.get(session_id)
        think_sid = getattr(s, "think_session", "") if s else ""
        return {
            "session_id": think_sid,
            "events": adjuster.get_events(think_sid),
            "strategy_pool": adjuster.list_strategies(),
        }

    def decomposer_panel(self, goal_id: str) -> Dict[str, Any]:
        dg = decomposer.get_goal(goal_id)
        if dg is None:
            return {}
        return dg.to_dict()


dashboard = PlannerDashboard()
