# -*- coding: utf-8 -*-
"""
ai_autonomous_planner — AI 自主规划能力大升级。

模块组成：
    - task_decomposer    : 把自然语言目标拆解为带依赖的子任务 DAG
    - planner_engine     : 规划引擎（探测→枚举→漏洞→分析→报告 状态机）
    - thinking_visualizer: AI 思考过程可视化（观察/推理/决策/依据）
    - dynamic_adjuster   : 失败自动换策略（SQLi→XSS→目录遍历…）
    - autonomous_agent   : 自主智能体编排器（后台线程全自动闭环）
    - planner_dashboard  : 仪表盘聚合

对外单例：
    decomposer / engine / visualizer / adjuster / agent / dashboard
"""

from __future__ import annotations

from .task_decomposer import decomposer, TaskDecomposer, SubTask, DecomposedGoal
from .planner_engine import engine, PlannerEngine, PlanSession, PIPELINE
from .thinking_visualizer import visualizer, ThinkingVisualizer, ThoughtStep
from .dynamic_adjuster import adjuster, DynamicAdjuster, AdjustmentEvent
from .autonomous_agent import agent, AutonomousAgent, AgentEvent
from .planner_dashboard import dashboard, PlannerDashboard

__all__ = [
    "decomposer", "TaskDecomposer", "SubTask", "DecomposedGoal",
    "engine", "PlannerEngine", "PlanSession", "PIPELINE",
    "visualizer", "ThinkingVisualizer", "ThoughtStep",
    "adjuster", "DynamicAdjuster", "AdjustmentEvent",
    "agent", "AutonomousAgent", "AgentEvent",
    "dashboard", "PlannerDashboard",
]

__version__ = "1.0.0"
