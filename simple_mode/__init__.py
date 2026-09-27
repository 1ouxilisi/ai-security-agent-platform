# -*- coding: utf-8 -*-
"""
simple_mode 包 —— 极简模式 / 界面简洁

只暴露核心功能：新建任务、任务列表、实时动态、详情/报告。
参考 AegisAI 三栏布局：左任务列表 / 中实时动态 / 右详情。
全部使用内存字典模拟存储，无外部依赖。
"""

from __future__ import annotations

from .simple_layout import SimpleLayout, get_layout
from .task_manager_simple import SimpleTaskManager, get_task_manager
from .onboarding_guide import OnboardingGuide, get_onboarding_guide
from .simple_dashboard import SimpleDashboard, get_dashboard

__all__ = [
    "SimpleLayout",
    "get_layout",
    "SimpleTaskManager",
    "get_task_manager",
    "OnboardingGuide",
    "get_onboarding_guide",
    "SimpleDashboard",
    "get_dashboard",
]
