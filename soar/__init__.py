# -*- coding: utf-8 -*-
"""
soar — SOAR 安全编排自动化与响应模块。

子模块：
    - playbook_engine: 剧本编排引擎（50+ 模板）
    - action_library:  响应动作库（100+ 动作）
    - alert_triage:    告警分诊与丰富
    - case_manager:    案例管理
    - execution_engine: 自动化执行引擎
    - soar_metrics:    SOAR 运营度量
    - soar_workflow:    端到端综合工作流
"""

from __future__ import annotations

from .action_library import ActionExecutor, ACTION_LIBRARY, ACTION_CATEGORIES, get_action_executor
from .playbook_engine import Playbook, PlaybookEngine, PLAYBOOK_TEMPLATES, NODE_TYPES, get_playbook_engine
from .alert_triage import AlertTriage, get_alert_triage
from .case_manager import CaseManager, get_case_manager
from .execution_engine import ExecutionEngine, get_execution_engine
from .soar_metrics import SOARMetrics, get_soar_metrics
from .soar_workflow import SOARWorkflow, get_soar_workflow, WORKFLOW_STEPS

__all__ = [
    "ActionExecutor", "ACTION_LIBRARY", "ACTION_CATEGORIES", "get_action_executor",
    "Playbook", "PlaybookEngine", "PLAYBOOK_TEMPLATES", "NODE_TYPES", "get_playbook_engine",
    "AlertTriage", "get_alert_triage",
    "CaseManager", "get_case_manager",
    "ExecutionEngine", "get_execution_engine",
    "SOARMetrics", "get_soar_metrics",
    "SOARWorkflow", "get_soar_workflow", "WORKFLOW_STEPS",
]

__version__ = "15.2.0"
