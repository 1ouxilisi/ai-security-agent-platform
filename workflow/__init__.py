#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
__init__工作流引擎模块，提供相关安全测试工作流的定义和执行。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

"""渗透测试工作流模块"""
from workflow.engine import (
    WorkflowEngine,
    WorkflowInstance,
    WorkflowPhase,
    WorkflowStatus,
    PhaseStatus,
    workflow_engine
)
from workflow.definitions import (
    create_standard_pentest_workflow,
    create_quick_scan_workflow,
    WORKFLOW_TEMPLATES
)

__all__ = [
    'WorkflowEngine',
    'WorkflowInstance',
    'WorkflowPhase',
    'WorkflowStatus',
    'PhaseStatus',
    'workflow_engine',
    'create_standard_pentest_workflow',
    'create_quick_scan_workflow',
    'WORKFLOW_TEMPLATES'
]
