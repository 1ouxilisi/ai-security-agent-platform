# -*- coding: utf-8 -*-
"""
security_llm — 安全大模型与 AI Agent 深度平台（第26轮升级方向1）。

模块组成：
    - llm_manager      安全领域大模型管理（模型/RAG/提示词/微调/推理/评测）
    - agent_engine     安全 Agent 自主决策（管理/规划/执行/反思/记忆/协作）
    - code_generator   安全代码生成（生成/审查/解释/转换/测试/知识库）
    - qa_system        安全问答系统（管理/检索/生成/审核/统计/知识库）
    - smart_report     安全报告智能生成（规划/生成/优化/审核/版本/模板）
    - llm_dashboard     安全大模型控制台数据聚合层

仅用于授权的安全评估与运营场景。
"""
from __future__ import annotations

__version__ = "26.1.0"
__module_name__ = "security_llm"

from .llm_manager import llm_manager
from .agent_engine import agent_engine
from .code_generator import code_generator
from .qa_system import qa_system
from .smart_report import smart_report
from .llm_dashboard import llm_dashboard

__all__ = [
    "llm_manager",
    "agent_engine",
    "code_generator",
    "qa_system",
    "smart_report",
    "llm_dashboard",
]
