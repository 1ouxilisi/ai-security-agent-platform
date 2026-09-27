# -*- coding: utf-8 -*-
"""
llm_optimization 包 — LLM 接入优化（方向5）

在已有 llm_integration 之上，确保「配了 Key 后所有 AI 功能真能用」：
    - prompt_optimizer : 专业级 Prompt 模板（漏洞分析/报告生成/智能问答）
    - ai_function_tester: 三大 AI 功能验证器（无 Key 时规则引擎降级）
    - llm_e2e_test     : 端到端测试运行器（3 个标准用例 + 结果落盘）
    - llm_dashboard    : LLM 状态仪表盘数据聚合

设计原则：
    1. 全部复用 llm_integration.get_llm_client()，不重复造客户端；
    2. 无 Key / LLM 调用失败时优雅降级到规则引擎，结果统一标注
       「规则模式（未配置LLM）」，绝不抛异常、绝不 500；
    3. 所有运行态数据放内存字典，不落盘数据库；
    4. 统一响应 {success, data, error}。
"""
from __future__ import annotations

from .prompt_optimizer import (
    PromptOptimizer,
    get_prompt_optimizer,
    PROMPT_REGISTRY,
)
from .ai_function_tester import (
    AIFunctionTester,
    get_ai_tester,
)
from .llm_e2e_test import (
    LLME2ETestRunner,
    get_e2e_runner,
)
from .llm_dashboard import (
    LLMDashboard,
    get_dashboard,
)

__all__ = [
    "PromptOptimizer", "get_prompt_optimizer", "PROMPT_REGISTRY",
    "AIFunctionTester", "get_ai_tester",
    "LLME2ETestRunner", "get_e2e_runner",
    "LLMDashboard", "get_dashboard",
]
