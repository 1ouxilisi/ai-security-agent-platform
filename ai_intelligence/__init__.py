#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 大模型智能决策引擎（ai_intelligence）
==========================================

第 23 轮升级方向 1。本包为 AI Hacking Agent 平台提供"大模型决策中枢"能力，
全部能力均为防御 / 授权评估视角，仅用于授权的安全测试与运营场景。

核心组件：
    - NLAssistant         自然语言安全助手（意图识别 / 参数提取 / 多轮对话 / 会话历史）
    - ScanDecisionEngine 智能扫描决策（策略生成 / 路径规划 / 深度自适应 / 结果分析 / 调度）
    - POCGenerator        自动 POC/EXP 生成（漏洞解析 / 代码生成 / 沙箱验证 / 利用链构建）
    - SmartReport         智能报告生成（结构规划 / 风险翻译 / 修复建议 / 质量评分 / 多格式）
    - AIKnowledgeBase     AI 安全知识库（漏洞 / 攻击 / 防御 / 工具 / 案例 / 检索推理）
    - AIDashboard          AI 管理控制台数据（总览 / 模型 / 提示词 / 对话 / 任务 / 设置）

设计约束：
    - ``from __future__ import annotations`` 全量使用
    - openai / requests 等第三方库 try-import，缺失时自动回退为本地模拟推理
    - 全部使用内存字典模拟，不落数据库表
    - 每个核心类均为单例，模块级导出实例供路由层直接调用
"""

from .nl_assistant import NLAssistant, nl_assistant
from .scan_decision import ScanDecisionEngine, scan_decision_engine
from .poc_generator import POCGenerator, poc_generator
from .smart_report import SmartReport, smart_report
from .ai_knowledge_base import AIKnowledgeBase, ai_knowledge_base
from .ai_dashboard import AIDashboard, ai_dashboard

__all__ = [
    "NLAssistant",
    "nl_assistant",
    "ScanDecisionEngine",
    "scan_decision_engine",
    "POCGenerator",
    "poc_generator",
    "SmartReport",
    "smart_report",
    "AIKnowledgeBase",
    "ai_knowledge_base",
    "AIDashboard",
    "ai_dashboard",
]

__version__ = "23.1.0"
