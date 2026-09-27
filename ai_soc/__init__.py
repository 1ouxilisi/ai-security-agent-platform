#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 安全运营（AI SOC）模块
===================================

本模块提供 AI 驱动的安全运营中心（Security Operations Center）能力，
全部为防御 / 评估 / 检测视角，仅用于授权的安全运营与监控场景。

核心组件：
    - AnomalyDetector      AI 异常检测器（流量/行为/性能/日志异常，纯 Python 统计 + 孤立森林）
    - AlertCorrelator      AI 告警关联分析器（攻击链识别 / MITRE ATT&CK 映射）
    - EventClassifier      AI 事件自动分类器（8 类事件，朴素贝叶斯文本分类）
    - RootCauseAnalyzer    AI 根因分析器（日志/拓扑/时间线分析）
    - ResponseAdvisor      AI 自动响应建议器（遏制/根除/恢复/监控）
    - SOCAssistant         安全运营 AI 助手（自然语言交互 / 知识检索）

设计约束：
    - 不依赖外部第三方机器学习库（scikit-learn 等），算法均为纯 Python 实现
    - 数据存储使用内存字典 + JSON 文件持久化（data/ai_soc/ 目录）
    - 每个核心类均为单例，模块级导出实例
"""

from .anomaly_detector import AnomalyDetector, anomaly_detector
from .alert_correlator import AlertCorrelator, alert_correlator
from .event_classifier import EventClassifier, event_classifier
from .root_cause_analyzer import RootCauseAnalyzer, root_cause_analyzer
from .response_advisor import ResponseAdvisor, response_advisor
from .soc_assistant import SOCAssistant, soc_assistant

__all__ = [
    "AnomalyDetector",
    "anomaly_detector",
    "AlertCorrelator",
    "alert_correlator",
    "EventClassifier",
    "event_classifier",
    "RootCauseAnalyzer",
    "root_cause_analyzer",
    "ResponseAdvisor",
    "response_advisor",
    "SOCAssistant",
    "soc_assistant",
]

__version__ = "1.0.0"
