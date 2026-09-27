#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_training — 安全培训与意识平台（第 14 轮升级 · 方向 2）。

作为可独立商业化的产品线（企业内训 / 认证 / 钓鱼演练服务），提供：
    - course_manager          课程管理（课程库/分类/章节/测验/学习路径/推荐/进度）
    - lab_environment         在线实验与靶场集成（DVWA/Juice Shop/WebGoat 等）
    - exam_certification      考试与认证（题库/组卷/在线考试/证书/二维码验证）
    - phishing_simulation     钓鱼演练（模板库/分组/点击追踪/意识评分，纯模拟）
    - awareness_assessment    安全意识评估（问卷/部门对比/薄弱环节/合规报告）
    - training_operations     培训运营（学员/讲师/班级/柯氏四级评估/ROI）
    - training_workflow       综合培训工作流（需求→匹配→学习→实验→考试→认证）

设计定位：
    - 全部为培训、评估、模拟视角；钓鱼演练仅做模拟与意识打分，绝不真实发送邮件。
    - 所有第三方库 try-import，不可用时回退到内嵌离线模拟数据。
    - Python 3.14 兼容；全部数据用内存字典模拟，不落库。
"""

from __future__ import annotations

__version__ = "14.2.0"
__round__ = 14

try:
    from security_training.course_manager import CourseManager, COURSE_CATEGORIES, COURSE_LIBRARY
except Exception:  # pragma: no cover
    CourseManager = None  # type: ignore
    COURSE_CATEGORIES = {}
    COURSE_LIBRARY = {}

try:
    from security_training.lab_environment import LabEnvironmentManager, RANGE_LIBRARY
except Exception:  # pragma: no cover
    LabEnvironmentManager = None  # type: ignore
    RANGE_LIBRARY = {}

try:
    from security_training.exam_certification import ExamCertManager, EXAM_BANK
except Exception:  # pragma: no cover
    ExamCertManager = None  # type: ignore
    EXAM_BANK = {}

try:
    from security_training.phishing_simulation import PhishingSimulation, PHISHING_TEMPLATES
except Exception:  # pragma: no cover
    PhishingSimulation = None  # type: ignore
    PHISHING_TEMPLATES = {}

try:
    from security_training.awareness_assessment import AwarenessAssessor, AWARENESS_QUESTIONNAIRE
except Exception:  # pragma: no cover
    AwarenessAssessor = None  # type: ignore
    AWARENESS_QUESTIONNAIRE = {}

try:
    from security_training.training_operations import TrainingOperations
except Exception:  # pragma: no cover
    TrainingOperations = None  # type: ignore

try:
    from security_training.training_workflow import TrainingWorkflow, get_training_workflow, TRAINING_WORKFLOW_STEPS
except Exception:  # pragma: no cover
    TrainingWorkflow = None  # type: ignore
    get_training_workflow = None  # type: ignore
    TRAINING_WORKFLOW_STEPS = []

__all__ = [
    "__version__", "__round__",
    "CourseManager", "COURSE_CATEGORIES", "COURSE_LIBRARY",
    "LabEnvironmentManager", "RANGE_LIBRARY",
    "ExamCertManager", "EXAM_BANK",
    "PhishingSimulation", "PHISHING_TEMPLATES",
    "AwarenessAssessor", "AWARENESS_QUESTIONNAIRE",
    "TrainingOperations",
    "TrainingWorkflow", "get_training_workflow", "TRAINING_WORKFLOW_STEPS",
]
