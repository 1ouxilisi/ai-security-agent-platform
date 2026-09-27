#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_training_deep — 第26轮升级方向4：安全培训与认证平台深度。

包含 7 大核心业务模块 + 1 个数据聚合层：
    - course_system          课程体系深度（课程管理/课程内容/课程路径/课程模板/课程质量/课程推荐）
    - lab_environment        实验环境深度（实验管理/靶场环境/环境管理/实验指导/实验评估/实验沙箱）
    - exam_certification     考试认证深度（考试管理/题库管理/考试执行/考试评分/证书管理/认证体系）
    - competency_assessment  能力评估深度（能力模型/能力评估/能力差距分析/能力发展/能力认证/能力报告）
    - enterprise_training    企业培训管理深度（培训计划/培训执行/培训评估/培训资源/培训统计/培训合规）
    - security_awareness     安全意识培训深度（意识课程/意识测试/意识活动/意识材料/意识度量/意识文化）
    - training_dashboard     安全培训深度控制台数据聚合层

设计定位：全部内存字典模拟，不建数据库表，真实功能可跑通。
"""

from __future__ import annotations

__version__ = "26.4.0"
__all__ = [
    "course_system",
    "lab_environment",
    "exam_certification",
    "competency_assessment",
    "enterprise_training",
    "security_awareness",
    "training_dashboard",
]
