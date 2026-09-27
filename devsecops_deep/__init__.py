#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
devsecops_deep — 第26轮升级方向2：安全自动化与 DevSecOps 深度平台。

包含 7 大核心模块：
    - cicd_security         CI/CD 安全集成（管道管理/安全门禁/安全扫描集成/结果处理/度量/报告）
    - sast_deep             代码安全扫描深度（SAST/漏洞检测/质量分析/安全建议/规则/报告）
    - dependency_deep       依赖漏洞检测深度（清单生成/漏洞匹配/优先级/修复/许可证/管理）
    - container_deep        容器安全扫描深度（镜像扫描/运行时/逃逸/网络/合规/生命周期）
    - iac_security          IaC 基础设施即代码安全（扫描/配置错误/合规/修复/策略/报告）
    - security_as_code      安全即代码 SaC（策略/控制/流程/配置/测试/审计即代码）
    - devsecops_dashboard   DevSecOps 深度控制台数据聚合层

设计定位：全部内存字典模拟，不建数据库表；但核心扫描/解析/门禁判断为真实逻辑
（正则匹配代码、真实解析 requirements.txt、真实分析镜像层、真实解析 Terraform/YAML、
真实阈值判定门禁通过/失败）。
"""

from __future__ import annotations

__version__ = "26.2.0"
__all__ = [
    "cicd_security",
    "sast_deep",
    "dependency_deep",
    "container_deep",
    "iac_security",
    "security_as_code",
    "devsecops_dashboard",
]
