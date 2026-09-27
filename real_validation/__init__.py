#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
real_validation — 第28轮升级方向2：真实场景验证与误报率优化。

包含 7 大核心模块：
    - range_integration          真实靶场集成（DVWA/Juice Shop/WebGoat/bWAPP/Mutillidae/
                                  Pikachu/Vulhub/Metasploitable 等靶场管理/部署/监控/验证）
    - scan_validation            真实扫描验证（Nmap端口扫描/Web扫描/漏洞扫描/结果收集/
                                  误报漏报分析/验证报告）
    - false_positive_optimizer   误报率优化（误报规则库/过滤引擎/检测逻辑优化/
                                  机器学习模型/人工审核/优化效果）
    - vuln_verification          漏洞确认与验证（POC/EXP验证/CVSS评级/CWE分类/趋势报告）
    - validation_framework       验证体系与基准（验证标准/基准靶场/验证用例库/
                                  自动化验证/验证度量）
    - real_validation_dashboard   真实场景验证控制台数据聚合层

设计定位：全部内存字典模拟，不建数据库表；靶场管理真实维护 DVWA 等靶场部署状态、
扫描验证真实对靶场执行扫描并统计误报率漏报率、误报优化真实管理误报规则和过滤逻辑、
漏洞验证真实确认漏洞可利用性、验证体系真实管理验证用例和基准。
"""

from __future__ import annotations

__version__ = "28.2.0"
__all__ = [
    "range_integration",
    "scan_validation",
    "false_positive_optimizer",
    "vuln_verification",
    "validation_framework",
    "real_validation_dashboard",
]
