#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_security_lifecycle — 第29轮升级方向3：API 安全全生命周期。

包含 7 大核心模块：
    - api_assets                API 资产管理（自动发现/手动录入/网关/流量/文档/SDK/爬虫/主动探测/目录/分类/版本/状态/负责人/依赖/调用链/健康/治理）
    - design_security           API 设计安全（设计原则/设计规范/认证授权/输入输出/错误处理/设计评审）
    - dev_security              API 开发安全（安全编码/安全测试/密钥管理/版本管理/CI-CD安全/开发文档）
    - runtime_security         API 运行时安全（网关/访问控制/流量控制/威胁防护/数据保护/监控告警）
    - abuse_logic               API 滥用与业务逻辑安全（滥用检测/业务逻辑漏洞/爬虫防护/重放攻击/配额计费/安全事件）
    - governance_compliance     API 安全治理与合规（安全策略/合规/度量/审计/报告/成熟度）
    - api_security_dashboard    API 安全生命周期控制台数据聚合层

设计定位：全部内存字典模拟，不建数据库表；但核心发现/检测/判定/评分逻辑为真实逻辑。
"""

from __future__ import annotations

__version__ = "29.3.0"
__all__ = [
    "api_assets",
    "design_security",
    "dev_security",
    "runtime_security",
    "abuse_logic",
    "governance_compliance",
    "api_security_dashboard",
]
