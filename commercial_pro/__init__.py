# -*- coding: utf-8 -*-
"""commercial_pro — 商业成熟度大升级包。

模块：
- license_real      真实机器码 + RSA-PSS 签名验证 + 功能分级
- customer_portal   客户登录/注册、项目管理、在线报告、个人信息
- billing_system    按扫描次数计费、订阅、支付接口预留、账单
- sla_monitor       可用性监控、故障自动恢复、备份恢复、状态页
- commercial_dashboard  商业化聚合
"""

from __future__ import annotations

__version__ = "4.0.0"
__target_score__ = "9.0"

__all__ = [
    "license_real",
    "customer_portal",
    "billing_system",
    "sla_monitor",
    "commercial_dashboard",
]
