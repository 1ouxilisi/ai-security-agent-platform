# -*- coding: utf-8 -*-
"""
self_security — 自身安全加固大提升模块包（第19轮升级方向2）。

六个核心子模块：
    - self_pentest            自身渗透测试（授权安全评估）
    - code_security_audit     代码安全审计 / SAST
    - api_security_hardening  API 安全加固
    - data_security_privacy   数据安全与隐私
    - runtime_protection      运行时安全防护（WAF/IDS/日志）
    - security_dashboard      安全仪表盘与报告

设计原则：
    * 仅做防御 / 检测 / 加固视角的安全评估，不对任何外部目标发起攻击。
    * 全部为内存字典模拟异步，不创建数据库表。
    * 第三方能力 try-import，缺失时回退为基于正则的本地静态扫描。
"""

from __future__ import annotations

__all__ = [
    "self_pentest",
    "code_security_audit",
    "api_security_hardening",
    "data_security_privacy",
    "runtime_protection",
    "security_dashboard",
]

__version__ = "19.2.0"
