# -*- coding: utf-8 -*-
"""
security_final — 安全最终加固模块包（第22轮升级方向4）。

六个核心子模块：
    - self_pentest_final     自身渗透测试最终版
    - dep_vuln_final        依赖漏洞最终扫描
    - baseline_final         安全基线最终检查
    - audit_monitor          安全审计与监控
    - data_security_final    数据安全最终加固
    - security_dashboard_final 安全管理控制台

设计原则：
    * 仅做防御 / 检测 / 加固视角的安全评估，不对任何外部目标发起攻击。
    * 全部为内存字典模拟异步，不创建数据库表。
    * 第三方能力 try-import，缺失时回退为基于正则的本地静态扫描。
    * 真实扫描当前项目安全问题，真实检查安全基线，真实生成安全报告。
"""

from __future__ import annotations

__all__ = [
    "self_pentest_final",
    "dep_vuln_final",
    "baseline_final",
    "audit_monitor",
    "data_security_final",
    "security_dashboard_final",
]

__version__ = "22.4.0"
