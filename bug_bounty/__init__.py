# -*- coding: utf-8 -*-
"""
bug_bounty — 漏洞赏金 / SRC 管理平台包。

包含 6 个核心模块：
    - program_manager.py          项目与范围管理
    - submission_workflow.py       漏洞提交与审核流程
    - hunter_community.py          白帽与社区管理
    - bounty_finance.py           赏金与财务管理
    - vulnerability_lifecycle.py  漏洞生命周期与修复跟踪
    - src_dashboard.py            SRC 运营仪表盘

设计定位：合法的漏洞赏金平台管理端，用于管理 SRC 项目、接收白帽提交、
评定奖励、跟踪修复与运营统计；不提供任何利用漏洞、入侵目标的能力。
全部数据以内存字典模拟，不创建数据库表。
"""

from __future__ import annotations

__version__ = "18.3.0"
__all__ = [
    "program_manager",
    "submission_workflow",
    "hunter_community",
    "bounty_finance",
    "vulnerability_lifecycle",
    "src_dashboard",
]
