# -*- coding: utf-8 -*-
"""
deception — 蜜罐与欺骗技术模块（第13轮升级）。

提供：
- 蜜罐部署管理器（Web/SSH/SMB/数据库/邮件/DNS/IoT/工控/FTP/Telnet/RDP/VNC）
- 攻击检测与告警器（行为捕获/横向移动/凭据窃取/提权/攻击链重建）
- 威胁情报生成器（攻击者画像/TTPs/工具识别/IOC提取/ATT&CK映射）
- 诱饵与面包屑设计器（虚假文件/数据库/API/账户/网络共享）
- 蜜网与分布式欺骗管理器（多节点/集中管理/流量转发/云原生）
- 欺骗技术综合运营器（策略管理/效果评估/SOAR联动/红蓝对抗/成熟度）

合法边界：本模块仅用于防御、检测与安全研究。蜜罐仅被动记录与分析，
不主动攻击任何系统；收集的数据仅用于防御目的。
"""

from __future__ import annotations

__version__ = "13.0.0"
__all__ = [
    "honeypot_manager",
    "attack_detector",
    "threat_intel_generator",
    "decoy_breadcrumb",
    "honeynet_distributed",
    "deception_operations",
]
