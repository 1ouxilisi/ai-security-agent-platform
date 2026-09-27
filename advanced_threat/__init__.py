# -*- coding: utf-8 -*-
"""
advanced_threat — 高级威胁检测与响应包（第25轮升级方向1）。

包含六大核心子系统：
    1. ueba_engine          — UEBA 用户实体行为分析
    2. ml_anomaly           — 机器学习异常检测
    3. apt_detection        — APT 高级持续性威胁检测
    4. attack_chain         — 攻击链分析与重建
    5. threat_hunt          — 威胁狩猎深度平台
    6. advanced_threat_dashboard — 高级威胁检测控制台数据层

所有数据均为内存字典模拟，不建数据库表。
"""
from __future__ import annotations

__version__ = "25.1.0"
__module_name__ = "advanced_threat"
