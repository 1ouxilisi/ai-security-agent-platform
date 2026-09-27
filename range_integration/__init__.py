# -*- coding: utf-8 -*-
"""
range_integration - 真实靶场集成包

6 大核心模块：
- range_manager: 靶场环境管理（列表/部署/配置/生命周期/监控/模板）
- vuln_range:    漏洞靶场集成（Web/系统/移动/云/API/工控）
- auto_scanner:  自动扫描与验证（扫描/验证/对比/策略/性能/质量）
- range_report:  靶场报告生成（评估/利用/学习路径/对比/合规/教练反馈）
- range_learning: 靶场学习与训练（路径/课程/练习/考核/团队/竞赛）
- range_dashboard: 靶场管理控制台数据（总览/管理/扫描/学习/用户/设置）

所有模块使用内存字典模拟，不依赖数据库；第三方库 try-import 容错。
"""

from __future__ import annotations

__version__ = "22.2.0"
__module__ = "range_integration"
