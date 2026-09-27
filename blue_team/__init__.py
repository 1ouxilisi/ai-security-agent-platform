# -*- coding: utf-8 -*-
"""
蓝队模块（Blue Team）

模块功能：
    - 检测规则管理（IDS/IPS/EDR/SIEM/日志）
    - 防御检测任务与告警管理
    - 日志分析与告警关联（模拟）
    - 防御有效性评估、防御盲区识别与改进建议

注意事项：
    - 本模块对日志/告警的分析为模拟推演，不直接接入真实生产日志流
    - 本模块仅用于授权的安全测试与红蓝对抗演练
"""
from blue_team.detection import BlueTeamDetector

# 全局单例，供路由层复用
blue_team = BlueTeamDetector()

__all__ = ["BlueTeamDetector", "blue_team"]
