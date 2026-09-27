# -*- coding: utf-8 -*-
"""
紫队模块（Purple Team）

模块功能：
    - 红蓝对抗演练编排与状态管理
    - 红队攻击与蓝队检测的对比分析
    - ATT&CK 检测覆盖率统计与覆盖率矩阵
    - 攻击/检测时间线对比与检测延迟分析
    - 复盘报告生成与改进措施跟踪

注意事项：
    - 本模块仅用于授权的安全测试与红蓝对抗演练
    - 所有数据均来自红队模拟与蓝队检测的推演结果
"""
from purple_team.debrief import PurpleTeamDebrief

# 全局单例，供路由层复用
purple_team = PurpleTeamDebrief()

__all__ = ["PurpleTeamDebrief", "purple_team"]
