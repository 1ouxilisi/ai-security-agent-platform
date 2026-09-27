# -*- coding: utf-8 -*-
"""
红队模块（Red Team）

模块功能：
    - 红队攻击场景管理
    - 攻击模拟（仅模拟与评估，不执行真实攻击）
    - 攻击路径建模与成功概率计算
    - 业务影响评估与红队报告生成

注意事项：
    - 本模块仅做模拟和评估，不执行真实攻击，不获取真实访问权限
    - 本模块仅用于授权的安全测试与红蓝对抗演练
"""
from red_team.simulation import RedTeamSimulator

# 全局单例，供路由层复用
red_team = RedTeamSimulator()

__all__ = ["RedTeamSimulator", "red_team"]
