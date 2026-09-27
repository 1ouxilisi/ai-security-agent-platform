"""
护网行动（HuDong）支持模块

模块功能：
    - preparation.py  护网准备管理器（资产梳理/攻击面/漏洞扫描/风险评估/加固）
    - monitoring.py  护网持续监控器（告警/威胁/态势感知/攻击监测）
    - emergency.py   护网应急响应器（分级上报/遏制/根除/恢复/溯源/信息上报）
    - summary.py     护网总结管理器（数据统计/攻防复盘/改进计划/总结报告）

护网流程符合中国实际情况：准备 → 监控 → 应急 → 总结。

合法定位：
    本模块为企业防御视角的护网行动保障系统，用于己方资产的防护准备、
    监测预警与应急响应演练，不提供任何攻击实施能力。

注意事项：
    - 本模块仅用于授权的护网演练与安全运营
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

from hudong.preparation import PreparationManager, preparation_manager
from hudong.monitoring import MonitoringManager, monitoring_manager
from hudong.emergency import EmergencyManager, emergency_manager
from hudong.summary import SummaryManager, summary_manager

__all__ = [
    "PreparationManager",
    "preparation_manager",
    "MonitoringManager",
    "monitoring_manager",
    "EmergencyManager",
    "emergency_manager",
    "SummaryManager",
    "summary_manager",
]
