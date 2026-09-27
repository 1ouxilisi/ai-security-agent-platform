# -*- coding: utf-8 -*-
"""
visualization 模块 —— 数据可视化增强模块（第7轮升级）

模块功能：
    - 攻击路径可视化（AttackPathGenerator）
    - 网络拓扑可视化（NetworkTopologyGenerator）
    - 风险热力图（RiskHeatmapGenerator）
    - 趋势分析可视化（TrendAnalyzer）

定位说明：
    本模块为授权安全评估 / 防御检测产品的可视化分析组件，
    所有攻击路径图均为【防御视角的风险评估】，
    用于帮助安全团队理解攻击面、识别薄弱环节、加强防护，
    请勿用于非法用途。
"""

from .attack_path import AttackPathGenerator
from .network_topology import NetworkTopologyGenerator
from .risk_heatmap import RiskHeatmapGenerator
from .trend_analysis import TrendAnalyzer

# ===== 第10轮升级：数据可视化深化模块（不覆盖既有导出）=====
from .realtime_dashboard import RealtimeDashboard, realtime_dashboard
from .topology_3d import Topology3D, topology_3d
from .attack_map import AttackMap, attack_map
from .custom_dashboard import CustomDashboard, custom_dashboard

__all__ = [
    "AttackPathGenerator",
    "NetworkTopologyGenerator",
    "RiskHeatmapGenerator",
    "TrendAnalyzer",
    # 第10轮新增单例/类
    "RealtimeDashboard", "realtime_dashboard",
    "Topology3D", "topology_3d",
    "AttackMap", "attack_map",
    "CustomDashboard", "custom_dashboard",
]

__version__ = "10.0.0"
