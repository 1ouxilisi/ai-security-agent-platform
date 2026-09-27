# -*- coding: utf-8 -*-
"""
target_lab_manager 包 —— 本地靶场一键部署

支持 DVWA / Juice Shop / WebGoat 三类靶场：
  - 有 Docker 时：subprocess 调用 docker 启动官方镜像
  - 无 Docker 时：用 Python 内置 http.server 在后台线程起一个模拟页面
统一由 LabManager 管理实例生命周期。全部内存字典记录状态。
"""

from __future__ import annotations

from .dvwa_deployer import DVWADeployer
from .juice_shop_deployer import JuiceShopDeployer
from .webgoat_deployer import WebGoatDeployer
from .lab_manager import LabManager, get_lab_manager
from .lab_dashboard import LabDashboard, get_lab_dashboard

__all__ = [
    "DVWADeployer",
    "JuiceShopDeployer",
    "WebGoatDeployer",
    "LabManager",
    "get_lab_manager",
    "LabDashboard",
    "get_lab_dashboard",
]
