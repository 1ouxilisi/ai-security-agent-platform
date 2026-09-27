# -*- coding: utf-8 -*-
"""
target_lab_real 包 —— 真实靶场一键部署

模块：
  - lab_registry: 靶场元数据注册表
  - docker_manager: docker CLI 封装
  - lab_config: 部署配置
  - lab_template: 部署模板
  - simulated_lab: 无 Docker 时的模拟靶场
  - lab_deployer: 一键部署/停止/重启/销毁/健康检查
  - labs_dashboard: 仪表盘聚合
"""
from __future__ import annotations

from . import lab_registry
from . import docker_manager
from . import lab_config
from . import lab_template
from . import simulated_lab
from . import lab_deployer
from . import labs_dashboard

__all__ = [
    "lab_registry", "docker_manager", "lab_config", "lab_template",
    "simulated_lab", "lab_deployer", "labs_dashboard",
]
