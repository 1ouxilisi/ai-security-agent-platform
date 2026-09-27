# -*- coding: utf-8 -*-
"""
deploy — 一键部署与安装包模块（Round 20 升级方向 1）。

子模块:
  - env_detector       环境检测与依赖管理
  - installer          一键安装脚本生成（Windows/Linux/macOS/Docker/K8s/离线包）
  - config_wizard      初始化与配置向导
  - backup_recovery    升级与备份恢复
  - multi_env_deploy   多环境部署
  - deploy_dashboard   部署管理控制台数据模型
"""

from __future__ import annotations

__version__ = "20.1.0"
__module_name__ = "deploy"
