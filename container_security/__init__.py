# -*- coding: utf-8 -*-
"""
container_security — 专业级容器与 Kubernetes 安全深化模块（第18轮升级方向2）。

6 大核心模块：
  1. image_scanner         — 容器镜像安全扫描
  2. runtime_security      — 容器运行时安全
  3. k8s_config_audit      — Kubernetes 配置审计
  4. k8s_runtime_security  — Kubernetes 运行时安全
  5. infrastructure_security — 容器基础设施安全
  6. container_dashboard   — 容器安全运营仪表盘

设计定位：仅用于经过授权的容器/K8s 安全检测、审计与加固建议，
全部为检测/审计/管理视角，合法安全服务边界。
"""

from __future__ import annotations

__version__ = "18.0.0"
__all__ = [
    "image_scanner",
    "runtime_security",
    "k8s_config_audit",
    "k8s_runtime_security",
    "infrastructure_security",
    "container_dashboard",
]
