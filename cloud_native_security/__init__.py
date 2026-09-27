# -*- coding: utf-8 -*-
"""
cloud_native_security - 云原生安全深度 (CNAPP) 模块包（第25轮升级方向2）。

6 大核心子系统：
  - k8s_runtime      : K8s 运行时安全（资产发现/配置审计/运行时监控/逃逸检测/威胁检测/响应）
  - container_security : 容器安全深度（镜像扫描/运行时/逃逸防护/网络/合规/生命周期）
  - service_mesh     : 服务网格安全（资产发现/配置审计/mTLS/威胁检测/可视化/响应）
  - cwpp             : 云工作负载保护（工作负载发现/配置审计/运行时/漏洞/合规/响应）
  - cspm             : 云安全态势管理（云资产/配置审计/合规/风险评分/攻击路径/改进）
  - cnapp_dashboard  : 云原生安全控制台聚合（总览/K8s/容器/服务网格/CWPP/CSPM/设置）
"""

from __future__ import annotations

__version__ = "25.2.0"
__round__ = 25
__direction__ = "cloud-native-security-cnapp"

__all__ = [
    "k8s_runtime",
    "container_security",
    "service_mesh",
    "cwpp",
    "cspm",
    "cnapp_dashboard",
]
