# -*- coding: utf-8 -*-
"""domains_real — 所有领域真实可用模块包（方向2：补齐短板）。

包含：
    - red_blue_real:    红蓝对抗做实（红队真实攻击流程 + 蓝队真实检测规则）
    - supply_chain_real: 供应链安全做实（SBOM 生成 + CVE 组件漏洞检测）
    - devsecops_real:   DevSecOps 做实（CI/CD 集成 + Semgrep SAST）
    - forensics_real:   取证分析做实（内存/磁盘/网络/日志取证）
    - iot_ics_real:     工控/IoT 做实（Modbus/S7 协议 + IoT 设备发现）
    - domains_real_dashboard: 仪表盘聚合
"""
from __future__ import annotations

from . import red_blue_real
from . import supply_chain_real
from . import devsecops_real
from . import forensics_real
from . import iot_ics_real
from . import domains_real_dashboard

__all__ = [
    "red_blue_real",
    "supply_chain_real",
    "devsecops_real",
    "forensics_real",
    "iot_ics_real",
    "domains_real_dashboard",
]
