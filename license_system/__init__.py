# -*- coding: utf-8 -*-
"""
license_system — 软件 License 授权系统。

模块组成:
    # v21 旧模块（保留向后兼容）
    license_generator   License 生成/签名/验证/吊销/审计（RSA-PSS）
    device_binding      设备指纹采集、激活流程、设备绑定/离线激活
    feature_control     功能模块/用户数/时间/API配额/数据量限制
    billing_upgrade     续费/升级/加购/扩容/订单/价格管理
    anti_piracy         防篡改/逆向防护/破解检测/水印/黑名单/合规
    license_dashboard   运营仪表盘聚合（总览/分布/收入/告警）

    # v30 真实 License 系统（机器码绑定 + 功能分级）
    license_verifier    License 验证中间件（签名/机器码/过期）
    license_manager     License 生命周期管理（激活/状态/历史）
    feature_gating      功能分级闸门（Free/Pro/Enterprise）
    license_generator   同时提供 RealLicenseIssuer / generate_machine_code /
                        generate_real_license / REAL_TIERS
"""

from __future__ import annotations

__version__ = "30.0.0"
__all__ = [
    # v21 旧模块
    "license_generator",
    "device_binding",
    "feature_control",
    "billing_upgrade",
    "anti_piracy",
    "license_dashboard",
    # v30 新模块
    "license_verifier",
    "license_manager",
    "feature_gating",
]
