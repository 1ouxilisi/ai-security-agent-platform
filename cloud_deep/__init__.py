# -*- coding: utf-8 -*-
"""
cloud_deep — 云安全深度做实（方向4）。

子模块：
    cloud_client          统一云客户端（AWS boto3 / 阿里云 SDK）
    config_checker        配置检查规则引擎（安全组/存储桶/防火墙/IAM/加密）
    asset_discovery       云资产自动发现
    risk_rater            风险评级与修复建议
    cloud_deep_dashboard  控制台聚合

设计原则：
    - 真实对接：boto3 / aliyun SDK 可用时直接调用云 API；
    - 未配置凭证时返回明确提示，不 mock 任何"看起来真实"的结果；
    - 全部内存字典模拟存储。
"""
from __future__ import annotations

__version__ = "33.1.0"
__all__ = [
    "cloud_client",
    "config_checker",
    "asset_discovery",
    "risk_rater",
    "cloud_deep_dashboard",
]

try:  # noqa: SIM105
    from . import cloud_client, config_checker, asset_discovery  # noqa: F401
    from . import risk_rater, cloud_deep_dashboard  # noqa: F401
except Exception:
    pass
