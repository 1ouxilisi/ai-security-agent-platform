# -*- coding: utf-8 -*-
"""
asset_management - 资产管理深化模块

本模块为 AI Hacking Agent 提供完整的资产管理能力，包含：
    - discovery:        资产发现器（主动/被动发现模拟、合并去重、导入资产）
    - fingerprint:      资产指纹库（200+ 指纹规则，服务/操作系统/应用识别）
    - risk_rating:      资产风险评级器（7 维度加权评分、趋势、排名、建议）
    - change_detection: 资产变更检测器（8 类变更、基线对比、审批、自动告警）
    - grouping:         资产分组管理器（树形分组、自动分组、批量扫描/报告）

注意事项：
    - 本模块仅用于授权的安全测试与资产管理
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = [
    "discovery",
    "fingerprint",
    "risk_rating",
    "change_detection",
    "grouping",
]

# 模块导入时自动确保所有数据表存在（容错处理，不抛出致命错误）
try:  # pragma: no cover - 仅做初始化兜底
    from asset_management import discovery as _disc  # noqa: F401
    from asset_management import fingerprint as _fp  # noqa: F401
    from asset_management import risk_rating as _rr  # noqa: F401
    from asset_management import change_detection as _cd  # noqa: F401
    from asset_management import grouping as _grp  # noqa: F401
except Exception:  # pragma: no cover
    # 允许单独导入子模块而不强制整体依赖
    pass
