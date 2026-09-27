# -*- coding: utf-8 -*-
"""tech_deep_upgrade — 技术深度大升级包（方向1）。

提供：
    - web_pentest_deep:        Web 渗透深度增强（nuclei 全量 / SQLi 提权 / XSS 利用 /
                               多字典目录扫描 / 100+ 指纹库 / 真实 subprocess 调用）
    - internal_pentest_deep:   内网渗透做实（SMB / AD / 横向移动 / 凭据获取）
    - mobile_security_deep:    移动安全做实（APK 静态分析 / 组件 / 签名 / Frida 接口）
    - cloud_security_deep:     云安全做实（AWS/阿里云真实 API / 配置基线 / 资产发现）
    - tech_dashboard:          技术深度聚合仪表盘

设计原则：
    - 所有扫描都走 subprocess，超时 300s
    - 工具未安装时返回明确提示，绝不 mock
    - 全部内存字典模拟异步任务
    - 统一响应 {"success", "data", "error"}
"""
from __future__ import annotations

import logging

from .web_pentest_deep import (
    WebPentestDeepEngine,
    FINGERPRINT_DB,
    DIR_WORDLISTS,
    NUCLEI_TAGS,
)
from .internal_pentest_deep import (
    InternalPentestDeepEngine,
    SMB_ENUM_COMMANDS,
    AD_QUERY_TEMPLATES,
)
from .mobile_security_deep import (
    MobileSecurityDeepEngine,
    APK_ANALYZERS,
    FRIDA_SCRIPTS,
)
from .cloud_security_deep import (
    CloudSecurityDeepEngine,
    CLOUD_PROVIDERS,
    CONFIG_BASELINE_CHECKS,
)
from .tech_dashboard import (
    TechDeepDashboard,
    TECH_SCORE_BASELINE,
    CAPABILITY_MATRIX,
)

__all__ = [
    "WebPentestDeepEngine",
    "InternalPentestDeepEngine",
    "MobileSecurityDeepEngine",
    "CloudSecurityDeepEngine",
    "TechDeepDashboard",
    "FINGERPRINT_DB",
    "DIR_WORDLISTS",
    "NUCLEI_TAGS",
    "SMB_ENUM_COMMANDS",
    "AD_QUERY_TEMPLATES",
    "APK_ANALYZERS",
    "FRIDA_SCRIPTS",
    "CLOUD_PROVIDERS",
    "CONFIG_BASELINE_CHECKS",
    "TECH_SCORE_BASELINE",
    "CAPABILITY_MATRIX",
]

logger = logging.getLogger(__name__)
logger.info("tech_deep_upgrade package loaded (方向1: 技术深度大升级)")
