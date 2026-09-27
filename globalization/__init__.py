# -*- coding: utf-8 -*-
"""
globalization — 国际化与全球部署包（第25轮升级方向4）。

六大核心模块：
  - i18n_engine            : 多语言国际化引擎（10+语言/翻译记忆/术语库/质量保证）
  - regional_compliance    : 区域合规管理（10+合规框架/跨境数据/隐私权利）
  - global_payment         : 国际支付与计费（10+支付方式/10+货币/税务/发票/订阅）
  - global_deployment      : 全球部署与CDN（10+区域/CDN/负载均衡/边缘计算）
  - localization           : 本地化与文化适配（时区/节假日/文化/区域营销/区域法律）
  - globalization_dashboard: 国际化控制台总览

全部内存字典模拟，不依赖数据库。所有模块 try-import 第三方库，缺失时回退模拟。
本包仅用于授权安全评估与企业国际化运营场景。
"""

from __future__ import annotations

__version__ = "25.4.0"
__author__ = "AI Hacking Agent Team"

# 子模块（try-import，缺失不崩溃）
try:
    from . import i18n_engine as _i18n_engine
    I18N_ENGINE = _i18n_engine
except Exception:
    I18N_ENGINE = None

try:
    from . import regional_compliance as _regional_compliance
    REGIONAL_COMPLIANCE = _regional_compliance
except Exception:
    REGIONAL_COMPLIANCE = None

try:
    from . import global_payment as _global_payment
    GLOBAL_PAYMENT = _global_payment
except Exception:
    GLOBAL_PAYMENT = None

try:
    from . import global_deployment as _global_deployment
    GLOBAL_DEPLOYMENT = _global_deployment
except Exception:
    GLOBAL_DEPLOYMENT = None

try:
    from . import localization as _localization
    LOCALIZATION = _localization
except Exception:
    LOCALIZATION = None

try:
    from . import globalization_dashboard as _globalization_dashboard
    GLOBALIZATION_DASHBOARD = _globalization_dashboard
except Exception:
    GLOBALIZATION_DASHBOARD = None

__all__ = [
    "I18N_ENGINE", "REGIONAL_COMPLIANCE", "GLOBAL_PAYMENT",
    "GLOBAL_DEPLOYMENT", "LOCALIZATION", "GLOBALIZATION_DASHBOARD",
    "__version__",
]
