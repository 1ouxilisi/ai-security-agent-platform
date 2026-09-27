# -*- coding: utf-8 -*-
"""
darkweb_monitor — 暗网监控与数字风险保护(DRP)模块（第13轮升级）。

提供：
- 暗网情报监控：论坛/市场/聊天频道/Pastebin/泄露站/博客/IRC 多源监控、
  关键词/品牌/域名/凭证监控、实时告警与情报报告。
- 凭证泄露检测：邮箱/手机号泄露、密码哈希分析、API密钥/Token/私钥泄露检测、
  密码强度评估与重置建议。
- 品牌保护与欺诈检测：仿冒域名/钓鱼网站/假冒App/虚假社媒账号/商标侵权/欺诈广告。
- 数据泄露分析：泄露数据解析、数据类型识别、影响范围评估、合规通知评估、根因分析。
- 威胁Actor与团伙分析：Actor画像、TTPs、攻击工具、关联分析、威胁等级评估。
- DRP综合运营：监控策略、风险评分、优先级排序、响应建议、takedown协助、情报报告。

合法边界：仅监控公开可访问的信息源，不参与非法交易，不购买泄露数据，
所有情报仅用于防御、品牌保护与数字风险保护目的。
"""

from __future__ import annotations

__version__ = "13.0.0"
__all__ = [
    "darkweb_intel",
    "credential_leak",
    "brand_protection",
    "data_breach_analysis",
    "threat_actor_analysis",
    "drp_operations",
]
