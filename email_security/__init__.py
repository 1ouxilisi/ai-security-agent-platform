# -*- coding: utf-8 -*-
"""email_security — 邮件安全与反欺诈检测包（第18轮升级方向1）。

包含：
- phishing_detector     钓鱼邮件检测（头/内容/URL/附件/信誉/评分）
- bec_detector          BEC 商业邮件欺诈检测（50+规则库）
- email_authentication  SPF/DKIM/DMARC/ARC/MTA-STS/SMTP 安全
- attachment_sandbox   附件静态分析 + 模拟动态沙箱 + YARA/哈希匹配
- email_threat_intel    邮件威胁情报与 IOC 管理/匹配/富化
- email_dashboard       邮件安全运营仪表盘与模拟钓鱼演练

设计边界：全部为检测/分析/管理视角的合法安全服务，不传播、不投递恶意软件。
"""

from __future__ import annotations

__version__ = "18.1.0"
__all__ = [
    "phishing_detector",
    "bec_detector",
    "email_authentication",
    "attachment_sandbox",
    "email_threat_intel",
    "email_dashboard",
]
