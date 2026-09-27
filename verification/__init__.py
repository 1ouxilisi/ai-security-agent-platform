# -*- coding: utf-8 -*-
"""漏洞真实验证模块（模块一：漏洞验证深度提升）。

本包提供：
    - WebVulnVerifier：Web 漏洞（SQL注入/XSS/路径穿越/SSRF/命令注入/文件上传）真实验证
    - ServiceVulnVerifier：服务层漏洞（弱口令/未授权/匿名/默认凭证/版本CVE匹配）真实验证
    - VerificationManager：验证任务队列、并发控制、结果缓存、统计与报告

合法安全边界：所有验证仅做"探测/存在性检测"，绝不获取 shell、不窃取数据、不上传 webshell。
"""

from .web_vuln_verifier import WebVulnVerifier
from .service_vuln_verifier import ServiceVulnVerifier
from .verification_manager import VerificationManager, verification_manager

__all__ = [
    "WebVulnVerifier",
    "ServiceVulnVerifier",
    "VerificationManager",
    "verification_manager",
]
