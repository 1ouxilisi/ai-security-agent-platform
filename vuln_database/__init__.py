# -*- coding: utf-8 -*-
"""
vuln_database 模块 —— AI Hacking Agent 第7轮升级：漏洞库深化模块

本模块提供：
    - CVE_DATABASE       : 200+ 条真实 CVE 记录（中文描述）
    - EXPLOIT_DB         : 100+ 条漏洞利用原理与检测方法（不含可执行代码）
    - REMEDIATION_DB     : 100+ 条漏洞修复方案

免责声明：
    本模块所有内容仅用于安全研究、授权渗透测试与防御建设。
    严禁用于任何非法用途。使用前请确保已获得书面授权。
"""

from .cve_database import (
    CVE_DATABASE,
    get_cve,
    search_cve,
    match_cve_by_service,
    get_cve_stats,
    list_cves,
    CVE_INDEX,
)

from .exploit_db import (
    EXPLOIT_DB,
    EXPLOIT_INDEX,
    get_exploit_by_cve,
    list_exploits,
    search_exploits,
)

from .remediation_db import (
    REMEDIATION_DB,
    REMEDIATION_INDEX,
    get_remediation_by_cve,
    list_remediations,
    search_remediations,
)

__all__ = [
    "CVE_DATABASE",
    "EXPLOIT_DB",
    "REMEDIATION_DB",
    "CVE_INDEX",
    "EXPLOIT_INDEX",
    "REMEDIATION_INDEX",
    "get_cve",
    "search_cve",
    "match_cve_by_service",
    "get_cve_stats",
    "list_cves",
    "get_exploit_by_cve",
    "list_exploits",
    "search_exploits",
    "get_remediation_by_cve",
    "list_remediations",
    "search_remediations",
]
