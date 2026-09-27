# -*- coding: utf-8 -*-
"""内网渗透真实能力包：全部基于真实 subprocess 执行 nmap/smbclient/rpcclient/ldapsearch/nuclei。

仅用于已授权的安全测试。工具未安装时返回明确提示，不产生 mock 数据。
"""
from __future__ import annotations

from .runner import ToolRunner, tool_status, run_subprocess
from .nmap_real import NmapReal
from .smb_real import SMBReal
from .ldap_real import LDAPReal
from .ad_real import ADReal
from .console import InternalRealDashboard

__all__ = [
    "ToolRunner",
    "tool_status",
    "run_subprocess",
    "NmapReal",
    "SMBReal",
    "LDAPReal",
    "ADReal",
    "InternalRealDashboard",
]
