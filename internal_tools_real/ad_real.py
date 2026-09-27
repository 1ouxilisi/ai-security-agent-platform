# -*- coding: utf-8 -*-
"""AD 综合评估：串联 nmap 端口探测 + SMB 枚举 + LDAP 查询，全部真实执行。"""
from __future__ import annotations

from typing import Any, Dict, Optional

from .ldap_real import LDAPReal
from .nmap_real import NmapReal
from .runner import ToolRunner
from .smb_real import SMBReal


class ADReal:
    """AD 真实评估流水线。"""

    def __init__(self, timeout: int = 300) -> None:
        self.nmap = NmapReal(timeout)
        self.smb = SMBReal(timeout)
        self.ldap = LDAPReal(timeout)
        self.runner = ToolRunner(timeout)

    def discover_dc(self, cidr: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """通过 nmap 探测域控常用端口（53/88/135/139/389/445/636/3268）。"""
        args = ["-Pn", "-p", "53,88,135,139,389,445,636,3268", cidr]
        return self.nmap._run_nmap(args, timeout=timeout)

    def assess(
        self,
        target: str,
        base_dn: str = "",
        bind_dn: str = "",
        password: str = "",
        domain: str = "",
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """对单台 DC 做完整评估：端口 → SMB → LDAP。"""
        result: Dict[str, Any] = {"target": target}
        result["port_scan"] = self.nmap.port_scan(
            target, ports="53,88,135,139,389,445,636,3268,3269", timeout=timeout
        )
        result["smb_shares"] = self.smb.list_shares(
            target, bind_dn.split("=")[-1] if bind_dn else "", password, domain, timeout=timeout
        )
        if base_dn:
            result["ldap_users"] = self.ldap.users(target, base_dn, bind_dn, password, timeout)
            result["ldap_computers"] = self.ldap.computers(target, base_dn, bind_dn, password, timeout)
            result["ldap_groups"] = self.ldap.groups(target, base_dn, bind_dn, password, timeout)
        return result
