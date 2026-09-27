# -*- coding: utf-8 -*-
"""真实 AD / LDAP 查询：ldapsearch，支持 Bind DN / Base DN / Filter。"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .runner import ToolRunner


class LDAPReal:
    """基于真实 ldapsearch 二进制。"""

    def __init__(self, timeout: int = 120) -> None:
        self.runner = ToolRunner(timeout)

    def query(
        self,
        server: str,
        base_dn: str,
        bind_dn: str = "",
        password: str = "",
        filter_str: str = "(objectClass=*)",
        attributes: Optional[List[str]] = None,
        use_ssl: bool = True,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """通用 LDAP 查询。"""
        chk = self.runner.ensure("ldapsearch")
        if not chk["success"]:
            return {"success": False, "data": None, "error": chk["error"]}
        proto = "ldaps" if use_ssl else "ldap"
        uri = f"{proto}://{server}"
        cmd = ["ldapsearch", "-x", "-H", uri, "-b", base_dn]
        if bind_dn:
            cmd += ["-D", bind_dn, "-w", password]
        else:
            cmd += ["-N"]
        cmd += [filter_str]
        if attributes:
            cmd += attributes
        res = self.runner.run(cmd, timeout=timeout)
        entries = self._parse_ldif(res["stdout"])
        return {
            "success": res["success"],
            "data": {"entries": entries, "count": len(entries), "raw": res["stdout"]},
            "error": res["stderr"] or None,
            "elapsed": res["elapsed"],
            "cmd": cmd,
        }

    def _parse_ldif(self, text: str) -> List[Dict[str, Any]]:
        entries: List[Dict[str, List[str]]] = []
        cur: Dict[str, List[str]] = {}
        cur_dn = ""
        for line in text.splitlines():
            if not line.strip():
                if cur:
                    entries.append({"dn": cur_dn, "attrs": cur})
                cur = {}
                cur_dn = ""
                continue
            if line.startswith("dn: "):
                cur_dn = line[4:].strip()
                continue
            if line.startswith("#") or ":" not in line:
                continue
            key, _, val = line.partition(":")
            val = val.lstrip().rstrip()
            cur.setdefault(key.strip(), [])
            cur[key.strip()].append(val)
        if cur:
            entries.append({"dn": cur_dn, "attrs": cur})
        return entries

    # ---------- 便捷查询 ----------
    def users(self, server: str, base_dn: str, bind_dn: str = "", password: str = "",
              timeout: Optional[int] = None) -> Dict[str, Any]:
        return self.query(server, base_dn, bind_dn, password,
                          "(&(objectClass=user)(objectCategory=person))",
                          ["sAMAccountName", "displayName", "mail", "memberOf",
                           "userAccountControl", "whenCreated"],
                          timeout=timeout)

    def groups(self, server: str, base_dn: str, bind_dn: str = "", password: str = "",
               timeout: Optional[int] = None) -> Dict[str, Any]:
        return self.query(server, base_dn, bind_dn, password,
                          "(objectClass=group)",
                          ["sAMAccountName", "member", "memberOf", "description"],
                          timeout=timeout)

    def computers(self, server: str, base_dn: str, bind_dn: str = "", password: str = "",
                  timeout: Optional[int] = None) -> Dict[str, Any]:
        return self.query(server, base_dn, bind_dn, password,
                          "(objectClass=computer)",
                          ["dNSHostName", "operatingSystem", "operatingSystemVersion",
                           "lastLogonTimestamp", "memberOf"],
                          timeout=timeout)

    def gpo(self, server: str, base_dn: str, bind_dn: str = "", password: str = "",
            timeout: Optional[int] = None) -> Dict[str, Any]:
        return self.query(server, f"CN=Policies,CN=System,{base_dn}", bind_dn, password,
                          "(objectClass=groupPolicyContainer)",
                          ["displayName", "gpcfilesyspath", "versionNumber"],
                          timeout=timeout)
