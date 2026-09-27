# -*- coding: utf-8 -*-
"""内网渗透真实能力控制台聚合：内存字典存储，统一响应。"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from .ad_real import ADReal
from .ldap_real import LDAPReal
from .nmap_real import NmapReal
from .runner import tool_status
from .smb_real import SMBReal


class InternalRealDashboard:
    """聚合所有真实扫描能力，结果存内存字典。"""

    def __init__(self, timeout: int = 300) -> None:
        self.timeout = timeout
        self.nmap = NmapReal(timeout)
        self.smb = SMBReal(timeout)
        self.ldap = LDAPReal(timeout)
        self.ad = ADReal(timeout)
        # 内存存储
        self.scans: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}

    # ---------- 工具健康 ----------
    def health(self) -> Dict[str, Any]:
        st = tool_status()
        return {
            "tools": st,
            "summary": {
                name: "✅ 可用" if v["available"] else "❌ 未安装"
                for name, v in st.items()
            },
        }

    def _record(self, kind: str, params: Dict[str, Any], result: Dict[str, Any]) -> str:
        tid = f"scan_{uuid.uuid4().hex[:10]}"
        self.scans[tid] = {
            "id": tid,
            "kind": kind,
            "params": params,
            "result": result,
            "ts": time.time(),
        }
        return tid

    # ---------- Nmap ----------
    def host_discovery(self, cidr: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.nmap.host_discovery(cidr, timeout=timeout)
        tid = self._record("host_discovery", {"cidr": cidr}, r)
        return {"scan_id": tid, **r}

    def port_scan(self, target: str, ports: Optional[str] = None,
                  technique: str = "sS", timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.nmap.port_scan(target, ports=ports, technique=technique, timeout=timeout)
        tid = self._record("port_scan", {"target": target, "ports": ports}, r)
        return {"scan_id": tid, **r}

    def service_scan(self, target: str, ports: Optional[str] = None,
                     timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.nmap.service_version(target, ports=ports, timeout=timeout)
        tid = self._record("service_version", {"target": target, "ports": ports}, r)
        return {"scan_id": tid, **r}

    def os_detect(self, target: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.nmap.os_detection(target, timeout=timeout)
        tid = self._record("os_detection", {"target": target}, r)
        return {"scan_id": tid, **r}

    def nse_scan(self, target: str, scripts: str = "default",
                 ports: Optional[str] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.nmap.script_scan(target, scripts=scripts, ports=ports, timeout=timeout)
        tid = self._record("nse_scan", {"target": target, "scripts": scripts}, r)
        return {"scan_id": tid, **r}

    # ---------- SMB ----------
    def smb_shares(self, target: str, username: str = "", password: str = "",
                   domain: str = "", timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.smb.list_shares(target, username, password, domain, timeout)
        tid = self._record("smb_shares", {"target": target}, r)
        return {"scan_id": tid, **r}

    def smb_connect(self, target: str, share: str, username: str = "",
                    password: str = "", timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.smb.connect_share(target, share, username, password, timeout=timeout)
        tid = self._record("smb_connect", {"target": target, "share": share}, r)
        return {"scan_id": tid, **r}

    def rpc_users(self, target: str, username: str = "", password: str = "",
                  timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.smb.enumdomusers(target, username, password, timeout)
        tid = self._record("rpc_enumdomusers", {"target": target}, r)
        return {"scan_id": tid, **r}

    def rpc_domains(self, target: str, username: str = "", password: str = "",
                    timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.smb.enumdomains(target, username, password, timeout)
        tid = self._record("rpc_enumdomains", {"target": target}, r)
        return {"scan_id": tid, **r}

    def rpc_dominfo(self, target: str, username: str = "", password: str = "",
                    timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.smb.querydominfo(target, username, password, timeout)
        tid = self._record("rpc_querydominfo", {"target": target}, r)
        return {"scan_id": tid, **r}

    # ---------- LDAP / AD ----------
    def ldap_query(self, server: str, base_dn: str, bind_dn: str = "", password: str = "",
                   filter_str: str = "(objectClass=*)",
                   attributes: Optional[List[str]] = None,
                   use_ssl: bool = True, timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.ldap.query(server, base_dn, bind_dn, password, filter_str,
                            attributes, use_ssl, timeout)
        tid = self._record("ldap_query", {"server": server, "base_dn": base_dn}, r)
        return {"scan_id": tid, **r}

    def ldap_users(self, server: str, base_dn: str, bind_dn: str = "", password: str = "",
                   timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.ldap.users(server, base_dn, bind_dn, password, timeout)
        tid = self._record("ldap_users", {"server": server, "base_dn": base_dn}, r)
        return {"scan_id": tid, **r}

    def ldap_groups(self, server: str, base_dn: str, bind_dn: str = "", password: str = "",
                    timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.ldap.groups(server, base_dn, bind_dn, password, timeout)
        tid = self._record("ldap_groups", {"server": server, "base_dn": base_dn}, r)
        return {"scan_id": tid, **r}

    def ldap_computers(self, server: str, base_dn: str, bind_dn: str = "", password: str = "",
                       timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.ldap.computers(server, base_dn, bind_dn, password, timeout)
        tid = self._record("ldap_computers", {"server": server, "base_dn": base_dn}, r)
        return {"scan_id": tid, **r}

    def ldap_gpo(self, server: str, base_dn: str, bind_dn: str = "", password: str = "",
                 timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.ldap.gpo(server, base_dn, bind_dn, password, timeout)
        tid = self._record("ldap_gpo", {"server": server, "base_dn": base_dn}, r)
        return {"scan_id": tid, **r}

    def ad_assess(self, target: str, base_dn: str = "", bind_dn: str = "",
                  password: str = "", domain: str = "",
                  timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self.ad.assess(target, base_dn, bind_dn, password, domain, timeout)
        tid = self._record("ad_assess", {"target": target}, r)
        return {"scan_id": tid, **r}

    # ---------- 查询历史 ----------
    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        items = sorted(self.scans.values(), key=lambda x: x["ts"], reverse=True)
        return [
            {"id": s["id"], "kind": s["kind"], "params": s["params"],
             "ts": s["ts"], "success": s["result"].get("success")}
            for s in items[:limit]
        ]

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return self.scans.get(scan_id)


dashboard = InternalRealDashboard()
