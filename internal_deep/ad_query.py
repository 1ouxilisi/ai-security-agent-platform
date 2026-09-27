# -*- coding: utf-8 -*-
"""ad_query.py — AD 深度查询。

真实调用 ldapsearch（subprocess，超时 300s）：
  - 用户查询、组查询、计算机查询、OU 查询。
未安装工具时明确提示，不 mock。
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List

TIMEOUT = 300


def _which(name: str) -> Dict[str, Any]:
    p = shutil.which(name)
    return {"available": bool(p), "path": p, "error": None if p else f"{name} not in PATH"}


def _run(cmd: List[str], timeout: int = TIMEOUT) -> Dict[str, Any]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout, check=False)
        return {"ok": proc.returncode == 0, "rc": proc.returncode,
                "stdout": (proc.stdout or "")[:20000],
                "stderr": (proc.stderr or "")[:4000],
                "error": None, "cmd": cmd}
    except FileNotFoundError as e:
        return {"ok": False, "rc": -1, "stdout": "", "stderr": "",
                "error": f"tool not found: {e}", "cmd": cmd}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -2, "stdout": "", "stderr": "",
                "error": f"timeout after {timeout}s", "cmd": cmd}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "rc": -3, "stdout": "", "stderr": "",
                "error": str(e), "cmd": cmd}


def _parse_ldap_entries(out: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    cur: Dict[str, Any] = {}
    for line in out.splitlines():
        if line.startswith("dn:"):
            if cur:
                entries.append(cur)
            cur = {"dn": line[3:].strip()}
        elif ":" in line and cur:
            k, _, v = line.partition(":")
            cur[k.strip()] = v.strip()
    if cur:
        entries.append(cur)
    return entries


class ADQuerier:
    """AD 深度查询器。"""

    def tools_status(self) -> Dict[str, Any]:
        return {"ldapsearch": _which("ldapsearch")}

    @staticmethod
    def _base_cmd(dc: str, user: str, password: str) -> List[str]:
        # dc 形如 "dc=contoso,dc=local"
        bind = []
        if user:
            bind = ["-D", user, "-w", password]
        else:
            bind = ["-x", "-W"] if password else ["-x"]
        return ["ldapsearch", "-x", "-H", f"ldap://{dc}"] + bind + ["-b", dc]

    def query_users(self, dc: str, user: str = "", password: str = "",
                    timeout: int = TIMEOUT) -> Dict[str, Any]:
        cmd = self._base_cmd(dc, user, password) + [
            "(objectClass=user)", "sAMAccountName", "mail", "description"]
        res = _run(cmd, timeout)
        res["entries"] = _parse_ldap_entries(res["stdout"]) if res["ok"] else []
        return res

    def query_groups(self, dc: str, user: str = "", password: str = "",
                     timeout: int = TIMEOUT) -> Dict[str, Any]:
        cmd = self._base_cmd(dc, user, password) + [
            "(objectClass=group)", "cn", "member"]
        res = _run(cmd, timeout)
        res["entries"] = _parse_ldap_entries(res["stdout"]) if res["ok"] else []
        return res

    def query_computers(self, dc: str, user: str = "", password: str = "",
                        timeout: int = TIMEOUT) -> Dict[str, Any]:
        cmd = self._base_cmd(dc, user, password) + [
            "(objectClass=computer)", "dNSHostName", "operatingSystem", "lastLogon"]
        res = _run(cmd, timeout)
        res["entries"] = _parse_ldap_entries(res["stdout"]) if res["ok"] else []
        return res

    def query_ous(self, dc: str, user: str = "", password: str = "",
                  timeout: int = TIMEOUT) -> Dict[str, Any]:
        cmd = self._base_cmd(dc, user, password) + [
            "(objectClass=organizationalUnit)", "ou", "description"]
        res = _run(cmd, timeout)
        res["entries"] = _parse_ldap_entries(res["stdout"]) if res["ok"] else []
        return res

    def full_query(self, dc: str, user: str = "", password: str = "",
                   timeout: int = TIMEOUT) -> Dict[str, Any]:
        return {
            "dc": dc,
            "users": self.query_users(dc, user, password, timeout),
            "groups": self.query_groups(dc, user, password, timeout),
            "computers": self.query_computers(dc, user, password, timeout),
            "ous": self.query_ous(dc, user, password, timeout),
        }


_singleton: ADQuerier | None = None


def get_ad_querier() -> ADQuerier:
    global _singleton
    if _singleton is None:
        _singleton = ADQuerier()
    return _singleton
