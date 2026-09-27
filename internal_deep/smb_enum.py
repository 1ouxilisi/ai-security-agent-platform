# -*- coding: utf-8 -*-
"""smb_enum.py — SMB 深度枚举。

真实调用 smbclient / rpcclient（subprocess，超时 300s）：
  - 共享列表枚举（smbclient -L）
  - 用户列表枚举（rpcclient querydispinfo / enumdomusers）
  - 组列表枚举（rpcclient enumalsgroups / enumdomgroups）
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


def _parse_shares(out: str) -> List[Dict[str, Any]]:
    shares: List[Dict[str, Any]] = []
    for line in out.splitlines():
        # smbclient -L 输出形如:  SHARENAME    Disk
        parts = line.split()
        if len(parts) >= 2 and parts[1] in ("Disk", "IPC", "Printer"):
            shares.append({"name": parts[0], "type": parts[1]})
    return shares


def _parse_rpc_users(out: str) -> List[Dict[str, Any]]:
    users: List[Dict[str, Any]] = []
    for line in out.splitlines():
        # [response] users:[0xffffffff] user:[alice]
        if "user:[" in line and "]" in line:
            try:
                name = line.split("user:[", 1)[1].split("]", 1)[0]
                users.append({"username": name})
            except Exception:  # noqa: BLE001
                pass
    return users


def _parse_rpc_groups(out: str) -> List[Dict[str, Any]]:
    groups: List[Dict[str, Any]] = []
    for line in out.splitlines():
        if "group:" in line or "[0x" in line and "group:" in line:
            groups.append({"raw": line.strip()[:200]})
    return groups


class SMBEnumerator:
    """SMB 深度枚举器。"""

    def tools_status(self) -> Dict[str, Any]:
        return {"smbclient": _which("smbclient"),
                "rpcclient": _which("rpcclient")}

    def list_shares(self, host: str, user: str = "", password: str = "",
                    timeout: int = TIMEOUT) -> Dict[str, Any]:
        cred = []
        if user:
            cred = ["-U", f"{user}%{password}"]
        else:
            cred = ["-N"]
        cmd = ["smbclient", "-L", f"//{host}/"] + cred
        res = _run(cmd, timeout)
        if res["ok"]:
            res["shares"] = _parse_shares(res["stdout"])
        else:
            res["shares"] = []
        return res

    def list_users(self, host: str, user: str = "", password: str = "",
                   timeout: int = TIMEOUT) -> Dict[str, Any]:
        if not user:
            user = "guest"; password = ""
        cmd = ["rpcclient", f"//{host}", "-U", f"{user}%{password}",
               "-c", "querydispinfo; enumdomusers"]
        res = _run(cmd, timeout)
        if res["ok"]:
            res["users"] = _parse_rpc_users(res["stdout"])
        else:
            res["users"] = []
        return res

    def list_groups(self, host: str, user: str = "", password: str = "",
                    timeout: int = TIMEOUT) -> Dict[str, Any]:
        if not user:
            user = "guest"; password = ""
        cmd = ["rpcclient", f"//{host}", "-U", f"{user}%{password}",
               "-c", "enumalsgroups domain; enumdomgroups"]
        res = _run(cmd, timeout)
        if res["ok"]:
            res["groups"] = _parse_rpc_groups(res["stdout"])
        else:
            res["groups"] = []
        return res

    def full_enum(self, host: str, user: str = "", password: str = "",
                  timeout: int = TIMEOUT) -> Dict[str, Any]:
        return {
            "host": host,
            "shares": self.list_shares(host, user, password, timeout),
            "users": self.list_users(host, user, password, timeout),
            "groups": self.list_groups(host, user, password, timeout),
        }


_singleton: SMBEnumerator | None = None


def get_smb_enumerator() -> SMBEnumerator:
    global _singleton
    if _singleton is None:
        _singleton = SMBEnumerator()
    return _singleton
