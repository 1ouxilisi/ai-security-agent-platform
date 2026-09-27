# -*- coding: utf-8 -*-
"""真实 SMB / NetBIOS 枚举：smbclient 列共享、rpcclient 查询 RPC 信息。"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .runner import ToolRunner


class SMBReal:
    """全部基于真实 smbclient / rpcclient 二进制。"""

    def __init__(self, timeout: int = 120) -> None:
        self.runner = ToolRunner(timeout)

    # ---------- smbclient ----------
    def list_shares(
        self,
        target: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """枚举 SMB 共享：smbclient -L //target -U user%pass"""
        chk = self.runner.ensure("smbclient")
        if not chk["success"]:
            return {"success": False, "data": None, "error": chk["error"]}
        cred = f"{username}%{password}" if username else "%password"
        cmd = ["smbclient", "-L", f"//{target}", "-N" if not username else f"-U{cred}"]
        if domain:
            cmd += ["-W", domain]
        res = self.runner.run(cmd, timeout=timeout)
        shares = self._parse_shares(res["stdout"] + "\n" + res["stderr"])
        return {
            "success": res["success"],
            "data": {"shares": shares, "raw": res["stdout"] + res["stderr"]},
            "error": res["stderr"] or None,
            "elapsed": res["elapsed"],
            "cmd": cmd,
        }

    def _parse_shares(self, text: str) -> List[Dict[str, str]]:
        shares: List[Dict[str, str]] = []
        # 典型行：  Disk       Drive      (Disk)
        for line in text.splitlines():
            m = re.match(r"^\s*(\S+)\s+(Disk|IPC|Printer|Comment)\s+(.*)$", line)
            if m:
                name, stype, comment = m.group(1), m.group(2), m.group(3).strip()
                shares.append({"name": name, "type": stype, "comment": comment})
            else:
                # 宽松匹配：第一个 token 是共享名，后面是类型
                parts = line.split()
                if len(parts) >= 2 and parts[1] in ("Disk", "IPC", "Printer"):
                    shares.append({
                        "name": parts[0],
                        "type": parts[1],
                        "comment": " ".join(parts[2:]).strip(),
                    })
        return shares

    def connect_share(
        self,
        target: str,
        share: str,
        username: str = "",
        password: str = "",
        commands: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """连接指定共享并执行一批交互命令（如 dir）。"""
        chk = self.runner.ensure("smbclient")
        if not chk["success"]:
            return {"success": False, "data": None, "error": chk["error"]}
        cred = f"{username}%{password}" if username else "%password"
        cmd = ["smbclient", f"//{target}/{share}", "-N" if not username else f"-U{cred}"]
        script_cmds = commands or ["dir"]
        stdin_input = "\n".join(script_cmds + ["exit"]) + "\n"
        try:
            import subprocess
            proc = subprocess.run(
                cmd, input=stdin_input, capture_output=True, text=True,
                timeout=timeout or self.runner.default_timeout,
                encoding="utf-8", errors="replace",
            )
            return {
                "success": proc.returncode == 0,
                "data": {"output": proc.stdout},
                "error": proc.stderr or None,
                "returncode": proc.returncode,
                "cmd": cmd,
            }
        except Exception as e:  # noqa: BLE001
            return {"success": False, "data": None, "error": str(e), "cmd": cmd}

    # ---------- rpcclient ----------
    def _rpc(
        self,
        target: str,
        rpc_cmds: List[str],
        username: str = "",
        password: str = "",
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        chk = self.runner.ensure("rpcclient")
        if not chk["success"]:
            return {"success": False, "data": None, "error": chk["error"]}
        cred = f"{username}%{password}" if username else "%"
        cmd = ["rpcclient", target, "-U", cred]
        stdin_input = "\n".join(rpc_cmds) + "\n"
        import subprocess
        proc = subprocess.run(
            cmd, input=stdin_input, capture_output=True, text=True,
            timeout=timeout or self.runner.default_timeout,
            encoding="utf-8", errors="replace",
        )
        return {
            "success": proc.returncode == 0,
            "data": {"output": proc.stdout},
            "error": proc.stderr or None,
            "returncode": proc.returncode,
            "cmd": cmd,
        }

    def enumdomusers(self, target: str, username: str = "", password: str = "",
                     timeout: Optional[int] = None) -> Dict[str, Any]:
        r = self._rpc(target, ["enumdomusers"], username, password, timeout)
        users = self._parse_rpc_lines(r.get("data", {}).get("output", ""), r"user:\[([^\]]+)\]\s+rid:\[(\d+)\]")
        r["data"] = {"users": users, "raw": r.get("data", {}).get("output", "")}
        return r

    def enumdomains(self, target: str, username: str = "", password: str = "",
                    timeout: Optional[int] = None) -> Dict[str, Any]:
        return self._rpc(target, ["enumdomains"], username, password, timeout)

    def querydominfo(self, target: str, username: str = "", password: str = "",
                     timeout: Optional[int] = None) -> Dict[str, Any]:
        return self._rpc(target, ["querydominfo"], username, password, timeout)

    def lsaenumsid(self, target: str, username: str = "", password: str = "",
                   timeout: Optional[int] = None) -> Dict[str, Any]:
        return self._rpc(target, ["lsaenumsid"], username, password, timeout)

    def netshareenum(self, target: str, username: str = "", password: str = "",
                     timeout: Optional[int] = None) -> Dict[str, Any]:
        return self._rpc(target, ["netshareenum"], username, password, timeout)

    def _parse_rpc_lines(self, text: str, pattern: str) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        rx = re.compile(pattern)
        for line in text.splitlines():
            m = rx.search(line)
            if m:
                out.append(dict(zip(["name", "rid"], m.groups())))
        return out
