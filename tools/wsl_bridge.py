#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WSL 桥接器（模块二：2.2）。

职责：
    - 检测 WSL 是否可用、列出发行版
    - 在 WSL 中安装/运行 Linux 工具
    - 解析 WSL 输出为项目标准字典
    - WSL 不可用时返回降级方案
"""

import os
import subprocess
from typing import Any, Dict, List, Optional

try:
    from loguru import logger
except Exception:  # pragma: no cover
    import logging

    logger = logging.getLogger("wsl_bridge")


class WSLBridge:
    """WSL 桥接器。"""

    def __init__(self, default_distro: str = "", timeout: int = 60):
        self.default_distro = default_distro
        self.timeout = timeout
        self._available: Optional[bool] = None

    # ------------------------------------------------------------------
    # 1. is_wsl_available
    # ------------------------------------------------------------------
    def is_wsl_available(self) -> bool:
        """检测 WSL 是否安装可用。"""
        if self._available is not None:
            return self._available
        try:
            proc = subprocess.run(
                ["wsl", "--status"],
                capture_output=True, text=True, timeout=15, shell=True,
            )
            # 退出码 0 或输出含 "Linux" / "发行版" 即认为可用
            out = (proc.stdout or "") + (proc.stderr or "")
            self._available = (
                proc.returncode == 0 or "Linux" in out or "version" in out.lower()
                or "kernel" in out.lower()
            )
        except FileNotFoundError:
            self._available = False
        except Exception as e:
            logger.warning(f"WSL 检测失败: {e}")
            self._available = False
        return self._available

    # ------------------------------------------------------------------
    # 2. list_distributions
    # ------------------------------------------------------------------
    def list_distributions(self) -> List[str]:
        """列出已安装的 WSL 发行版。"""
        try:
            proc = subprocess.run(
                ["wsl", "--list", "--verbose"],
                capture_output=True, text=True, timeout=20, shell=True,
                errors="ignore",  # WSL 输出可能是 UTF-16
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            distros: List[str] = []
            for line in out.splitlines():
                line = line.strip()
                # 跳过表头
                if not line or "NAME" in line.upper() or "STATE" in line.upper():
                    continue
                # 发行版名通常在行首
                parts = line.split()
                if parts:
                    name = parts[0].strip("*").strip()
                    if name and name.lower() not in ("name",):
                        distros.append(name)
            return distros
        except Exception as e:
            logger.warning(f"列出 WSL 发行版失败: {e}")
            return []

    # ------------------------------------------------------------------
    # 3. install_in_wsl
    # ------------------------------------------------------------------
    def install_in_wsl(self, distro: str, package: str,
                       install_cmd: str = "") -> Dict[str, Any]:
        """在指定 WSL 发行版中安装工具。"""
        if not self.is_wsl_available():
            return {"status": "unavailable", "message": "WSL 不可用"}
        distro = distro or self.default_distro or (
            self.list_distributions() or [""])[0]
        if not install_cmd:
            install_cmd = f"sudo apt update && sudo apt install -y {package}"
        try:
            proc = subprocess.run(
                ["wsl", "-d", distro, "--", "bash", "-c", install_cmd],
                capture_output=True, text=True, timeout=600, shell=True,
            )
            return {
                "status": "ok" if proc.returncode == 0 else "failed",
                "distro": distro,
                "package": package,
                "returncode": proc.returncode,
                "stdout": (proc.stdout or "")[-1000:],
                "stderr": (proc.stderr or "")[-1000:],
            }
        except Exception as e:
            return {"status": "error", "distro": distro,
                    "package": package, "error": str(e)}

    # ------------------------------------------------------------------
    # 4. run_in_wsl
    # ------------------------------------------------------------------
    def run_in_wsl(self, distro: str, command: str,
                   timeout: Optional[int] = None) -> Dict[str, Any]:
        """通过 WSL 调用 Linux 工具。"""
        if not self.is_wsl_available():
            return {"status": "unavailable", "message": "WSL 不可用",
                    "stdout": "", "stderr": "", "returncode": -1}
        distro = distro or self.default_distro
        if not distro:
            distros = self.list_distributions()
            distro = distros[0] if distros else ""
        t = timeout or self.timeout
        try:
            cmd = ["wsl"]
            if distro:
                cmd += ["-d", distro]
            cmd += ["--", "bash", "-c", command]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=t, shell=True,
            )
            return {
                "status": "ok",
                "distro": distro,
                "command": command,
                "returncode": proc.returncode,
                "stdout": proc.stdout or "",
                "stderr": proc.stderr or "",
            }
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "command": command,
                    "stdout": "", "stderr": "", "returncode": -1}
        except Exception as e:
            return {"status": "error", "command": command,
                    "stdout": "", "stderr": str(e), "returncode": -1}

    # ------------------------------------------------------------------
    # 5. parse_wsl_output
    # ------------------------------------------------------------------
    def parse_wsl_output(self, output: str,
                         tool_name: str) -> Dict[str, Any]:
        """把 WSL 文本输出解析为项目标准字典。"""
        result: Dict[str, Any] = {
            "tool": tool_name,
            "raw": output,
            "lines": [],
            "version": "",
            "errors": [],
        }
        try:
            lines = (output or "").splitlines()
            result["lines"] = [l.strip() for l in lines if l.strip()]
            # 版本号提取
            import re
            m = re.search(r"(\d+\.\d+(?:\.\d+)*)", output or "")
            if m:
                result["version"] = m.group(1)
            # 错误行
            for l in lines:
                low = l.lower()
                if any(k in low for k in ("error", "failed", "no such",
                                          "not found", "cannot")):
                    result["errors"].append(l.strip())
        except Exception as e:
            result["parse_error"] = str(e)
        return result

    # ------------------------------------------------------------------
    # 6. get_fallback
    # ------------------------------------------------------------------
    def get_fallback(self, tool_name: str) -> Dict[str, Any]:
        """WSL 不可用时返回降级方案。"""
        fallbacks: Dict[str, Dict[str, str]] = {
            "masscan": {"method": "python_socket",
                        "desc": "降级为纯 Python socket 端口扫描（无速率优势）"},
            "hydra": {"method": "python_bruteforce",
                      "desc": "降级为 ftplib/paramiko 慢速登录尝试（限速 1/s）"},
            "dirb": {"method": "python_dirbruteforce",
                     "desc": "降级为 requests 目录字典爆破（较慢）"},
            "nikto": {"method": "basic_http_check",
                      "desc": "降级为基础 HTTP 头/常见路径探测"},
            "john": {"method": "python_hash_verify",
                     "desc": "降级为字典比对（仅支持简单哈希）"},
        }
        if not self.is_wsl_available():
            fb = fallbacks.get(tool_name, {
                "method": "manual",
                "desc": f"{tool_name} 无 Windows 原生包，建议启用 WSL 或手动安装"})
            return {"available": False, "tool": tool_name, **fb}
        return {"available": True, "tool": tool_name,
                "method": "wsl", "desc": "WSL 可用，直接在 WSL 中运行"}
