# -*- coding: utf-8 -*-
"""统一子进程执行器：超时控制、工具探测、结构化输出。"""
from __future__ import annotations

import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT = 300


def which(name: str) -> Optional[str]:
    """跨平台探测可执行文件路径。"""
    return shutil.which(name)


_TOOL_CACHE: Dict[str, Optional[str]] = {}


def detect_tool(name: str) -> Optional[str]:
    if name not in _TOOL_CACHE:
        _TOOL_CACHE[name] = which(name)
    return _TOOL_CACHE[name]


def tool_status() -> Dict[str, Dict[str, Any]]:
    """返回所有相关工具的探测结果。"""
    names = ["nmap", "subfinder", "ldapsearch", "smbclient", "rpcclient", "nuclei"]
    out: Dict[str, Dict[str, Any]] = {}
    for n in names:
        path = detect_tool(n)
        out[n] = {"available": bool(path), "path": path}
    return out


class ToolRunner:
    """封装 subprocess 调用，统一超时与错误处理。"""

    def __init__(self, default_timeout: int = DEFAULT_TIMEOUT) -> None:
        self.default_timeout = default_timeout

    def ensure(self, tool: str) -> Dict[str, Any]:
        path = detect_tool(tool)
        if not path:
            return {
                "success": False,
                "error": f"工具 {tool} 未安装或不在 PATH 中，请先安装后再使用。",
                "path": None,
            }
        return {"success": True, "path": path}

    def run(
        self,
        cmd: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
    ) -> Dict[str, Any]:
        """执行命令并返回结构化结果。绝不 mock。"""
        to = timeout or self.default_timeout
        started = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=to,
                cwd=cwd,
                encoding="utf-8",
                errors="replace",
            )
            return {
                "success": proc.returncode == 0,
                "cmd": cmd,
                "returncode": proc.returncode,
                "stdout": proc.stdout or "",
                "stderr": proc.stderr or "",
                "elapsed": round(time.time() - started, 2),
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as e:
            return {
                "success": False,
                "cmd": cmd,
                "returncode": None,
                "stdout": (e.stdout or "") if isinstance(e.stdout, str) else "",
                "stderr": f"执行超时（{to}s）",
                "elapsed": round(time.time() - started, 2),
                "timed_out": True,
            }
        except FileNotFoundError as e:
            return {
                "success": False,
                "cmd": cmd,
                "returncode": None,
                "stdout": "",
                "stderr": f"命令未找到: {e}",
                "elapsed": round(time.time() - started, 2),
                "timed_out": False,
            }
        except Exception as e:  # noqa: BLE001
            return {
                "success": False,
                "cmd": cmd,
                "returncode": None,
                "stdout": "",
                "stderr": f"执行异常: {e}",
                "elapsed": round(time.time() - started, 2),
                "timed_out": False,
            }


def run_subprocess(cmd: List[str], timeout: Optional[int] = None) -> Dict[str, Any]:
    return ToolRunner(timeout or DEFAULT_TIMEOUT).run(cmd, timeout=timeout)
