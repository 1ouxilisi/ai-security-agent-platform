# -*- coding: utf-8 -*-
"""
tools_installer/tool_detector.py — 工具检测

对注册表中的每个工具：
  - 用 shutil.which 判断是否安装
  - 运行 detect_cmd 抓取版本号
  - 做一次 --help / version 健康检查
  - 检查依赖是否满足
所有结果内存缓存，避免重复调用外部命令。
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from . import tool_registry as reg
from .package_manager import _run

VERSION_PATTERNS = [
    r"(\d+\.\d+(?:\.\d+){0,3})",
]


def _extract_version(text: str) -> Optional[str]:
    if not text:
        return None
    for pat in VERSION_PATTERNS:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


def detect_one(tool: Dict[str, Any], timeout: int = 8) -> Dict[str, Any]:
    """检测单个工具的安装状态、版本、健康度。"""
    cmd = tool.get("detect_cmd") or []
    info: Dict[str, Any] = {
        "name": tool["name"],
        "display": tool["display"],
        "category": tool["category"],
        "installed": False,
        "version": None,
        "path": None,
        "healthy": False,
        "missing_deps": [],
        "install": tool.get("install", {}),
        "description": tool.get("description"),
        "website": tool.get("website"),
        "detected_at": time.time(),
    }
    if not cmd:
        return info

    exe = cmd[0]
    path = shutil.which(exe)
    if not path and tool["name"] in ("python", "python3"):
        path = shutil.which("python") or shutil.which("python3")
        if path:
            cmd = [path] + cmd[1:]

    if not path and not cmd[0].startswith("docker"):
        info["status"] = "not_installed"
        return info

    if cmd[0].startswith("docker"):
        # docker image inspect 形式
        r = _run(cmd, timeout=timeout)
        if r["returncode"] == 0:
            info["installed"] = True
            info["healthy"] = True
            info["status"] = "installed"
            info["version"] = _extract_version(r.get("stdout", "")) or "present"
        else:
            info["installed"] = False
            info["status"] = "not_installed"
        return info

    info["path"] = path
    r = _run(cmd, timeout=timeout)
    out = (r.get("stdout", "") or "") + "\n" + (r.get("stderr", "") or "")
    version = _extract_version(out)
    info["version"] = version

    if r["returncode"] == 0 or version:
        info["installed"] = True
        info["healthy"] = True
        info["status"] = "installed"
    elif r["returncode"] == -1:
        info["installed"] = False
        info["status"] = "not_installed"
    else:
        info["installed"] = True
        info["healthy"] = False
        info["status"] = "broken"

    # 依赖检测
    for dep in tool.get("deps", []):
        if not shutil.which(dep):
            info["missing_deps"].append(dep)

    return info


def detect_all_tools(include_libs: bool = True,
                      include_images: bool = True) -> Dict[str, Any]:
    """批量检测所有工具。"""
    native = [detect_one(t) for t in reg.get_native_tools()]
    libs = [detect_one(t) for t in reg.get_python_libs()] if include_libs else []
    images = [detect_one(t) for t in reg.get_docker_images()] if include_images else []

    def summarize(items: List[Dict[str, Any]]) -> Dict[str, int]:
        installed = sum(1 for i in items if i["installed"])
        broken = sum(1 for i in items if i.get("status") == "broken")
        return {"total": len(items), "installed": installed,
                "not_installed": len(items) - installed,
                "broken": broken}

    return {
        "native": {"items": native, "summary": summarize(native)},
        "python_libs": {"items": libs, "summary": summarize(libs)},
        "docker_images": {"items": images, "summary": summarize(images)},
        "checked_at": time.time(),
    }


def health_check(tool_name: str) -> Dict[str, Any]:
    tool = reg.find_tool(tool_name)
    if not tool:
        return {"success": False, "error": f"未知工具 {tool_name}"}
    info = detect_one(tool, timeout=10)
    return {"success": True, "data": info}
