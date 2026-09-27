# -*- coding: utf-8 -*-
"""
tools_installer/package_manager.py — 包管理器探测与执行

检测 Windows 上可用的包管理器：
  - Chocolatey (choco)
  - Scoop (scoop)
  - pip
  - npm
  - docker

提供统一的 run_command() 执行外部命令，实时捕获 stdout/stderr。
不 mock，未安装时明确返回安装指引。
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def detect_choco() -> Dict[str, Any]:
    p = _which("choco")
    if not p:
        return {"available": False, "path": None,
                "install_url": "https://chocolatey.org/install",
                "install_cmd": "Set-ExecutionPolicy Bypass -Scope Process -Force; "
                               "[System.Net.ServicePointManager]::SecurityProtocol = "
                               "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; "
                               "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"}
    ver = _run(["choco", "--version"], timeout=10)
    return {"available": True, "path": p,
            "version": ver.get("stdout", "").strip(),
            "install_url": "https://chocolatey.org/install"}


def detect_scoop() -> Dict[str, Any]:
    p = _which("scoop")
    if not p:
        return {"available": False, "path": None,
                "install_url": "https://scoop.sh",
                "install_cmd": "iwr -useb get.scoop.sh | iex"}
    ver = _run(["scoop", "--version"], timeout=10)
    return {"available": True, "path": p,
            "version": ver.get("stdout", "").strip()[:80],
            "install_url": "https://scoop.sh"}


def detect_pip() -> Dict[str, Any]:
    p = _which("pip") or _which("pip3")
    if not p:
        return {"available": False, "path": None,
                "install_url": "https://pip.pypa.io",
                "install_cmd": "python -m ensurepip --upgrade"}
    ver = _run([p, "--version"], timeout=10)
    return {"available": True, "path": p,
            "version": ver.get("stdout", "").strip()[:80],
            "install_url": "https://pip.pypa.io"}


def detect_npm() -> Dict[str, Any]:
    p = _which("npm")
    if not p:
        return {"available": False, "path": None,
                "install_url": "https://nodejs.org",
                "install_cmd": "choco install nodejs -y"}
    ver = _run(["npm", "--version"], timeout=10)
    return {"available": True, "path": p,
            "version": ver.get("stdout", "").strip(),
            "install_url": "https://nodejs.org"}


def detect_docker() -> Dict[str, Any]:
    p = _which("docker")
    if not p:
        return {"available": False, "path": None,
                "install_url": "https://www.docker.com/products/docker-desktop/",
                "install_cmd": "choco install docker-desktop -y"}
    ver = _run(["docker", "--version"], timeout=10)
    info = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=10)
    return {"available": True, "path": p,
            "version": ver.get("stdout", "").strip(),
            "daemon_running": info.get("returncode") == 0,
            "install_url": "https://www.docker.com/products/docker-desktop/"}


def detect_go() -> Dict[str, Any]:
    p = _which("go")
    if not p:
        return {"available": False, "path": None,
                "install_url": "https://go.dev/dl/",
                "install_cmd": "choco install golang -y"}
    ver = _run(["go", "version"], timeout=10)
    return {"available": True, "path": p,
            "version": ver.get("stdout", "").strip(),
            "install_url": "https://go.dev/dl/"}


def detect_ruby_gem() -> Dict[str, Any]:
    p = _which("gem")
    if not p:
        return {"available": False, "path": None,
                "install_url": "https://rubyinstaller.org",
                "install_cmd": "choco install ruby -y"}
    return {"available": True, "path": p, "install_url": "https://rubyinstaller.org"}


def detect_git() -> Dict[str, Any]:
    p = _which("git")
    if not p:
        return {"available": False, "path": None,
                "install_url": "https://git-scm.com",
                "install_cmd": "choco install git -y"}
    ver = _run(["git", "--version"], timeout=10)
    return {"available": True, "path": p,
            "version": ver.get("stdout", "").strip()}


def detect_all() -> Dict[str, Any]:
    """返回所有包管理器状态。"""
    return {
        "choco": detect_choco(),
        "scoop": detect_scoop(),
        "pip": detect_pip(),
        "npm": detect_npm(),
        "docker": detect_docker(),
        "go": detect_go(),
        "gem": detect_ruby_gem(),
        "git": detect_git(),
        "platform": sys.platform,
    }


# ---------------------------------------------------------------------------
# 命令执行
# ---------------------------------------------------------------------------
def _run(cmd: List[str], timeout: int = 15) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
            shell=(cmd[0].endswith(".ps1")) if cmd else False,
        )
        return {
            "returncode": p.returncode,
            "stdout": p.stdout or "",
            "stderr": p.stderr or "",
        }
    except FileNotFoundError:
        return {"returncode": -1, "stdout": "", "stderr": f"未找到命令: {cmd[0] if cmd else ''}"}
    except subprocess.TimeoutExpired:
        return {"returncode": -2, "stdout": "", "stderr": f"命令超时({timeout}s)"}
    except Exception as e:  # noqa: BLE001
        return {"returncode": -3, "stdout": "", "stderr": str(e)}


def run_stream(cmd: List[str], timeout: int = 300,
               on_line: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """实时执行命令，逐行回调输出。返回最终结果。"""
    lines: List[str] = []
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            bufsize=1,
        )
        deadline = time.time() + timeout
        assert proc.stdout is not None
        for line in proc.stdout:
            if time.time() > deadline:
                proc.kill()
                lines.append(f"[TIMEOUT] 超过 {timeout}s，已终止")
                return {"returncode": -2, "stdout": "\n".join(lines),
                        "timed_out": True}
            line = line.rstrip()
            lines.append(line)
            if on_line:
                try:
                    on_line(line)
                except Exception:  # noqa: BLE001
                    pass
        proc.wait(timeout=5)
        return {"returncode": proc.returncode, "stdout": "\n".join(lines),
                "timed_out": False}
    except FileNotFoundError:
        return {"returncode": -1, "stdout": "", "timed_out": False,
                "error": f"未找到命令: {cmd[0] if cmd else ''}"}
    except Exception as e:  # noqa: BLE001
        return {"returncode": -3, "stdout": "\n".join(lines),
                "timed_out": False, "error": str(e)}
