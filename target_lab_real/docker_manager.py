# -*- coding: utf-8 -*-
"""
target_lab_real/docker_manager.py — Docker 操作封装

通过 subprocess 调用 docker CLI：
  - pull / run / stop / start / restart / rm / logs / inspect / stats
不依赖 docker SDK，未安装 Docker 时明确提示。
"""
from __future__ import annotations

import subprocess
import time
from typing import Any, Dict, List, Optional


def docker_available() -> Dict[str, Any]:
    try:
        r = subprocess.run(["docker", "--version"], capture_output=True,
                           text=True, timeout=5)
        if r.returncode != 0:
            return {"available": False, "message": r.stderr.strip()}
        info = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=5)
        return {
            "available": True,
            "version": r.stdout.strip(),
            "daemon_running": info.returncode == 0,
            "server_version": info.stdout.strip(),
        }
    except FileNotFoundError:
        return {"available": False,
                "message": "未找到 docker 命令，请先安装 Docker Desktop",
                "install_url": "https://www.docker.com/products/docker-desktop/"}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "message": f"docker 探测失败: {e}"}


def _run(cmd: List[str], timeout: int = 120) -> Dict[str, Any]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8",
                           errors="replace")
        return {"returncode": r.returncode, "stdout": r.stdout or "",
                "stderr": r.stderr or ""}
    except FileNotFoundError:
        return {"returncode": -1, "stdout": "", "stderr": "未找到 docker"}
    except subprocess.TimeoutExpired:
        return {"returncode": -2, "stdout": "", "stderr": f"超时({timeout}s)"}
    except Exception as e:  # noqa: BLE001
        return {"returncode": -3, "stdout": "", "stderr": str(e)}


def pull_image(image: str, timeout: int = 600) -> Dict[str, Any]:
    return _run(["docker", "pull", image], timeout=timeout)


def run_container(name: str, image: str,
                  port_map: Dict[int, int] | None = None,
                  env: Dict[str, str] | None = None,
                  volumes: Dict[str, str] | None = None,
                  restart: str = "no",
                  extra: Optional[List[str]] = None) -> Dict[str, Any]:
    cmd = ["docker", "run", "-d", "--name", name, "--restart", restart]
    for hp, cp in (port_map or {}).items():
        cmd += ["-p", f"{hp}:{cp}"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    for host, ctr in (volumes or {}).items():
        cmd += ["-v", f"{host}:{ctr}"]
    if extra:
        cmd += extra
    cmd.append(image)
    return _run(cmd, timeout=120)


def stop_container(name: str) -> Dict[str, Any]:
    return _run(["docker", "stop", name], timeout=60)


def start_container(name: str) -> Dict[str, Any]:
    return _run(["docker", "start", name], timeout=60)


def restart_container(name: str) -> Dict[str, Any]:
    return _run(["docker", "restart", name], timeout=120)


def remove_container(name: str, force: bool = True) -> Dict[str, Any]:
    cmd = ["docker", "rm"]
    if force:
        cmd.append("-f")
    cmd.append(name)
    return _run(cmd, timeout=60)


def remove_image(image: str, force: bool = True) -> Dict[str, Any]:
    cmd = ["docker", "rmi"]
    if force:
        cmd.append("-f")
    cmd.append(image)
    return _run(cmd, timeout=120)


def container_logs(name: str, tail: int = 200) -> Dict[str, Any]:
    return _run(["docker", "logs", "--tail", str(tail), name], timeout=30)


def container_inspect(name: str) -> Dict[str, Any]:
    r = _run(["docker", "inspect", name], timeout=15)
    return r


def container_stats(name: str) -> Dict[str, Any]:
    r = _run(["docker", "stats", name, "--no-stream", "--format",
              "{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}"],
             timeout=15)
    return r


def list_containers(filter_name: Optional[str] = None) -> List[Dict[str, Any]]:
    cmd = ["docker", "ps", "-a", "--format",
           "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"]
    if filter_name:
        cmd += ["--filter", f"name={filter_name}"]
    r = _run(cmd, timeout=15)
    out = []
    for line in r.get("stdout", "").strip().splitlines():
        parts = line.split("|")
        if len(parts) >= 5:
            out.append({"id": parts[0], "name": parts[1], "image": parts[2],
                        "status": parts[3], "ports": parts[4]})
    return out


def list_images() -> List[Dict[str, Any]]:
    r = _run(["docker", "images", "--format",
              "{{.Repository}}|{{.Tag}}|{{.Size}}|{{.CreatedSince}}"],
             timeout=15)
    out = []
    for line in r.get("stdout", "").strip().splitlines():
        parts = line.split("|")
        if len(parts) >= 4:
            out.append({"repo": parts[0], "tag": parts[1],
                        "size": parts[2], "created": parts[3]})
    return out
