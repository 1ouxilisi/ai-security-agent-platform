# -*- coding: utf-8 -*-
"""
target_lab_real/lab_deployer.py — 靶场一键部署

- 有 Docker：docker pull + docker run，管理容器生命周期
- 无 Docker：回退到模拟靶场（simulated_lab）
- 健康检查：HTTP GET 访问路径，最多 60s，重试 3 次
- 实例状态全部内存字典
"""
from __future__ import annotations

import socket
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.request import urlopen
from urllib.error import URLError

from . import docker_manager
from .lab_config import LabDeployConfig
from .lab_registry import get_lab, list_labs
from .simulated_lab import SimulatedLab, alloc_port, is_port_free

# instance_id -> info
_INSTANCES: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.Lock()

NOTICE = "仅限授权环境：本地靶场仅用于授权安全测试 / 教学 / 演示。"


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _http_get(url: str, timeout: int = 5) -> int:
    try:
        with urlopen(url, timeout=timeout) as r:
            return r.status
    except URLError:
        return -1
    except Exception:  # noqa: BLE001
        return -1


def deploy(lab_id: str, config: Optional[LabDeployConfig] = None,
          host_port_override: Optional[int] = None) -> Dict[str, Any]:
    lab = get_lab(lab_id)
    if not lab:
        return {"success": False, "error": f"未知靶场 {lab_id}"}
    config = config or LabDeployConfig()
    inst_id = f"{lab_id}-{uuid.uuid4().hex[:6]}"
    container_name = f"arel-{inst_id}"

    info: Dict[str, Any] = {
        "instance_id": inst_id,
        "lab_id": lab_id,
        "name": lab["name"],
        "image": lab["image"],
        "status": "starting",
        "mode": "pending",
        "container_name": container_name,
        "host": "127.0.0.1",
        "port": None,
        "url": "",
        "started_at": None,
        "logs": [],
        "health": "pending",
    }
    with _LOCK:
        _INSTANCES[inst_id] = info

    def log(msg: str) -> None:
        info["logs"].append(f"[{_now()}] {msg}")
        if len(info["logs"]) > 500:
            info["logs"] = info["logs"][-400:]

    docker = docker_manager.docker_available()
    primary_host_port = host_port_override or (
        list(lab["ports"].keys())[0] if lab["ports"] else None)

    if docker["available"] and docker["daemon_running"]:
        log("Docker 可用，开始拉取镜像...")
        pull = docker_manager.pull_image(lab["image"])
        if pull["returncode"] != 0:
            log(f"镜像拉取失败：{pull['stderr'][:200]}")
            log("回退到模拟模式")
            return _deploy_mock(lab, info, config, log)

        port_map = {hp: cp for hp, cp in lab["ports"].items()}
        if host_port_override and lab["ports"]:
            first_cp = list(lab["ports"].values())[0]
            port_map = {host_port_override: first_cp}
        elif config.host_ports:
            port_map = config.host_ports

        env = dict(lab.get("env") or {})
        env.update(config.env)
        volumes = dict(lab.get("volumes") or {})
        volumes.update(config.volumes)

        log(f"docker run: name={container_name} ports={port_map}")
        run = docker_manager.run_container(
            container_name, lab["image"],
            port_map=port_map, env=env, volumes=volumes,
            restart=config.restart,
            extra=config.extra_docker_args())
        if run["returncode"] != 0:
            log(f"容器启动失败：{run['stderr'][:300]}")
            log("回退到模拟模式")
            return _deploy_mock(lab, info, config, log)

        info["mode"] = "docker"
        info["status"] = "running"
        info["container_id"] = run["stdout"].strip()[:12]
        hp = primary_host_port or (list(port_map.keys())[0] if port_map else 80)
        info["port"] = hp
        info["url"] = f"http://127.0.0.1:{hp}{lab['health_path']}"
        info["started_at"] = _now()
        log(f"容器已启动，等待健康检查...")
        threading.Thread(target=_health_check, args=(inst_id,),
                         daemon=True).start()
        return {"success": True, "data": _snapshot(inst_id)}

    log(f"Docker 不可用：{docker.get('message', '')}")
    log("进入模拟模式")
    return _deploy_mock(lab, info, config, log)


def _deploy_mock(lab: Dict[str, Any], info: Dict[str, Any],
                 config: LabDeployConfig, log) -> Dict[str, Any]:
    preferred = (list(lab["ports"].keys())[0] if lab["ports"] else None)
    port = alloc_port(preferred)
    if port == 0:
        info["status"] = "failed"
        log("无可用端口")
        return {"success": False, "error": "无可用端口"}
    mock = SimulatedLab(lab["lab_id"], "127.0.0.1", port)
    if not mock.start():
        info["status"] = "failed"
        return {"success": False, "error": "模拟服务启动失败"}
    info["mode"] = "mock"
    info["status"] = "running"
    info["port"] = port
    info["url"] = f"http://127.0.0.1:{port}"
    info["started_at"] = _now()
    info["_mock"] = mock
    log(f"模拟靶场启动于 {info['url']}")
    return {"success": True, "data": _snapshot(info["instance_id"])}


def _health_check(inst_id: str) -> None:
    with _LOCK:
        info = _INSTANCES.get(inst_id)
    if not info:
        return
    url = info.get("url")
    if not url:
        return
    for attempt in range(3):
        for _ in range(20):
            code = _http_get(url, timeout=3)
            if code > 0:
                info["health"] = "ok"
                info["logs"].append(f"[{_now()}] 健康检查通过 HTTP {code}")
                return
            time.sleep(3)
        info["logs"].append(f"[{_now()}] 健康检查第 {attempt+1} 次未通过")
    info["health"] = "failed"
    info["logs"].append(f"[{_now()}] 健康检查失败（可能镜像仍在初始化）")


def stop(inst_id: str) -> Dict[str, Any]:
    with _LOCK:
        info = _INSTANCES.get(inst_id)
    if not info:
        return {"success": False, "error": "实例不存在"}
    info["logs"].append(f"[{_now()}] 请求停止...")
    if info.get("_mock"):
        info["_mock"].stop()
        info["_mock"] = None
    elif info["mode"] == "docker" and info.get("container_name"):
        r = docker_manager.stop_container(info["container_name"])
        info["logs"].append(f"[{_now()}] docker stop rc={r['returncode']}")
    info["status"] = "stopped"
    info["url"] = ""
    return {"success": True, "data": _snapshot(inst_id)}


def restart(inst_id: str) -> Dict[str, Any]:
    with _LOCK:
        info = _INSTANCES.get(inst_id)
    if not info:
        return {"success": False, "error": "实例不存在"}
    if info["mode"] == "docker" and info.get("container_name"):
        r = docker_manager.restart_container(info["container_name"])
        info["logs"].append(f"[{_now()}] docker restart rc={r['returncode']}")
        info["status"] = "running"
        threading.Thread(target=_health_check, args=(inst_id,),
                         daemon=True).start()
    elif info.get("_mock"):
        info["_mock"].stop()
        mock = SimulatedLab(info["lab_id"], "127.0.0.1", info["port"] or 18080)
        mock.start()
        info["_mock"] = mock
        info["status"] = "running"
    return {"success": True, "data": _snapshot(inst_id)}


def destroy(inst_id: str, remove_image: bool = False) -> Dict[str, Any]:
    with _LOCK:
        info = _INSTANCES.get(inst_id)
    if not info:
        return {"success": False, "error": "实例不存在"}
    if info.get("_mock"):
        info["_mock"].stop()
    elif info["mode"] == "docker" and info.get("container_name"):
        docker_manager.remove_container(info["container_name"])
        if remove_image:
            docker_manager.remove_image(info["image"])
    info["status"] = "destroyed"
    info["url"] = ""
    return {"success": True, "data": _snapshot(inst_id)}


def logs(inst_id: str, tail: int = 200) -> Dict[str, Any]:
    with _LOCK:
        info = _INSTANCES.get(inst_id)
    if not info:
        return {"success": False, "error": "实例不存在"}
    out = list(info["logs"])
    if info["mode"] == "docker" and info.get("container_name"):
        r = docker_manager.container_logs(info["container_name"], tail=tail)
        out.append("--- docker logs ---")
        out.extend((r.get("stdout", "") or "").splitlines())
    return {"success": True,
            "data": {"instance_id": inst_id, "logs": out[-tail:]}}


def stats(inst_id: str) -> Dict[str, Any]:
    with _LOCK:
        info = _INSTANCES.get(inst_id)
    if not info:
        return {"success": False, "error": "实例不存在"}
    data: Dict[str, Any] = {"mode": info["mode"],
                           "uptime": _uptime(info)}
    if info["mode"] == "docker" and info.get("container_name"):
        r = docker_manager.container_stats(info["container_name"])
        data["raw"] = r.get("stdout", "")
    return {"success": True, "data": data}


def _uptime(info: Dict[str, Any]) -> Optional[float]:
    if not info.get("started_at"):
        return None
    try:
        t = datetime.fromisoformat(info["started_at"])
        return round(time.time() - t.timestamp(), 1)
    except Exception:  # noqa: BLE001
        return None


def _snapshot(inst_id: str) -> Dict[str, Any]:
    with _LOCK:
        info = _INSTANCES.get(inst_id)
    if not info:
        return {}
    out = {k: v for k, v in info.items() if not k.startswith("_")}
    out["uptime"] = _uptime(info)
    return out


def list_instances() -> List[Dict[str, Any]]:
    with _LOCK:
        ids = list(_INSTANCES.keys())
    return [_snapshot(i) for i in ids]


def get_instance(inst_id: str) -> Dict[str, Any]:
    return _snapshot(inst_id)


def available_labs() -> List[Dict[str, Any]]:
    return list_labs()
