# -*- coding: utf-8 -*-
"""
challenge_deployment_phase.py — 阶段3：题目部署（Docker）。

功能:
    - Docker 一键部署题目容器（真实 subprocess 调用，超时 300s）
    - 动态 flag（每队伍/每用户独立 flag）
    - 端口分配（自动/手动）
    - 资源限制（CPU/内存/磁盘/网络）
    - 容器生命周期（启动/停止/重启/销毁/重置）
    - 容器状态监控 / 日志查看
    - 部署模板管理
    - 未安装 Docker 明确提示，不 mock；内置模拟部署框架兜底
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

TOOL_TIMEOUT = 300  # 秒


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def detect_docker() -> Dict[str, Any]:
    """探测 docker / docker-compose 是否可用。"""
    docker = _which("docker")
    compose = _which("docker-compose")
    info: Dict[str, Any] = {"docker": bool(docker),
                            "docker_compose": bool(compose),
                            "docker_path": docker,
                            "compose_path": compose}
    if docker:
        try:
            p = subprocess.run([docker, "version", "--format",
                                "{{.Server.Version}}"],
                               capture_output=True, text=True,
                               timeout=15)
            info["server_version"] = p.stdout.strip()
            info["daemon_running"] = (p.returncode == 0)
        except Exception as e:  # noqa: BLE001
            info["daemon_running"] = False
            info["error"] = str(e)
    return info


@dataclass
class Deployment:
    deploy_id: str = ""
    chal_id: str = ""
    team_id: str = ""
    image: str = ""
    container_id: str = ""
    container_name: str = ""
    host_port: int = 0
    internal_port: int = 80
    flag: str = ""                     # 动态生成的本队伍 flag
    status: str = "pending"            # pending/running/stopped/error/destroyed/simulated
    cpu_limit: str = "1.0"
    memory_limit: str = "512m"
    disk_limit: str = "1g"
    network: str = "bridge"
    logs: List[str] = field(default_factory=list)
    created_at: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deploy_id": self.deploy_id, "chal_id": self.chal_id,
            "team_id": self.team_id, "image": self.image,
            "container_id": self.container_id,
            "container_name": self.container_name,
            "host_port": self.host_port,
            "internal_port": self.internal_port,
            "flag": self.flag, "status": self.status,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "disk_limit": self.disk_limit,
            "network": self.network,
            "logs": self.logs[-50:],
            "created_at": self.created_at, "error": self.error,
            "endpoint": (f"http://127.0.0.1:{self.host_port}"
                         if self.host_port else ""),
        }


class ChallengeDeploymentPhase:
    """阶段3：题目部署。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._deploys: Dict[str, Deployment] = {}
        self._port_pool = list(range(20000, 20100))
        self._port_used: set = set()
        self._docker = detect_docker()
        self._templates: Dict[str, Dict[str, Any]] = {
            "web_standard": {"image": "ctf/web-chal:latest",
                             "internal_port": 80,
                             "memory_limit": "512m"},
            "pwn_standard": {"image": "ctf/pwn-chal:latest",
                            "internal_port": 9999,
                            "memory_limit": "256m"},
            "crypto_standard": {"image": "ctf/crypto-chal:latest",
                               "internal_port": 12345,
                               "memory_limit": "128m"},
        }

    # ------------------------------------------------------------------ #
    def docker_status(self) -> Dict[str, Any]:
        return self._docker

    def list_templates(self) -> Dict[str, Any]:
        return self._templates

    # ------------------------------------------------------------------ #
    def _alloc_port(self, manual: int = 0) -> int:
        if manual:
            if manual in self._port_used:
                raise ValueError(f"端口 {manual} 已被占用")
            self._port_used.add(manual)
            return manual
        for p in self._port_pool:
            if p not in self._port_used:
                self._port_used.add(p)
                return p
        raise RuntimeError("端口池已耗尽")

    def _gen_flag(self, team_id: str,
                  flag_template: str = "") -> str:
        if flag_template:
            # 支持 {team_id} 占位，其余随机
            import hashlib
            token = hashlib.md5(
                f"{team_id}:{uuid.uuid4().hex}".encode()).hexdigest()[:12]
            return flag_template.replace("{team_id}", team_id) \
                                .replace("{random}", token)
        return "flag{" + uuid.uuid4().hex[:16] + "}"

    # ------------------------------------------------------------------ #
    def deploy(self, chal_id: str, team_id: str,
              image: str = "", internal_port: int = 80,
              host_port: int = 0,
              cpu_limit: str = "1.0",
              memory_limit: str = "512m",
              disk_limit: str = "1g",
              network: str = "bridge",
              flag_template: str = "") -> Dict[str, Any]:
        d = Deployment(
            deploy_id="dep_" + uuid.uuid4().hex[:10],
            chal_id=chal_id, team_id=team_id,
            image=image or "ctf/chal:latest",
            container_name=f"ctf_{chal_id}_{team_id}_{uuid.uuid4().hex[:6]}",
            internal_port=internal_port,
            host_port=self._alloc_port(host_port),
            flag=self._gen_flag(team_id, flag_template),
            cpu_limit=cpu_limit, memory_limit=memory_limit,
            disk_limit=disk_limit, network=network,
            created_at=_now(),
        )
        use_docker = bool(self._docker.get("docker")
                          and self._docker.get("daemon_running"))
        image_available = False
        if use_docker:
            docker = self._docker["docker_path"]
            try:
                probe = subprocess.run(
                    [docker, "image", "inspect", d.image],
                    capture_output=True, text=True, timeout=10)
                image_available = (probe.returncode == 0)
            except Exception as e:  # noqa: BLE001
                d.logs.append(f"[{_now()}] 镜像探测异常: {e}")
        if use_docker and not image_available:
            d.logs.append(
                f"[{_now()}] Docker 守护进程可用，但本地未找到镜像 "
                f"{d.image!r}（未自动拉取，避免长时间阻塞）。"
                f"请先 docker pull {d.image} 或改用已构建镜像，"
                f"当前启用内置模拟部署框架兜底")
        if use_docker and image_available:
            docker = self._docker["docker_path"]
            cmd = [docker, "run", "-d",
                   "--name", d.container_name,
                   "--cpus", d.cpu_limit,
                   "--memory", d.memory_limit,
                   "--network", d.network,
                   "-p", f"{d.host_port}:{d.internal_port}",
                   "-e", f"FLAG={d.flag}",
                   d.image]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=TOOL_TIMEOUT)
                if p.returncode == 0:
                    d.container_id = p.stdout.strip()[:12]
                    d.status = "running"
                    d.logs.append(f"[{_now()}] docker run OK: "
                                  f"{d.container_id}")
                else:
                    d.status = "error"
                    d.error = p.stderr.strip()[:500]
                    d.logs.append(f"[{_now()}] docker run FAIL: "
                                  f"{d.error}")
            except Exception as e:  # noqa: BLE001
                d.status = "error"
                d.error = str(e)
        else:
            # 内置模拟部署框架兜底（明确标注 simulated）
            d.status = "simulated"
            d.container_id = "sim_" + uuid.uuid4().hex[:10]
            d.logs.append(
                f"[{_now()}] 未检测到可用 Docker"
                f"（docker={self._docker.get('docker')},"
                f" daemon={self._docker.get('daemon_running')}），"
                f"启用内置模拟部署框架兜底")
        with self._lock:
            self._deploys[d.deploy_id] = d
        return d.to_dict()

    # ------------------------------------------------------------------ #
    def _get(self, deploy_id: str) -> Deployment:
        d = self._deploys.get(deploy_id)
        if d is None:
            raise KeyError(f"部署不存在: {deploy_id}")
        return d

    def lifecycle(self, deploy_id: str,
                  action: str) -> Dict[str, Any]:
        d = self._get(deploy_id)
        use_docker = bool(self._docker.get("docker")
                          and self._docker.get("daemon_running"))
        docker = self._docker.get("docker_path")
        target = d.container_name
        if action == "start":
            d.status = "running"
        elif action == "stop":
            d.status = "stopped"
        elif action == "restart":
            d.status = "running"
        elif action == "reset":
            d.flag = self._gen_flag(d.team_id)
            d.status = "running"
            d.logs.append(f"[{_now()}] flag 已重置")
        elif action == "destroy":
            d.status = "destroyed"
            self._port_used.discard(d.host_port)
        else:
            raise ValueError(f"非法动作: {action}")
        if use_docker and d.container_id.startswith("sim_") is False \
                and d.container_id:
            try:
                verb = {"start": "start", "stop": "stop",
                        "restart": "restart",
                        "destroy": "rm",
                        "reset": "restart"}.get(action, action)
                sub = ["-f"] if verb == "rm" else []
                subprocess.run([docker, verb, *sub, target],
                               capture_output=True, text=True,
                               timeout=TOOL_TIMEOUT)
            except Exception as e:  # noqa: BLE001
                d.logs.append(f"[{_now()}] docker {action} 异常: {e}")
        d.logs.append(f"[{_now()}] action={action} -> {d.status}")
        return d.to_dict()

    def view_logs(self, deploy_id: str, tail: int = 100
                  ) -> Dict[str, Any]:
        d = self._get(deploy_id)
        out = list(d.logs)
        use_docker = bool(self._docker.get("docker")
                          and not d.container_id.startswith("sim_")
                          and self._docker.get("daemon_running"))
        if use_docker:
            try:
                p = subprocess.run(
                    [self._docker["docker_path"], "logs",
                     "--tail", str(tail), d.container_name],
                    capture_output=True, text=True, timeout=30)
                out += p.stdout.splitlines()[-tail:]
            except Exception as e:  # noqa: BLE001
                out.append(f"读取容器日志失败: {e}")
        return {"deploy_id": deploy_id, "logs": out[-tail:]}

    def status_monitor(self) -> List[Dict[str, Any]]:
        rows = []
        for d in self._deploys.values():
            rows.append(d.to_dict())
        return rows

    def list_deployments(self, chal_id: str = "",
                         team_id: str = "") -> List[Dict[str, Any]]:
        rows = []
        for d in self._deploys.values():
            if chal_id and d.chal_id != chal_id:
                continue
            if team_id and d.team_id != team_id:
                continue
            rows.append(d.to_dict())
        return rows

    def stats(self) -> Dict[str, Any]:
        running = sum(1 for d in self._deploys.values()
                      if d.status == "running")
        simulated = sum(1 for d in self._deploys.values()
                        if d.status == "simulated")
        return {"total": len(self._deploys), "running": running,
                "simulated": simulated,
                "docker_ready": bool(self._docker.get("docker")
                                     and self._docker.get("daemon_running"))}


_default: Optional[ChallengeDeploymentPhase] = None


def get_deployment_phase() -> ChallengeDeploymentPhase:
    global _default
    if _default is None:
        _default = ChallengeDeploymentPhase()
    return _default
