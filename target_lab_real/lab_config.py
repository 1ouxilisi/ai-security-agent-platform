# -*- coding: utf-8 -*-
"""
target_lab_real/lab_config.py — 靶场部署配置

端口映射 / 环境变量 / 资源限制 / 数据卷 / 网络 / 重启策略。
纯数据结构 + 校验。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

RESTART_POLICIES = ["no", "always", "unless-stopped", "on-failure"]
NETWORK_MODES = ["bridge", "host", "none"]


class LabDeployConfig:
    """一次部署的配置。"""

    def __init__(self,
                 host_ports: Optional[Dict[int, int]] = None,
                 env: Optional[Dict[str, str]] = None,
                 volumes: Optional[Dict[str, str]] = None,
                 cpu_limit: Optional[str] = None,
                 memory_limit: Optional[str] = None,
                 network: str = "bridge",
                 restart: str = "no",
                 name_prefix: str = "arel") -> None:
        self.host_ports = host_ports or {}
        self.env = env or {}
        self.volumes = volumes or {}
        self.cpu_limit = cpu_limit
        self.memory_limit = memory_limit
        self.network = network if network in NETWORK_MODES else "bridge"
        self.restart = restart if restart in RESTART_POLICIES else "no"
        self.name_prefix = name_prefix

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_ports": self.host_ports,
            "env": self.env,
            "volumes": self.volumes,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "network": self.network,
            "restart": self.restart,
        }

    def extra_docker_args(self) -> List[str]:
        args: List[str] = []
        if self.network and self.network != "bridge":
            args += ["--network", self.network]
        if self.cpu_limit:
            args += ["--cpus", str(self.cpu_limit)]
        if self.memory_limit:
            args += ["--memory", str(self.memory_limit)]
        return args

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LabDeployConfig":
        return cls(
            host_ports=d.get("host_ports") or {},
            env=d.get("env") or {},
            volumes=d.get("volumes") or {},
            cpu_limit=d.get("cpu_limit"),
            memory_limit=d.get("memory_limit"),
            network=d.get("network", "bridge"),
            restart=d.get("restart", "no"),
        )


# 预设资源档
PRESETS: Dict[str, Dict[str, str]] = {
    "light": {"cpu_limit": "0.5", "memory_limit": "512m"},
    "medium": {"cpu_limit": "1.5", "memory_limit": "2g"},
    "heavy": {"cpu_limit": "4", "memory_limit": "8g"},
}
