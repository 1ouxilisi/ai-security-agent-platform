#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
docker_sandbox模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import os
import json
import time
import shutil
import tempfile
import subprocess
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from utils.logger import log


class SandboxStatus(Enum):
    """沙箱状态"""
    CREATED = "created"
    RUNNING = "running"
    STOPPED = "stopped"
    REMOVED = "removed"
    ERROR = "error"


@dataclass
class SandboxResult:
    """沙箱执行结果"""
    success: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    execution_time: float = 0.0
    container_id: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "execution_time": self.execution_time,
            "container_id": self.container_id,
            "error": self.error
        }


@dataclass
class SandboxConfig:
    """沙箱配置"""
    image: str = "kalilinux/kali-rolling:latest"
    cpu_limit: float = 1.0  # CPU核心数限制
    memory_limit: str = "512m"  # 内存限制
    network_enabled: bool = True  # 是否启用网络
    pids_limit: int = 256  # 进程数限制
    tmpfs_size: str = "64m"  # tmpfs大小
    read_only_root: bool = False  # 只读根文件系统
    cap_drop: List[str] = field(default_factory=lambda: ["ALL"])
    cap_add: List[str] = field(default_factory=lambda: ["NET_RAW", "NET_ADMIN"])
    security_options: List[str] = field(default_factory=lambda: ["no-new-privileges"])
    volumes: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    working_dir: str = "/workspace"
    timeout: int = 300  # 超时时间（秒）

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "image": self.image,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "network_enabled": self.network_enabled,
            "pids_limit": self.pids_limit,
            "read_only_root": self.read_only_root,
            "cap_drop": self.cap_drop,
            "cap_add": self.cap_add,
            "security_options": self.security_options,
            "timeout": self.timeout
        }


class DockerSandbox:
    """Docker沙箱管理器"""

    def __init__(self, data_dir: str = "data/sandbox"):
        """初始化DockerSandbox实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.containers: Dict[str, Dict[str, Any]] = {}
        self.workspace_dir = os.path.join(data_dir, "workspaces")
        os.makedirs(self.workspace_dir, exist_ok=True)
        self._docker_available = None

    def check_docker_available(self) -> bool:
        """检查Docker是否可用"""
        if self._docker_available is not None:
            return self._docker_available
        try:
            result = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=10
            )
            self._docker_available = result.returncode == 0
            if self._docker_available:
                log.info(f"Docker可用，版本: {result.stdout.strip()}")
            else:
                log.warning(f"Docker不可用: {result.stderr}")
            return self._docker_available
        except Exception as e:
            log.warning(f"Docker检查失败: {e}")
            self._docker_available = False
            return False

    def create_container(self, config: SandboxConfig = None,
                         container_name: str = None) -> Tuple[str, SandboxResult]:
        """创建沙箱容器"""
        config = config or SandboxConfig()

        if not self.check_docker_available():
            return "", SandboxResult(success=False, error="Docker不可用")

        if not container_name:
            container_name = f"ai-hacking-sandbox-{int(time.time())}-{os.getpid()}"

        try:
            # 构建docker run命令
            cmd = ["docker", "run", "-d", "--name", container_name]

            # 资源限制
            cmd.extend(["--cpus", str(config.cpu_limit)])
            cmd.extend(["--memory", config.memory_limit])
            cmd.extend(["--pids-limit", str(config.pids_limit)])

            # 网络
            if not config.network_enabled:
                cmd.append("--network=none")

            # 安全选项
            for opt in config.security_options:
                cmd.extend(["--security-opt", opt])

            # Capabilities
            for cap in config.cap_drop:
                cmd.extend(["--cap-drop", cap])
            for cap in config.cap_add:
                cmd.extend(["--cap-add", cap])

            # 只读根文件系统
            if config.read_only_root:
                cmd.append("--read-only")
                cmd.extend(["--tmpfs", f"/tmp:size={config.tmpfs_size}"])

            # 工作目录
            cmd.extend(["-w", config.working_dir])

            # 环境变量
            for key, value in config.environment.items():
                cmd.extend(["-e", f"{key}={value}"])

            # 卷挂载
            for volume in config.volumes:
                cmd.extend(["-v", volume])

            # 镜像和保持运行
            cmd.extend([config.image, "sleep", "infinity"])

            log.info(f"创建沙箱容器: {container_name}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                error_msg = f"容器创建失败: {result.stderr}"
                log.error(error_msg)
                return "", SandboxResult(success=False, error=error_msg)

            container_id = result.stdout.strip()
            self.containers[container_id] = {
                "name": container_name,
                "config": config.to_dict(),
                "status": SandboxStatus.RUNNING.value,
                "created_at": datetime.now().isoformat()
            }

            log.info(f"沙箱容器创建成功: {container_id[:12]}")
            return container_id, SandboxResult(success=True, container_id=container_id)

        except subprocess.TimeoutExpired:
            return "", SandboxResult(success=False, error="容器创建超时")
        except Exception as e:
            return "", SandboxResult(success=False, error=str(e))

    def execute(self, container_id: str, command: str,
                timeout: int = None, workdir: str = None) -> SandboxResult:
        """在沙箱中执行命令"""
        if container_id not in self.containers and not self._container_exists(container_id):
            return SandboxResult(success=False, error="容器不存在")

        timeout = timeout or 300
        start_time = time.time()

        try:
            # 构建docker exec命令
            cmd = ["docker", "exec"]
            if workdir:
                cmd.extend(["-w", workdir])
            cmd.extend([container_id, "bash", "-c", command])

            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout
            )

            execution_time = round(time.time() - start_time, 2)

            return SandboxResult(
                success=result.returncode == 0,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                execution_time=execution_time,
                container_id=container_id
            )

        except subprocess.TimeoutExpired:
            return SandboxResult(
                success=False, error="命令执行超时",
                execution_time=round(time.time() - start_time, 2),
                container_id=container_id
            )
        except Exception as e:
            return SandboxResult(success=False, error=str(e), container_id=container_id)

    def execute_tool(self, container_id: str, tool: str, args: str = "",
                     timeout: int = None) -> SandboxResult:
        """在沙箱中执行安全工具"""
        # 检查工具是否安装
        check_result = self.execute(container_id, f"which {tool} || echo 'NOT_FOUND'")
        if "NOT_FOUND" in check_result.stdout:
            # 尝试安装工具
            install_result = self.execute(
                container_id,
                f"apt-get update -qq && apt-get install -y -qq {tool} 2>&1 | tail -5",
                timeout=120
            )
            if not install_result.success:
                return SandboxResult(success=False, error=f"工具{tool}安装失败: {install_result.stderr}")

        # 执行工具
        command = f"{tool} {args}".strip()
        return self.execute(container_id, command, timeout=timeout)

    def copy_to_container(self, container_id: str, local_path: str,
                          container_path: str) -> SandboxResult:
        """复制文件到容器"""
        if not os.path.exists(local_path):
            return SandboxResult(success=False, error=f"本地文件不存在: {local_path}")

        try:
            cmd = ["docker", "cp", local_path, f"{container_id}:{container_path}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return SandboxResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                container_id=container_id
            )
        except Exception as e:
            return SandboxResult(success=False, error=str(e))

    def copy_from_container(self, container_id: str, container_path: str,
                            local_path: str) -> SandboxResult:
        """从容器复制文件"""
        try:
            os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
            cmd = ["docker", "cp", f"{container_id}:{container_path}", local_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return SandboxResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                container_id=container_id
            )
        except Exception as e:
            return SandboxResult(success=False, error=str(e))

    def stop_container(self, container_id: str) -> SandboxResult:
        """停止容器"""
        try:
            cmd = ["docker", "stop", container_id]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if container_id in self.containers:
                self.containers[container_id]["status"] = SandboxStatus.STOPPED.value
            return SandboxResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                container_id=container_id
            )
        except Exception as e:
            return SandboxResult(success=False, error=str(e))

    def remove_container(self, container_id: str, force: bool = True) -> SandboxResult:
        """删除容器"""
        try:
            cmd = ["docker", "rm"]
            if force:
                cmd.append("-f")
            cmd.append(container_id)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if container_id in self.containers:
                del self.containers[container_id]
            return SandboxResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                container_id=container_id
            )
        except Exception as e:
            return SandboxResult(success=False, error=str(e))

    def _container_exists(self, container_id: str) -> bool:
        """检查容器是否存在"""
        try:
            cmd = ["docker", "inspect", container_id]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False

    def list_containers(self) -> List[Dict[str, Any]]:
        """列出所有沙箱容器"""
        return list(self.containers.values())

    def cleanup(self) -> Dict[str, Any]:
        """清理所有沙箱容器"""
        removed = []
        failed = []
        for container_id in list(self.containers.keys()):
            result = self.remove_container(container_id, force=True)
            if result.success:
                removed.append(container_id[:12])
            else:
                failed.append(container_id[:12])
        return {"removed": removed, "failed": failed}

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "docker_available": self.check_docker_available(),
            "active_containers": len(self.containers),
            "containers": self.list_containers(),
            "supported_images": [
                "kalilinux/kali-rolling:latest",
                "ubuntu:22.04",
                "alpine:latest",
                "python:3.11-slim"
            ],
            "security_features": [
                "CPU限制", "内存限制", "进程数限制", "网络隔离",
                "Capability控制", "只读根文件系统", "no-new-privileges",
                "tmpfs隔离"
            ]
        }


# 全局实例
docker_sandbox = DockerSandbox()
