#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
靶场管理器（Range Manager）

支持一键部署/管理常见漏洞靶场：
- DVWA (Damn Vulnerable Web Application)
- OWASP Juice Shop
- bWAPP
- WebGoat
- Mutillidae
- Vulhub 集合

提供靶场生命周期管理：启动/停止/状态检查/重置/删除。
"""

import subprocess
import time
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class RangeStatus(Enum):
    """靶场状态"""
    NOT_CREATED = "not_created"
    CREATING = "creating"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class VulnerableRange:
    """漏洞靶场定义"""
    range_id: str
    name: str
    description: str
    docker_image: str
    docker_tag: str = "latest"
    container_name: str = ""
    ports: Dict[int, int] = field(default_factory=dict)  # {host_port: container_port}
    environment: Dict[str, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    difficulty: str = "beginner"  # beginner/intermediate/advanced
    status: RangeStatus = RangeStatus.NOT_CREATED
    start_time: float = 0


class RangeManager:
    """
    靶场管理器

    管理漏洞靶场的Docker容器生命周期。
    """

    def __init__(self, work_dir: str = None):
        self.work_dir = work_dir or os.path.join(os.path.dirname(__file__), "..", "ranges")
        self.ranges: Dict[str, VulnerableRange] = {}
        self._init_builtin_ranges()
        self._docker_available = self._check_docker()

    def _check_docker(self) -> bool:
        """检查Docker是否可用"""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def _init_builtin_ranges(self):
        """初始化内置靶场列表"""
        self.ranges = {
            "dvwa": VulnerableRange(
                range_id="dvwa",
                name="DVWA",
                description="Damn Vulnerable Web Application - PHP/MySQL漏洞练习平台",
                docker_image="vulnerables/web-dvwa",
                container_name="ai-sec-dvwa",
                ports={8080: 80},
                environment={"MYSQL_PASS": "password"},
                vulnerabilities=["SQL注入", "XSS", "CSRF", "文件上传", "命令注入", "文件包含", "弱密码"],
                difficulty="beginner",
            ),
            "juice-shop": VulnerableRange(
                range_id="juice-shop",
                name="OWASP Juice Shop",
                description="OWASP官方漏洞应用 - Node.js/Angular现代Web应用",
                docker_image="bkimminich/juice-shop",
                container_name="ai-sec-juice-shop",
                ports={3000: 3000},
                vulnerabilities=["XSS", "SQL注入", "SSRF", "XXE", "路径遍历", "IDOR", "JWT攻击", "支付逻辑漏洞"],
                difficulty="intermediate",
            ),
            "bwapp": VulnerableRange(
                range_id="bwapp",
                name="bWAPP",
                description="buggy Web Application - 100+漏洞的PHP应用",
                docker_image="raesene/bwapp",
                container_name="ai-sec-bwapp",
                ports={8081: 80},
                vulnerabilities=["SQL注入", "XSS", "CSRF", "XXE", "SSRF", "文件上传", "命令注入", "LDAP注入"],
                difficulty="beginner",
            ),
            "webgoat": VulnerableRange(
                range_id="webgoat",
                name="WebGoat",
                description="OWASP WebGoat - Java编写的安全教学应用",
                docker_image="webgoat/webgoat",
                container_name="ai-sec-webgoat",
                ports={8082: 8080},
                vulnerabilities=["SQL注入", "XSS", "访问控制", "认证缺陷", "不安全反序列化", "请求伪造"],
                difficulty="intermediate",
            ),
            "mutillidae": VulnerableRange(
                range_id="mutillidae",
                name="Mutillidae",
                description="OWASP Mutillidae II - 大量漏洞的PHP教学平台",
                docker_image="citizenstig/nowasp",
                container_name="ai-sec-mutillidae",
                ports={8083: 80},
                vulnerabilities=["SQL注入", "XSS", "CSRF", "文件上传", "命令注入", "XML注入", "XPATH注入"],
                difficulty="beginner",
            ),
            "dvws-node": VulnerableRange(
                range_id="dvws-node",
                name="DVWS Node",
                description="Damn Vulnerable Web Services - 不安全的Web服务API",
                docker_image="snoopysecurity/dvws-node",
                container_name="ai-sec-dvws",
                ports={8084: 80},
                vulnerabilities=["GraphQL注入", "NoSQL注入", "SSRF", "XXE", "JWT攻击", "API滥用"],
                difficulty="advanced",
            ),
        }

    def list_ranges(self) -> List[Dict]:
        """列出所有可用靶场"""
        return [
            {
                "id": r.range_id,
                "name": r.name,
                "description": r.description,
                "docker_image": f"{r.docker_image}:{r.docker_tag}",
                "ports": r.ports,
                "vulnerabilities": r.vulnerabilities,
                "difficulty": r.difficulty,
                "status": r.status.value,
                "url": self._get_range_url(r),
            }
            for r in self.ranges.values()
        ]

    def _get_range_url(self, range_obj: VulnerableRange) -> str:
        """获取靶场访问URL"""
        if not range_obj.ports:
            return ""
        host_port = list(range_obj.ports.keys())[0]
        return f"http://127.0.0.1:{host_port}"

    def get_range(self, range_id: str) -> Optional[VulnerableRange]:
        """获取靶场信息"""
        return self.ranges.get(range_id)

    def start_range(self, range_id: str, timeout: int = 120) -> Dict[str, Any]:
        """启动靶场"""
        if range_id not in self.ranges:
            return {"success": False, "error": f"未知靶场: {range_id}"}

        if not self._docker_available:
            return {"success": False, "error": "Docker不可用，请先安装Docker Desktop",
                    "fallback": "可使用在线靶场或手动部署"}

        range_obj = self.ranges[range_id]
        range_obj.status = RangeStatus.CREATING
        range_obj.start_time = time.time()

        try:
            # 先停止已存在的容器
            self._run_docker(["rm", "-f", range_obj.container_name], check=False)

            # 构建docker run命令
            cmd = ["docker", "run", "-d", "--name", range_obj.container_name]
            for host_port, container_port in range_obj.ports.items():
                cmd.extend(["-p", f"{host_port}:{container_port}"])
            for key, value in range_obj.environment.items():
                cmd.extend(["-e", f"{key}={value}"])
            cmd.append(f"{range_obj.docker_image}:{range_obj.docker_tag}")

            result = self._run_docker(cmd[1:], check=True)  # 去掉"docker"前缀

            # 等待容器启动
            time.sleep(5)
            range_obj.status = RangeStatus.RUNNING

            return {
                "success": True,
                "range_id": range_id,
                "name": range_obj.name,
                "url": self._get_range_url(range_obj),
                "container_name": range_obj.container_name,
                "ports": range_obj.ports,
                "message": f"靶场 {range_obj.name} 已启动，访问 {self._get_range_url(range_obj)}",
            }
        except Exception as e:
            range_obj.status = RangeStatus.ERROR
            return {"success": False, "error": str(e)}

    def stop_range(self, range_id: str) -> Dict[str, Any]:
        """停止靶场"""
        if range_id not in self.ranges:
            return {"success": False, "error": f"未知靶场: {range_id}"}

        range_obj = self.ranges[range_id]
        try:
            self._run_docker(["stop", range_obj.container_name], check=False)
            range_obj.status = RangeStatus.STOPPED
            return {"success": True, "message": f"靶场 {range_obj.name} 已停止"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def remove_range(self, range_id: str) -> Dict[str, Any]:
        """删除靶场容器"""
        if range_id not in self.ranges:
            return {"success": False, "error": f"未知靶场: {range_id}"}

        range_obj = self.ranges[range_id]
        try:
            self._run_docker(["rm", "-f", range_obj.container_name], check=False)
            range_obj.status = RangeStatus.NOT_CREATED
            return {"success": True, "message": f"靶场 {range_obj.name} 容器已删除"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_range_status(self, range_id: str) -> Dict[str, Any]:
        """获取靶场运行状态"""
        if range_id not in self.ranges:
            return {"success": False, "error": f"未知靶场: {range_id}"}

        range_obj = self.ranges[range_id]
        try:
            result = self._run_docker(
                ["inspect", "-f", "{{.State.Running}}", range_obj.container_name],
                check=False, capture_output=True
            )
            is_running = "true" in result.stdout.lower() if result.stdout else False
            range_obj.status = RangeStatus.RUNNING if is_running else RangeStatus.STOPPED

            # 检查端口可访问性
            url = self._get_range_url(range_obj)
            port_open = self._check_port(url) if is_running else False

            return {
                "success": True,
                "range_id": range_id,
                "name": range_obj.name,
                "status": range_obj.status.value,
                "container_running": is_running,
                "port_accessible": port_open,
                "url": url,
                "uptime": time.time() - range_obj.start_time if range_obj.start_time else 0,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_docker(self, args: List[str], check: bool = True,
                    capture_output: bool = True) -> subprocess.CompletedProcess:
        """执行Docker命令"""
        cmd = ["docker"] + args
        return subprocess.run(
            cmd, capture_output=capture_output, text=True, timeout=60, check=check
        )

    def _check_port(self, url: str) -> bool:
        """检查端口是否可访问"""
        try:
            import urllib.request
            req = urllib.request.Request(url, method="HEAD")
            urllib.request.urlopen(req, timeout=5)
            return True
        except Exception:
            try:
                import urllib.request
                urllib.request.urlopen(url, timeout=5)
                return True
            except Exception:
                return False

    def get_docker_status(self) -> Dict[str, Any]:
        """获取Docker状态"""
        return {
            "docker_available": self._docker_available,
            "version": self._get_docker_version() if self._docker_available else None,
            "ranges_total": len(self.ranges),
            "ranges_running": sum(1 for r in self.ranges.values() if r.status == RangeStatus.RUNNING),
        }

    def _get_docker_version(self) -> str:
        """获取Docker版本"""
        try:
            result = self._run_docker(["--version"], check=False)
            return result.stdout.strip()
        except Exception:
            return "unknown"


# 单例模式
_manager_instance: Optional[RangeManager] = None

def get_range_manager() -> RangeManager:
    """获取全局靶场管理器实例"""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = RangeManager()
    return _manager_instance
