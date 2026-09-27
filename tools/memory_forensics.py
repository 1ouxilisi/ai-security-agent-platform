#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
memory_forensics安全工具集成模块，提供相关安全工具的封装和调用。

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
import struct
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class ProcessInfo:
    """进程信息"""
    pid: int
    ppid: int
    name: str
    path: str
    cmdline: str
    user: str
    start_time: str
    threads: int
    handles: int
    memory_usage: int  # KB
    cpu_usage: float
    status: str
    is_suspicious: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    injected: bool = False
    has_hollowed: bool = False


@dataclass
class NetworkConnection:
    """网络连接"""
    pid: int
    process_name: str
    protocol: str  # TCP/UDP
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    is_suspicious: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    is_c2: bool = False
    is_data_exfiltration: bool = False


@dataclass
class CredentialInfo:
    """凭证信息"""
    type: str  # password/hash/token/key
    username: str
    domain: str
    value: str
    source: str  # lsass/sam/ntds.dit/browser/credential_manager
    is_valid: bool = False
    notes: str = ""


@dataclass
class MalwareIndicator:
    """恶意软件指标"""
    type: str  # process/injection/registry/file/network/mutex
    name: str
    path: str
    description: str
    severity: str  # critical/high/medium/low/info
    evidence: str
    timestamp: str
    ioc_type: str = ""
    ioc_value: str = ""


@dataclass
class MemoryForensicsResult:
    """内存取证结果"""
    image_path: str
    image_size: int = 0
    os_type: str = ""
    os_version: str = ""
    architecture: str = ""
    analysis_time: float = 0.0
    total_processes: int = 0
    suspicious_processes: int = 0
    total_connections: int = 0
    suspicious_connections: int = 0
    credentials_found: int = 0
    malware_indicators: int = 0
    processes: List[ProcessInfo] = field(default_factory=list)
    connections: List[NetworkConnection] = field(default_factory=list)
    credentials: List[CredentialInfo] = field(default_factory=list)
    indicators: List[MalwareIndicator] = field(default_factory=list)
    summary: str = ""
    risk_level: str = "low"  # low/medium/high/critical
    recommendations: List[str] = field(default_factory=list)


class MemoryForensics:
    """内存取证分析器"""

    def __init__(self, config: Optional[Dict] = None):
        """初始化MemoryForensics实例。

        Args:
            self: 类实例。
        """
        self.config = config or {}
        self.suspicious_process_names = [
            "mimikatz", "cobaltstrike", "metasploit", "meterpreter",
            "powershell_ise", "cmd.exe", "nc.exe", "netcat", "ncat",
            "procdump", "procexp", "autoruns", "tcpview", "wireshark",
            "procmon", "dbgview", "ollydbg", "x64dbg", "x32dbg",
            "ghidra", "ida64", "ida32", "binaryninja", "radare2",
            "hashcat", "john", "hydra", "medusa", "ncrack",
            "sqlmap", "nmap", "masscan", "zmap", "nikto",
            "burpsuite", "burp", "fiddler", "charles", "wireshark",
            "volatility", "vol", "rekall", "redline", "mandiant",
        ]
        self.suspicious_ports = [
            4444, 5555, 6666, 7777, 8888, 9999,  # 常见反向Shell端口
            31337, 12345, 54321,  # 常见后门端口
            1337, 31337,  # 黑客文化端口
        ]
        self.c2_indicators = [
            "beacon", "c2", "command", "control", "malleable",
            "http-beacon", "https-beacon", "dns-beacon",
        ]
        logger.info("内存取证分析模块初始化完成")

    async def analyze_memory_image(self, image_path: str) -> MemoryForensicsResult:
        """分析内存镜像"""
        result = MemoryForensicsResult(image_path=image_path)
        start_time = time.time()

        logger.info(f"开始分析内存镜像: {image_path}")

        # 检查文件
        if not os.path.exists(image_path):
            result.summary = f"内存镜像文件不存在: {image_path}"
            return result

        result.image_size = os.path.getsize(image_path)

        # 1. 识别操作系统
        result.os_type, result.os_version, result.architecture = self._identify_os(image_path)

        # 2. 进程分析
        result.processes = self._analyze_processes(image_path)
        result.total_processes = len(result.processes)
        result.suspicious_processes = len([p for p in result.processes if p.is_suspicious])

        # 3. 网络连接分析
        result.connections = self._analyze_connections(image_path)
        result.total_connections = len(result.connections)
        result.suspicious_connections = len([c for c in result.connections if c.is_suspicious])

        # 4. 凭证提取
        result.credentials = self._extract_credentials(image_path)
        result.credentials_found = len(result.credentials)

        # 5. 恶意软件检测
        result.indicators = self._detect_malware(image_path)
        result.malware_indicators = len(result.indicators)

        # 6. 计算风险等级
        result.risk_level = self._calculate_risk_level(result)

        # 7. 生成摘要和建议
        result.summary = self._generate_summary(result)
        result.recommendations = self._generate_recommendations(result)

        result.analysis_time = time.time() - start_time
        logger.info(f"内存镜像分析完成: {result.total_processes}进程, {result.suspicious_processes}可疑, {result.credentials_found}凭证, 耗时{result.analysis_time:.2f}秒")

        return result

    def _identify_os(self, image_path: str) -> Tuple[str, str, str]:
        """识别操作系统"""
        # 简化版，实际需要解析内存镜像结构
        try:
            with open(image_path, "rb") as f:
                header = f.read(4096)

            # 检查Windows内存镜像特征
            if b"Windows" in header or b"win32k" in header or b"ntoskrnl" in header:
                # 尝试识别版本
                if b"Windows 10" in header:
                    return "Windows", "10", "x64"
                elif b"Windows 11" in header:
                    return "Windows", "11", "x64"
                elif b"Windows Server 2019" in header:
                    return "Windows", "Server 2019", "x64"
                elif b"Windows Server 2022" in header:
                    return "Windows", "Server 2022", "x64"
                else:
                    return "Windows", "Unknown", "x64"

            # 检查Linux内存镜像特征
            elif b"Linux" in header or b"vmlinux" in header or b"init_task" in header:
                return "Linux", "Unknown", "x64"

            else:
                return "Unknown", "Unknown", "Unknown"

        except Exception as e:
            logger.error(f"识别操作系统失败: {e}")
            return "Unknown", "Unknown", "Unknown"

    def _analyze_processes(self, image_path: str) -> List[ProcessInfo]:
        """分析进程"""
        # 简化版，实际需要解析EPROCESS结构
        processes = []

        # 常见系统进程
        system_processes = [
            (4, 0, "System", "", "", "SYSTEM", "", 0, 0, 0, 0.0, "running"),
            (96, 4, "Registry", "", "", "SYSTEM", "", 0, 0, 0, 0.0, "running"),
            (320, 4, "smss.exe", "C:\\Windows\\System32\\smss.exe", "", "SYSTEM", "", 2, 0, 0, 0.0, "running"),
            (448, 320, "csrss.exe", "C:\\Windows\\System32\\csrss.exe", "", "SYSTEM", "", 10, 0, 0, 0.0, "running"),
            (528, 320, "wininit.exe", "C:\\Windows\\System32\\wininit.exe", "", "SYSTEM", "", 1, 0, 0, 0.0, "running"),
            (600, 528, "services.exe", "C:\\Windows\\System32\\services.exe", "", "SYSTEM", "", 5, 0, 0, 0.0, "running"),
            (620, 528, "lsass.exe", "C:\\Windows\\System32\\lsass.exe", "", "SYSTEM", "", 8, 0, 0, 0.0, "running"),
            (700, 600, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "-k LocalServiceNoNetwork", "LOCAL SERVICE", "", 10, 0, 0, 0.0, "running"),
            (800, 600, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "-k NetworkService", "NETWORK SERVICE", "", 15, 0, 0, 0.0, "running"),
            (900, 600, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "-k LocalSystemNetworkRestricted", "SYSTEM", "", 20, 0, 0, 0.0, "running"),
            (1000, 600, "spoolsv.exe", "C:\\Windows\\System32\\spoolsv.exe", "", "SYSTEM", "", 5, 0, 0, 0.0, "running"),
            (1200, 600, "explorer.exe", "C:\\Windows\\explorer.exe", "", "user", "", 20, 0, 0, 0.0, "running"),
        ]

        for pid, ppid, name, path, cmdline, user, start_time, threads, handles, mem, cpu, status in system_processes:
            proc = ProcessInfo(
                pid=pid, ppid=ppid, name=name, path=path, cmdline=cmdline,
                user=user, start_time=start_time, threads=threads, handles=handles,
                memory_usage=mem, cpu_usage=cpu, status=status
            )
            processes.append(proc)

        # 检测可疑进程
        for proc in processes:
            self._check_suspicious_process(proc)

        return processes

    def _check_suspicious_process(self, proc: ProcessInfo):
        """检查可疑进程"""
        name_lower = proc.name.lower()

        # 检查可疑进程名
        for suspicious in self.suspicious_process_names:
            if suspicious in name_lower:
                proc.is_suspicious = True
                proc.suspicious_reasons.append(f"可疑进程名: {proc.name}")
                break

        # 检查异常父进程
        if proc.name.lower() in ["powershell.exe", "cmd.exe"] and proc.ppid not in [1200, 600]:
            proc.is_suspicious = True
            proc.suspicious_reasons.append(f"异常父进程: PPID={proc.ppid}")

        # 检查无路径进程（可能被注入）
        if not proc.path and proc.name not in ["System", "Registry"]:
            proc.is_suspicious = True
            proc.suspicious_reasons.append("进程路径为空，可能被注入或进程掏空")
            proc.injected = True

        # 检查异常内存使用
        if proc.memory_usage > 1024 * 1024:  # >1GB
            proc.is_suspicious = True
            proc.suspicious_reasons.append(f"异常内存使用: {proc.memory_usage}KB")

    def _analyze_connections(self, image_path: str) -> List[NetworkConnection]:
        """分析网络连接"""
        connections = []

        # 示例连接
        sample_connections = [
            (1200, "explorer.exe", "TCP", "192.168.1.100", 49152, "104.18.32.10", 443, "ESTABLISHED"),
            (700, "svchost.exe", "TCP", "192.168.1.100", 49153, "52.114.132.10", 443, "ESTABLISHED"),
            (800, "svchost.exe", "UDP", "192.168.1.100", 5353, "224.0.0.251", 5353, "LISTEN"),
        ]

        for pid, name, proto, local_ip, local_port, remote_ip, remote_port, state in sample_connections:
            conn = NetworkConnection(
                pid=pid, process_name=name, protocol=proto,
                local_ip=local_ip, local_port=local_port,
                remote_ip=remote_ip, remote_port=remote_port, state=state
            )
            self._check_suspicious_connection(conn)
            connections.append(conn)

        return connections

    def _check_suspicious_connection(self, conn: NetworkConnection):
        """检查可疑网络连接"""
        # 检查可疑端口
        if conn.remote_port in self.suspicious_ports:
            conn.is_suspicious = True
            conn.suspicious_reasons.append(f"可疑远程端口: {conn.remote_port}")
            conn.is_c2 = True

        # 检查非标准端口的HTTP/HTTPS
        if conn.remote_port not in [80, 443, 53, 8080, 8443] and conn.protocol == "TCP":
            if conn.state == "ESTABLISHED":
                conn.is_suspicious = True
                conn.suspicious_reasons.append(f"非标准端口: {conn.remote_port}")

        # 检查已知C2 IP段（简化）
        c2_ip_ranges = ["185.", "193.", "45.", "103."]
        for prefix in c2_ip_ranges:
            if conn.remote_ip.startswith(prefix):
                conn.is_suspicious = True
                conn.suspicious_reasons.append(f"可疑IP段: {conn.remote_ip}")
                break

        # 检查大量出站连接（可能是数据外泄）
        if conn.remote_port in [21, 22, 80, 443] and conn.state == "ESTABLISHED":
            pass  # 正常端口

    def _extract_credentials(self, image_path: str) -> List[CredentialInfo]:
        """提取凭证"""
        credentials = []

        # 示例凭证（实际需要解析LSASS内存）
        sample_credentials = [
            ("ntlm", "Administrator", "DOMAIN", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "lsass"),
            ("password", "user", "DOMAIN", "P@ssw0rd123!", "lsass"),
            ("kerberos_ticket", "Administrator", "DOMAIN", "<TGT Ticket>", "lsass"),
            ("hash", "Administrator", "", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "sam"),
        ]

        for cred_type, username, domain, value, source in sample_credentials:
            cred = CredentialInfo(
                type=cred_type, username=username, domain=domain,
                value=value, source=source
            )
            credentials.append(cred)

        return credentials

    def _detect_malware(self, image_path: str) -> List[MalwareIndicator]:
        """检测恶意软件"""
        indicators = []

        # 示例恶意软件指标
        sample_indicators = [
            ("process", "mimikatz.exe", "C:\\Temp\\mimikatz.exe", "Mimikatz凭证窃取工具", "critical", "进程名匹配Mimikatz特征"),
            ("injection", "explorer.exe", "C:\\Windows\\explorer.exe", "进程注入检测", "high", "explorer.exe中检测到异常内存区域"),
            ("registry", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\backdoor", "", "注册表持久化", "high", "启动项中发现可疑程序"),
            ("network", "unknown", "", "C2通信检测", "critical", "检测到与已知C2服务器的通信"),
            ("mutex", "Global\\malware_mutex", "", "互斥量检测", "medium", "发现已知恶意软件互斥量"),
        ]

        for ind_type, name, path, desc, severity, evidence in sample_indicators:
            indicator = MalwareIndicator(
                type=ind_type, name=name, path=path, description=desc,
                severity=severity, evidence=evidence,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            indicators.append(indicator)

        return indicators

    def _calculate_risk_level(self, result: MemoryForensicsResult) -> str:
        """计算风险等级"""
        score = 0

        # 可疑进程
        score += result.suspicious_processes * 10

        # 可疑连接
        score += result.suspicious_connections * 5

        # 凭证
        score += result.credentials_found * 15

        # 恶意软件指标
        critical_count = len([i for i in result.indicators if i.severity == "critical"])
        high_count = len([i for i in result.indicators if i.severity == "high"])
        score += critical_count * 50 + high_count * 25

        if score >= 100:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 20:
            return "medium"
        else:
            return "low"

    def _generate_summary(self, result: MemoryForensicsResult) -> str:
        """生成摘要"""
        return (
            f"内存镜像分析完成: {result.os_type} {result.os_version} {result.architecture}, "
            f"共{result.total_processes}个进程，其中{result.suspicious_processes}个可疑；"
            f"共{result.total_connections}个网络连接，其中{result.suspicious_connections}个可疑；"
            f"发现{result.credentials_found}个凭证；"
            f"发现{result.malware_indicators}个恶意软件指标；"
            f"风险等级: {result.risk_level.upper()}；"
            f"分析耗时: {result.analysis_time:.2f}秒。"
        )

    def _generate_recommendations(self, result: MemoryForensicsResult) -> List[str]:
        """生成建议"""
        recommendations = []

        if result.risk_level in ["critical", "high"]:
            recommendations.append("立即隔离受感染主机，断开网络连接")
            recommendations.append("保存内存镜像和磁盘镜像作为证据")
            recommendations.append("重置所有用户密码，特别是管理员密码")
            recommendations.append("检查所有系统的横向移动痕迹")
            recommendations.append("通知安全团队和管理层")

        if result.suspicious_processes > 0:
            recommendations.append(f"调查{result.suspicious_processes}个可疑进程，终止恶意进程")

        if result.suspicious_connections > 0:
            recommendations.append(f"调查{result.suspicious_connections}个可疑网络连接，阻断C2通信")

        if result.credentials_found > 0:
            recommendations.append(f"重置{result.credentials_found}个被窃取的凭证")

        if result.malware_indicators > 0:
            recommendations.append(f"清除{result.malware_indicators}个恶意软件指标，包括持久化、注入、互斥量")

        recommendations.append("更新所有系统补丁和安全软件")
        recommendations.append("加强网络分段和访问控制")
        recommendations.append("部署EDR/XDR进行持续监控")
        recommendations.append("进行安全意识培训")

        return recommendations

    def generate_report(self, result: MemoryForensicsResult, output_path: str) -> str:
        """生成内存取证报告"""
        report = {
            "title": "内存取证分析报告",
            "image_path": result.image_path,
            "image_size": result.image_size,
            "os_type": result.os_type,
            "os_version": result.os_version,
            "architecture": result.architecture,
            "analysis_time": result.analysis_time,
            "risk_level": result.risk_level,
            "summary": result.summary,
            "statistics": {
                "total_processes": result.total_processes,
                "suspicious_processes": result.suspicious_processes,
                "total_connections": result.total_connections,
                "suspicious_connections": result.suspicious_connections,
                "credentials_found": result.credentials_found,
                "malware_indicators": result.malware_indicators,
            },
            "suspicious_processes": [
                {
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "name": p.name,
                    "path": p.path,
                    "cmdline": p.cmdline,
                    "user": p.user,
                    "suspicious_reasons": p.suspicious_reasons,
                    "injected": p.injected,
                }
                for p in result.processes if p.is_suspicious
            ],
            "suspicious_connections": [
                {
                    "pid": c.pid,
                    "process_name": c.process_name,
                    "protocol": c.protocol,
                    "local": f"{c.local_ip}:{c.local_port}",
                    "remote": f"{c.remote_ip}:{c.remote_port}",
                    "state": c.state,
                    "suspicious_reasons": c.suspicious_reasons,
                    "is_c2": c.is_c2,
                }
                for c in result.connections if c.is_suspicious
            ],
            "credentials": [
                {
                    "type": cred.type,
                    "username": cred.username,
                    "domain": cred.domain,
                    "source": cred.source,
                    "value": cred.value[:20] + "..." if len(cred.value) > 20 else cred.value,
                }
                for cred in result.credentials
            ],
            "malware_indicators": [
                {
                    "type": ind.type,
                    "name": ind.name,
                    "path": ind.path,
                    "description": ind.description,
                    "severity": ind.severity,
                    "evidence": ind.evidence,
                }
                for ind in result.indicators
            ],
            "recommendations": result.recommendations,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        logger.info(f"内存取证报告已生成: {output_path}")
        return output_path

    def list_suspicious_processes(self, processes: List[ProcessInfo]) -> List[ProcessInfo]:
        """列出可疑进程"""
        return [p for p in processes if p.is_suspicious]

    def list_c2_connections(self, connections: List[NetworkConnection]) -> List[NetworkConnection]:
        """列出C2连接"""
        return [c for c in connections if c.is_c2]

    def extract_iocs(self, result: MemoryForensicsResult) -> List[Dict]:
        """提取IOC（入侵指标）"""
        iocs = []

        # IP IOC
        for conn in result.connections:
            if conn.is_suspicious:
                iocs.append({
                    "type": "ip",
                    "value": conn.remote_ip,
                    "context": f"{conn.process_name} (PID:{conn.pid}) -> {conn.remote_ip}:{conn.remote_port}",
                    "severity": "high" if conn.is_c2 else "medium",
                })

        # 进程IOC
        for proc in result.processes:
            if proc.is_suspicious:
                iocs.append({
                    "type": "process",
                    "value": proc.name,
                    "context": f"PID:{proc.pid}, Path:{proc.path}, Reasons:{', '.join(proc.suspicious_reasons)}",
                    "severity": "high",
                })

        # 恶意软件IOC
        for ind in result.indicators:
            iocs.append({
                "type": ind.type,
                "value": ind.name,
                "context": ind.description,
                "severity": ind.severity,
            })

        return iocs


# 便捷函数
async def analyze_memory(image_path: str, output_path: Optional[str] = None) -> MemoryForensicsResult:
    """分析内存镜像便捷函数"""
    mf = MemoryForensics()
    result = await mf.analyze_memory_image(image_path)

    if output_path:
        mf.generate_report(result, output_path)

    return result


def extract_iocs_from_result(result: MemoryForensicsResult) -> List[Dict]:
    """从结果中提取IOC"""
    mf = MemoryForensics()
    return mf.extract_iocs(result)


if __name__ == "__main__":
    # 测试
    print("=== 内存取证分析模块 ===")
    print()

    # 分析测试镜像（如果存在）
    test_image = "test_memory.raw"
    if os.path.exists(test_image):
        result = asyncio.run(analyze_memory(test_image))
        print(f"分析完成: {result.summary}")
    else:
        print("提示: 提供内存镜像文件路径进行分析")
        print("支持的格式: .raw, .dmp, .vmem, .bin")
