#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap端口扫描封装
支持TCP/UDP扫描、服务识别、操作系统检测、脚本扫描
"""

import subprocess
import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PortInfo:
    """端口信息"""
    port: int = 0
    protocol: str = "tcp"
    state: str = "unknown"  # open/closed/filtered
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    cpe: List[str] = field(default_factory=list)
    scripts: List[Dict] = field(default_factory=list)


@dataclass
class HostInfo:
    """主机信息"""
    ip: str = ""
    hostname: str = ""
    state: str = "unknown"  # up/down
    os_guess: str = ""
    os_accuracy: int = 0
    ports: List[PortInfo] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    mac_address: str = ""
    vendor: str = ""
    latency: float = 0.0


@dataclass
class NmapScanResult:
    """Nmap扫描结果"""
    target: str = ""
    scan_type: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    hosts: List[HostInfo] = field(default_factory=list)
    total_hosts: int = 0
    up_hosts: int = 0
    total_ports: int = 0
    open_ports: int = 0
    command: str = ""
    raw_output: str = ""


class NmapWrapper:
    """Nmap扫描封装器"""

    # 扫描类型预设
    SCAN_PRESETS = {
        "quick": "-T4 -F",  # 快速扫描100个常用端口
        "default": "-T4 -sV",  # 默认扫描+服务识别
        "full": "-T4 -p- -sV",  # 全端口+服务识别
        "intense": "-T4 -A -v",  # 深度扫描（OS检测+脚本+服务识别）
        "stealth": "-sS -T2 -f",  # 隐蔽扫描
        "udp": "-sU -T4 --top-ports 100",  # UDP扫描
        "vuln": "-sV --script vuln",  # 漏洞脚本扫描
        "safe": "-sV --script safe",  # 安全脚本扫描
        "discovery": "-sn",  # 主机发现
        "os_detect": "-O -sV",  # OS检测
    }

    def __init__(self, nmap_path: str = "nmap", timeout: int = 300):
        self.nmap_path = nmap_path
        self.timeout = timeout
        self._check_nmap()

    def _check_nmap(self) -> bool:
        """检查nmap是否可用"""
        try:
            result = subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True, text=True, timeout=10
            )
            self.available = result.returncode == 0
            self.version = result.stdout.split("\n")[0] if result.stdout else ""
            return self.available
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.available = False
            self.version = ""
            return False

    def scan(self, target: str, scan_type: str = "default",
             custom_args: str = "", ports: str = "") -> NmapScanResult:
        """
        执行Nmap扫描

        Args:
            target: 目标IP或域名
            scan_type: 扫描类型（quick/default/full/intense/stealth/udp/vuln/safe/discovery/os_detect）
            custom_args: 自定义参数
            ports: 指定端口（如 "80,443,8080" 或 "1-1000"）

        Returns:
            NmapScanResult扫描结果
        """
        result = NmapScanResult(
            target=target,
            scan_type=scan_type,
            start_time=datetime.now().isoformat()
        )

        if not self.available:
            result.raw_output = "ERROR: nmap not available"
            return result

        # 构建命令
        preset_args = self.SCAN_PRESETS.get(scan_type, self.SCAN_PRESETS["default"])
        cmd = [self.nmap_path]

        # 添加预设参数
        cmd.extend(preset_args.split())

        # 添加端口
        if ports:
            cmd.extend(["-p", ports])

        # 添加自定义参数
        if custom_args:
            cmd.extend(custom_args.split())

        # 输出XML格式便于解析
        cmd.extend(["-oX", "-"])

        # 添加目标
        cmd.append(target)

        result.command = " ".join(cmd)

        try:
            # 执行扫描
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            result.raw_output = proc.stdout
            result.end_time = datetime.now().isoformat()

            # 解析XML输出
            if proc.stdout:
                self._parse_xml(proc.stdout, result)

        except subprocess.TimeoutExpired:
            result.raw_output = f"ERROR: scan timed out after {self.timeout}s"
        except Exception as e:
            result.raw_output = f"ERROR: {str(e)}"

        # 计算统计
        result.total_hosts = len(result.hosts)
        result.up_hosts = sum(1 for h in result.hosts if h.state == "up")
        result.total_ports = sum(len(h.ports) for h in result.hosts)
        result.open_ports = sum(len(h.open_ports) for h in result.hosts)

        return result

    def _parse_xml(self, xml_content: str, result: NmapScanResult):
        """解析Nmap XML输出"""
        try:
            root = ET.fromstring(xml_content)

            # 解析扫描信息
            scaninfo = root.find("scaninfo")
            if scaninfo is not None:
                result.scan_type = scaninfo.get("type", result.scan_type)

            # 解析主机
            for host_elem in root.findall("host"):
                host = HostInfo()

                # 状态
                status = host_elem.find("status")
                if status is not None:
                    host.state = status.get("state", "unknown")

                # 地址
                for addr in host_elem.findall("address"):
                    addr_type = addr.get("addrtype", "")
                    if addr_type == "ipv4":
                        host.ip = addr.get("addr", "")
                    elif addr_type == "mac":
                        host.mac_address = addr.get("addr", "")
                        host.vendor = addr.get("vendor", "")

                # 主机名
                hostnames = host_elem.find("hostnames")
                if hostnames is not None:
                    hostname_elem = hostnames.find("hostname")
                    if hostname_elem is not None:
                        host.hostname = hostname_elem.get("name", "")

                # OS检测
                os_elem = host_elem.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        host.os_guess = osmatch.get("name", "")
                        host.os_accuracy = int(osmatch.get("accuracy", 0))

                # 端口
                ports_elem = host_elem.find("ports")
                if ports_elem is not None:
                    for port_elem in ports_elem.findall("port"):
                        port = PortInfo(
                            port=int(port_elem.get("portid", 0)),
                            protocol=port_elem.get("protocol", "tcp")
                        )

                        # 端口状态
                        state_elem = port_elem.find("state")
                        if state_elem is not None:
                            port.state = state_elem.get("state", "unknown")

                        # 服务信息
                        service_elem = port_elem.find("service")
                        if service_elem is not None:
                            port.service = service_elem.get("name", "")
                            port.product = service_elem.get("product", "")
                            port.version = service_elem.get("version", "")
                            port.extra_info = service_elem.get("extrainfo", "")

                            # CPE
                            for cpe_elem in service_elem.findall("cpe"):
                                if cpe_elem.text:
                                    port.cpe.append(cpe_elem.text)

                        # 脚本结果
                        for script_elem in port_elem.findall("script"):
                            script_result = {
                                "id": script_elem.get("id", ""),
                                "output": script_elem.get("output", "")[:500]
                            }
                            port.scripts.append(script_result)

                        host.ports.append(port)
                        if port.state == "open":
                            host.open_ports.append(port.port)

                result.hosts.append(host)

        except ET.ParseError:
            pass

    def quick_scan(self, target: str) -> NmapScanResult:
        """快速扫描"""
        return self.scan(target, "quick")

    def full_scan(self, target: str) -> NmapScanResult:
        """全端口扫描"""
        return self.scan(target, "full")

    def service_scan(self, target: str, ports: str = "") -> NmapScanResult:
        """服务识别扫描"""
        return self.scan(target, "default", ports=ports)

    def vuln_scan(self, target: str, ports: str = "") -> NmapScanResult:
        """漏洞脚本扫描"""
        return self.scan(target, "vuln", ports=ports)

    def os_detect(self, target: str) -> NmapScanResult:
        """操作系统检测"""
        return self.scan(target, "os_detect")

    def host_discovery(self, network: str) -> NmapScanResult:
        """主机发现"""
        return self.scan(network, "discovery")

    def get_open_services(self, result: NmapScanResult) -> List[Dict]:
        """从扫描结果中提取开放服务列表"""
        services = []
        for host in result.hosts:
            for port in host.ports:
                if port.state == "open":
                    services.append({
                        "host": host.ip,
                        "port": port.port,
                        "protocol": port.protocol,
                        "service": port.service,
                        "product": port.product,
                        "version": port.version,
                        "cpe": port.cpe,
                    })
        return services

    def to_dict(self, result: NmapScanResult) -> Dict:
        """转换为字典"""
        return {
            "target": result.target,
            "scan_type": result.scan_type,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration": result.duration,
            "total_hosts": result.total_hosts,
            "up_hosts": result.up_hosts,
            "total_ports": result.total_ports,
            "open_ports": result.open_ports,
            "command": result.command,
            "hosts": [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "state": h.state,
                    "os_guess": h.os_guess,
                    "os_accuracy": h.os_accuracy,
                    "mac_address": h.mac_address,
                    "vendor": h.vendor,
                    "open_ports": h.open_ports,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "product": p.product,
                            "version": p.version,
                            "cpe": p.cpe,
                            "scripts": p.scripts,
                        }
                        for p in h.ports
                    ],
                }
                for h in result.hosts
            ],
        }
