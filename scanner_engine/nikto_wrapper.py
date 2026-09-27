#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nikto Web扫描封装
Web服务器漏洞扫描、配置错误检测、危险文件检测
"""

import subprocess
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class NiktoFinding:
    """Nikto发现结果"""
    url: str = ""
    description: str = ""
    osvdb_id: str = ""
    cve_id: str = ""
    severity: str = "medium"  # info/low/medium/high/critical
    method: str = "GET"
    resource: str = ""
    extra: str = ""


@dataclass
class NiktoScanResult:
    """Nikto扫描结果"""
    target_url: str = ""
    target_port: int = 80
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    findings: List[NiktoFinding] = field(default_factory=list)
    total_findings: int = 0
    server_header: str = ""
    x_powered_by: str = ""
    all_ports: bool = False
    command: str = ""
    raw_output: str = ""


class NiktoWrapper:
    """Nikto扫描封装器"""

    # OSVDB严重级别映射
    OSVDB_SEVERITY = {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
        "5": "critical",
    }

    def __init__(self, nikto_path: str = "nikto", timeout: int = 600):
        self.nikto_path = nikto_path
        self.timeout = timeout
        self._check_nikto()

    def _check_nikto(self) -> bool:
        """检查nikto是否可用"""
        try:
            # nikto -Version 可能需要perl
            result = subprocess.run(
                ["perl", self.nikto_path, "-Version"],
                capture_output=True, text=True, timeout=10
            )
            self.available = result.returncode == 0
            self.version = ""
            for line in result.stdout.split("\n"):
                if "version" in line.lower():
                    self.version = line.strip()
                    break
            return self.available
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.available = False
            self.version = ""
            return False

    def scan(self, url: str,
             port: int = 80,
             ssl: bool = False,
             plugins: List[str] = None,
             tuning: str = "",
             custom_args: str = "") -> NiktoScanResult:
        """
        执行Nikto扫描

        Args:
            url: 目标URL或主机
            port: 端口
            ssl: 是否使用SSL
            plugins: 指定插件
            tuning: 调优选项 (1-9, x)
            custom_args: 自定义参数

        Returns:
            NiktoScanResult扫描结果
        """
        result = NiktoScanResult(
            target_url=url,
            target_port=port,
            start_time=datetime.now().isoformat()
        )

        if not self.available:
            result.raw_output = "ERROR: nikto not available"
            return result

        # 构建命令
        cmd = ["perl", self.nikto_path, "-h", url, "-p", str(port), "-Format", "xml"]

        # SSL
        if ssl or port == 443:
            cmd.append("-ssl")

        # 插件
        if plugins:
            cmd.extend(["-Plugins", ",".join(plugins)])

        # 调优
        if tuning:
            cmd.extend(["-Tuning", tuning])

        # 自定义参数
        if custom_args:
            cmd.extend(custom_args.split())

        result.command = " ".join(cmd)

        try:
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

        result.total_findings = len(result.findings)
        return result

    def _parse_xml(self, xml_content: str, result: NiktoScanResult):
        """解析Nikto XML输出"""
        try:
            # 找到XML根元素（可能有前置输出）
            xml_start = xml_content.find("<?xml")
            if xml_start >= 0:
                xml_content = xml_content[xml_start:]

            root = ET.fromstring(xml_content)

            # 扫描详情
            scandetails = root.find("scandetails")
            if scandetails is not None:
                result.target_url = scandetails.get("targetip", result.target_url)
                result.target_port = int(scandetails.get("targetport", result.target_port))
                result.server_header = scandetails.get("serverheader", "")
                result.start_time = scandetails.get("starttime", result.start_time)
                result.end_time = scandetails.get("endtime", result.end_time)

            # 发现结果
            for item in root.findall(".//item"):
                finding = NiktoFinding(
                    description=item.get("description", ""),
                    osvdb_id=item.get("osvdbid", ""),
                    method=item.get("method", "GET"),
                    resource=item.get("uri", ""),
                )

                # 严重级别
                osvdb = item.get("osvdbid", "0")
                finding.severity = self.OSVDB_SEVERITY.get(osvdb, "medium")

                # 提取CVE
                cve_match = re.search(r"CVE-\d{4}-\d+", finding.description)
                if cve_match:
                    finding.cve_id = cve_match.group(0)

                # 额外信息
                extra_elem = item.find("extra")
                if extra_elem is not None and extra_elem.text:
                    finding.extra = extra_elem.text[:200]

                result.findings.append(finding)

        except ET.ParseError:
            # XML解析失败，尝试从文本输出提取
            self._parse_text(xml_content, result)

    def _parse_text(self, output: str, result: NiktoScanResult):
        """从文本输出提取信息（备用）"""
        # 服务器头
        server_match = re.search(r"Server: (.+)", output)
        if server_match:
            result.server_header = server_match.group(1).strip()

        # 发现项
        for line in output.split("\n"):
            if "+ " in line and "OSVDB" in line:
                finding = NiktoFinding(description=line.strip()[2:])
                osvdb_match = re.search(r"OSVDB-(\d+)", line)
                if osvdb_match:
                    finding.osvdb_id = osvdb_match.group(1)
                    finding.severity = self.OSVDB_SEVERITY.get(
                        osvdb_match.group(1), "medium"
                    )
                result.findings.append(finding)

    def quick_scan(self, url: str, port: int = 80) -> NiktoScanResult:
        """快速扫描"""
        return self.scan(url, port=port, tuning="2")

    def full_scan(self, url: str, port: int = 80) -> NiktoScanResult:
        """全量扫描"""
        return self.scan(url, port=port)

    def ssl_scan(self, url: str, port: int = 443) -> NiktoScanResult:
        """SSL扫描"""
        return self.scan(url, port=port, ssl=True)

    def get_high_severity(self, result: NiktoScanResult) -> List[NiktoFinding]:
        """获取高危发现"""
        return [f for f in result.findings if f.severity in ("high", "critical")]

    def get_cve_findings(self, result: NiktoScanResult) -> List[NiktoFinding]:
        """获取含CVE的发现"""
        return [f for f in result.findings if f.cve_id]

    def to_dict(self, result: NiktoScanResult) -> Dict:
        """转换为字典"""
        return {
            "target_url": result.target_url,
            "target_port": result.target_port,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration": result.duration,
            "total_findings": result.total_findings,
            "server_header": result.server_header,
            "x_powered_by": result.x_powered_by,
            "command": result.command,
            "findings": [
                {
                    "url": f.url,
                    "description": f.description,
                    "osvdb_id": f.osvdb_id,
                    "cve_id": f.cve_id,
                    "severity": f.severity,
                    "method": f.method,
                    "resource": f.resource,
                    "extra": f.extra,
                }
                for f in result.findings
            ],
        }
