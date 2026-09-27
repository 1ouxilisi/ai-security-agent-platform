#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描编排器
整合Nmap、Nuclei、SQLMap、Nikto，提供统一的自动化扫描接口
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .nmap_wrapper import NmapWrapper, NmapScanResult
from .nuclei_wrapper import NucleiWrapper, NucleiScanResult
from .sqlmap_wrapper import SqlmapWrapper, SqlmapScanResult
from .nikto_wrapper import NiktoWrapper, NiktoScanResult


@dataclass
class ScanTask:
    """扫描任务"""
    task_id: str = ""
    target: str = ""
    scan_type: str = "full"  # quick/full/deep/web/infrastructure
    status: str = "pending"  # pending/running/completed/failed
    start_time: str = ""
    end_time: str = ""
    progress: int = 0
    results: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class UnifiedScanResult:
    """统一扫描结果"""
    target: str = ""
    scan_type: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0

    # 各工具结果
    nmap_result: Optional[NmapScanResult] = None
    nuclei_result: Optional[NucleiScanResult] = None
    sqlmap_result: Optional[SqlmapScanResult] = None
    nikto_result: Optional[NiktoScanResult] = None

    # 汇总统计
    total_open_ports: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # 汇总发现
    all_findings: List[Dict] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)

    status: str = "completed"
    errors: List[str] = field(default_factory=list)


class ScanOrchestrator:
    """扫描编排器"""

    SCAN_TYPES = {
        "quick": {
            "description": "快速扫描 - 常用端口+中高危漏洞",
            "nmap": "quick",
            "nuclei": True,
            "nuclei_severity": ["critical", "high", "medium"],
            "sqlmap": False,
            "nikto": False,
        },
        "full": {
            "description": "完整扫描 - 全端口+全漏洞+Web扫描",
            "nmap": "full",
            "nuclei": True,
            "nuclei_severity": None,  # 全部
            "sqlmap": True,
            "nikto": True,
        },
        "deep": {
            "description": "深度扫描 - 全端口+深度漏洞+SQL注入+Web扫描",
            "nmap": "intense",
            "nuclei": True,
            "nuclei_severity": None,
            "sqlmap": True,
            "sqlmap_deep": True,
            "nikto": True,
        },
        "web": {
            "description": "Web专项扫描 - Web漏洞+SQL注入+配置错误",
            "nmap": "default",
            "nmap_ports": "80,443,8080,8443",
            "nuclei": True,
            "nuclei_categories": ["cves", "exposures", "default-logins", "misconfiguration"],
            "sqlmap": True,
            "nikto": True,
        },
        "infrastructure": {
            "description": "基础设施扫描 - 端口+服务+OS+漏洞",
            "nmap": "intense",
            "nuclei": True,
            "nuclei_severity": ["critical", "high"],
            "sqlmap": False,
            "nikto": False,
        },
    }

    def __init__(self, nmap_path: str = "nmap",
                 nuclei_path: str = "nuclei",
                 sqlmap_path: str = "sqlmap",
                 nikto_path: str = "nikto",
                 max_workers: int = 4):
        self.nmap = NmapWrapper(nmap_path)
        self.nuclei = NucleiWrapper(nuclei_path)
        self.sqlmap = SqlmapWrapper(sqlmap_path)
        self.nikto = NiktoWrapper(nikto_path)
        self.max_workers = max_workers
        self.tasks: Dict[str, ScanTask] = {}

    def get_tool_status(self) -> Dict[str, Any]:
        """获取工具状态"""
        return {
            "nmap": {
                "available": self.nmap.available,
                "version": self.nmap.version,
            },
            "nuclei": {
                "available": self.nuclei.available,
                "version": self.nuclei.version,
            },
            "sqlmap": {
                "available": self.sqlmap.available,
                "version": self.sqlmap.version,
            },
            "nikto": {
                "available": self.nikto.available,
                "version": self.nikto.version,
            },
        }

    def scan(self, target: str, scan_type: str = "full",
             custom_config: Dict = None) -> UnifiedScanResult:
        """
        执行统一扫描

        Args:
            target: 目标IP/域名/URL
            scan_type: 扫描类型（quick/full/deep/web/infrastructure）
            custom_config: 自定义配置

        Returns:
            UnifiedScanResult统一扫描结果
        """
        result = UnifiedScanResult(
            target=target,
            scan_type=scan_type,
            start_time=datetime.now().isoformat()
        )

        # 获取扫描配置
        config = self.SCAN_TYPES.get(scan_type, self.SCAN_TYPES["full"])
        if custom_config:
            config.update(custom_config)

        # 1. Nmap扫描
        if config.get("nmap"):
            try:
                nmap_type = config["nmap"]
                ports = config.get("nmap_ports", "")
                result.nmap_result = self.nmap.scan(
                    target, nmap_type, ports=ports
                )
                result.total_open_ports = result.nmap_result.open_ports
                result.services = self.nmap.get_open_services(result.nmap_result)
            except Exception as e:
                result.errors.append(f"Nmap扫描失败: {str(e)}")

        # 2. Nuclei扫描
        if config.get("nuclei"):
            try:
                # 构建目标URL
                url = target if target.startswith("http") else f"http://{target}"
                severity = config.get("nuclei_severity")
                categories = config.get("nuclei_categories")
                result.nuclei_result = self.nuclei.scan(
                    url, severity=severity, categories=categories
                )
            except Exception as e:
                result.errors.append(f"Nuclei扫描失败: {str(e)}")

        # 3. SQLMap扫描
        if config.get("sqlmap"):
            try:
                url = target if target.startswith("http") else f"http://{target}"
                if config.get("sqlmap_deep"):
                    result.sqlmap_result = self.sqlmap.deep_scan(url)
                else:
                    result.sqlmap_result = self.sqlmap.quick_scan(url)
            except Exception as e:
                result.errors.append(f"SQLMap扫描失败: {str(e)}")

        # 4. Nikto扫描
        if config.get("nikto"):
            try:
                # 从Nmap结果获取Web端口
                web_ports = [80, 443, 8080, 8443]
                if result.nmap_result:
                    for host in result.nmap_result.hosts:
                        for port in host.ports:
                            if port.state == "open" and port.service in ("http", "https"):
                                web_ports.append(port.port)

                # 扫描第一个Web端口
                port = web_ports[0] if web_ports else 80
                ssl = port in (443, 8443)
                result.nikto_result = self.nikto.scan(
                    target, port=port, ssl=ssl
                )
            except Exception as e:
                result.errors.append(f"Nikto扫描失败: {str(e)}")

        # 汇总统计
        self._aggregate_results(result)
        result.end_time = datetime.now().isoformat()

        return result

    def _aggregate_results(self, result: UnifiedScanResult):
        """汇总扫描结果"""
        # Nuclei发现
        if result.nuclei_result:
            for f in result.nuclei_result.findings:
                finding = {
                    "source": "nuclei",
                    "template_id": f.template_id,
                    "severity": f.severity,
                    "description": f.description,
                    "host": f.host,
                    "matched_at": f.matched_at,
                    "cve_ids": f.cve_ids,
                    "cvss_score": f.cvss_score,
                }
                result.all_findings.append(finding)

                # 统计
                sev = f.severity.lower()
                if sev == "critical":
                    result.critical_count += 1
                elif sev == "high":
                    result.high_count += 1
                elif sev == "medium":
                    result.medium_count += 1
                elif sev == "low":
                    result.low_count += 1
                else:
                    result.info_count += 1

        # SQLMap发现
        if result.sqlmap_result:
            for f in result.sqlmap_result.findings:
                finding = {
                    "source": "sqlmap",
                    "severity": "critical",
                    "description": f.description,
                    "url": f.url,
                    "parameter": f.parameter,
                    "injection_type": f.injection_type,
                    "db_type": f.db_type,
                }
                result.all_findings.append(finding)
                result.critical_count += 1

        # Nikto发现
        if result.nikto_result:
            for f in result.nikto_result.findings:
                finding = {
                    "source": "nikto",
                    "severity": f.severity,
                    "description": f.description,
                    "osvdb_id": f.osvdb_id,
                    "cve_id": f.cve_id,
                    "resource": f.resource,
                }
                result.all_findings.append(finding)

                sev = f.severity.lower()
                if sev == "critical":
                    result.critical_count += 1
                elif sev == "high":
                    result.high_count += 1
                elif sev == "medium":
                    result.medium_count += 1
                elif sev == "low":
                    result.low_count += 1
                else:
                    result.info_count += 1

        result.total_vulnerabilities = len(result.all_findings)

    def quick_scan(self, target: str) -> UnifiedScanResult:
        """快速扫描"""
        return self.scan(target, "quick")

    def full_scan(self, target: str) -> UnifiedScanResult:
        """完整扫描"""
        return self.scan(target, "full")

    def deep_scan(self, target: str) -> UnifiedScanResult:
        """深度扫描"""
        return self.scan(target, "deep")

    def web_scan(self, target: str) -> UnifiedScanResult:
        """Web专项扫描"""
        return self.scan(target, "web")

    def infrastructure_scan(self, target: str) -> UnifiedScanResult:
        """基础设施扫描"""
        return self.scan(target, "infrastructure")

    def get_scan_types(self) -> Dict[str, str]:
        """获取可用扫描类型"""
        return {k: v["description"] for k, v in self.SCAN_TYPES.items()}

    def to_dict(self, result: UnifiedScanResult) -> Dict:
        """转换为字典"""
        return {
            "target": result.target,
            "scan_type": result.scan_type,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration": result.duration,
            "summary": {
                "total_open_ports": result.total_open_ports,
                "total_vulnerabilities": result.total_vulnerabilities,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "info": result.info_count,
            },
            "services": result.services,
            "findings": result.all_findings,
            "nmap": self.nmap.to_dict(result.nmap_result) if result.nmap_result else None,
            "nuclei": self.nuclei.to_dict(result.nuclei_result) if result.nuclei_result else None,
            "sqlmap": self.sqlmap.to_dict(result.sqlmap_result) if result.sqlmap_result else None,
            "nikto": self.nikto.to_dict(result.nikto_result) if result.nikto_result else None,
            "errors": result.errors,
            "status": result.status,
        }
