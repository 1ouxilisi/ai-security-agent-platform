#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nuclei漏洞扫描封装
基于模板的漏洞扫描，支持CVE、暴露面板、默认凭据、配置错误等
"""

import subprocess
import json
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class NucleiFinding:
    """Nuclei发现结果"""
    template_id: str = ""
    template_name: str = ""
    severity: str = "info"  # info/low/medium/high/critical
    host: str = ""
    matched_at: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    reference: List[str] = field(default_factory=list)
    extracted_results: List[str] = field(default_factory=list)
    curl_command: str = ""


@dataclass
class NucleiScanResult:
    """Nuclei扫描结果"""
    target: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    findings: List[NucleiFinding] = field(default_factory=list)
    total_findings: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    templates_used: int = 0
    hosts_scanned: int = 0
    command: str = ""
    raw_output: str = ""


class NucleiWrapper:
    """Nuclei扫描封装器"""

    # 严重级别排序
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

    # 模板分类
    TEMPLATE_CATEGORIES = {
        "cves": "cves",  # CVE漏洞
        "exposures": "exposures",  # 暴露面板
        "default-logins": "default-logins",  # 默认凭据
        "misconfiguration": "misconfiguration",  # 配置错误
        "vulnerabilities": "vulnerabilities",  # 通用漏洞
        "technologies": "technologies",  # 技术识别
        "dns": "dns",  # DNS
        "ssl": "ssl",  # SSL/TLS
        "token-spray": "token-spray",  # Token喷洒
        "fuzzing": "fuzzing",  # Fuzzing
        "malware": "malware",  # 恶意软件
        "miscellaneous": "miscellaneous",  # 杂项
    }

    def __init__(self, nuclei_path: str = "nuclei", timeout: int = 600):
        self.nuclei_path = nuclei_path
        self.timeout = timeout
        self._check_nuclei()

    def _check_nuclei(self) -> bool:
        """检查nuclei是否可用"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "--version"],
                capture_output=True, text=True, timeout=10
            )
            self.available = result.returncode == 0
            self.version = result.stdout.strip() if result.stdout else ""
            return self.available
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.available = False
            self.version = ""
            return False

    def update_templates(self) -> bool:
        """更新漏洞模板"""
        if not self.available:
            return False
        try:
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True, text=True, timeout=120
            )
            return result.returncode == 0
        except Exception:
            return False

    def scan(self, target: str,
             severity: List[str] = None,
             tags: List[str] = None,
             templates: List[str] = None,
             categories: List[str] = None,
             custom_args: str = "") -> NucleiScanResult:
        """
        执行Nuclei扫描

        Args:
            target: 目标URL或IP
            severity: 严重级别过滤（critical/high/medium/low/info）
            tags: 标签过滤
            templates: 指定模板
            categories: 模板分类
            custom_args: 自定义参数

        Returns:
            NucleiScanResult扫描结果
        """
        result = NucleiScanResult(
            target=target,
            start_time=datetime.now().isoformat()
        )

        if not self.available:
            result.raw_output = "ERROR: nuclei not available"
            return result

        # 构建命令
        cmd = [self.nuclei_path, "-u", target, "-json", "-silent"]

        # 严重级别
        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        # 标签
        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        # 指定模板
        if templates:
            for t in templates:
                cmd.extend(["-t", t])

        # 模板分类
        if categories:
            for cat in categories:
                template_path = self.TEMPLATE_CATEGORIES.get(cat, cat)
                cmd.extend(["-t", template_path])

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

            # 解析JSON输出（每行一个JSON）
            if proc.stdout:
                self._parse_json_output(proc.stdout, result)

        except subprocess.TimeoutExpired:
            result.raw_output = f"ERROR: scan timed out after {self.timeout}s"
        except Exception as e:
            result.raw_output = f"ERROR: {str(e)}"

        # 统计
        result.total_findings = len(result.findings)
        result.by_severity = {}
        for f in result.findings:
            result.by_severity[f.severity] = result.by_severity.get(f.severity, 0) + 1

        return result

    def _parse_json_output(self, output: str, result: NucleiScanResult):
        """解析Nuclei JSON输出"""
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                finding = NucleiFinding(
                    template_id=data.get("template-id", ""),
                    template_name=data.get("template", ""),
                    severity=data.get("info", {}).get("severity", "info"),
                    host=data.get("host", ""),
                    matched_at=data.get("matched-at", ""),
                    description=data.get("info", {}).get("description", ""),
                    tags=data.get("info", {}).get("tags", []),
                    cve_ids=data.get("info", {}).get("classification", {}).get("cve-id", []),
                    cwe_ids=data.get("info", {}).get("classification", {}).get("cwe-id", []),
                    cvss_score=float(data.get("info", {}).get("classification", {}).get("cvss-score", 0) or 0),
                    cvss_vector=data.get("info", {}).get("classification", {}).get("cvss-vector", ""),
                    reference=data.get("info", {}).get("reference", []),
                    extracted_results=data.get("extracted-results", []),
                    curl_command=data.get("curl-command", ""),
                )

                # 处理cve-id可能是字符串的情况
                if isinstance(finding.cve_ids, str):
                    finding.cve_ids = [finding.cve_ids]
                if isinstance(finding.cwe_ids, str):
                    finding.cwe_ids = [finding.cwe_ids]

                result.findings.append(finding)

            except json.JSONDecodeError:
                continue

    def quick_scan(self, target: str) -> NucleiScanResult:
        """快速扫描（中高危漏洞）"""
        return self.scan(target, severity=["critical", "high", "medium"])

    def full_scan(self, target: str) -> NucleiScanResult:
        """全量扫描"""
        return self.scan(target)

    def cve_scan(self, target: str) -> NucleiScanResult:
        """仅CVE漏洞扫描"""
        return self.scan(target, categories=["cves"])

    def exposure_scan(self, target: str) -> NucleiScanResult:
        """暴露面板扫描"""
        return self.scan(target, categories=["exposures"])

    def default_login_scan(self, target: str) -> NucleiScanResult:
        """默认凭据扫描"""
        return self.scan(target, categories=["default-logins"])

    def misconfig_scan(self, target: str) -> NucleiScanResult:
        """配置错误扫描"""
        return self.scan(target, categories=["misconfiguration"])

    def tech_detect(self, target: str) -> NucleiScanResult:
        """技术栈识别"""
        return self.scan(target, categories=["technologies"])

    def ssl_scan(self, target: str) -> NucleiScanResult:
        """SSL/TLS扫描"""
        return self.scan(target, categories=["ssl"])

    def get_critical_findings(self, result: NucleiScanResult) -> List[NucleiFinding]:
        """获取严重级别发现"""
        return [f for f in result.findings if f.severity == "critical"]

    def get_high_findings(self, result: NucleiScanResult) -> List[NucleiFinding]:
        """获取高危发现"""
        return [f for f in result.findings if f.severity == "high"]

    def sort_by_severity(self, result: NucleiScanResult) -> List[NucleiFinding]:
        """按严重级别排序"""
        return sorted(
            result.findings,
            key=lambda f: self.SEVERITY_ORDER.index(f.severity)
            if f.severity in self.SEVERITY_ORDER else 99
        )

    def to_dict(self, result: NucleiScanResult) -> Dict:
        """转换为字典"""
        return {
            "target": result.target,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration": result.duration,
            "total_findings": result.total_findings,
            "by_severity": result.by_severity,
            "templates_used": result.templates_used,
            "command": result.command,
            "findings": [
                {
                    "template_id": f.template_id,
                    "template_name": f.template_name,
                    "severity": f.severity,
                    "host": f.host,
                    "matched_at": f.matched_at,
                    "description": f.description,
                    "tags": f.tags,
                    "cve_ids": f.cve_ids,
                    "cwe_ids": f.cwe_ids,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "reference": f.reference,
                    "extracted_results": f.extracted_results,
                    "curl_command": f.curl_command,
                }
                for f in result.findings
            ],
        }
