#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLMap注入扫描封装
自动化SQL注入检测和利用
"""

import subprocess
import json
import re
import os
import tempfile
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SqlInjectionFinding:
    """SQL注入发现结果"""
    url: str = ""
    parameter: str = ""
    injection_type: str = ""  # boolean_based/error_based/time_based/union_query/stacked_queries
    payload: str = ""
    db_type: str = ""  # mysql/postgresql/mssql/oracle/sqlite
    db_version: str = ""
    severity: str = "critical"
    description: str = ""
    data_extracted: List[str] = field(default_factory=list)


@dataclass
class SqlmapScanResult:
    """SQLMap扫描结果"""
    target_url: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    findings: List[SqlInjectionFinding] = field(default_factory=list)
    total_findings: int = 0
    injectable_params: List[str] = field(default_factory=list)
    db_identified: bool = False
    db_type: str = ""
    command: str = ""
    raw_output: str = ""
    log_file: str = ""


class SqlmapWrapper:
    """SQLMap扫描封装器"""

    # 注入类型
    INJECTION_TYPES = {
        "B": "boolean_based",
        "E": "error_based",
        "U": "union_query",
        "S": "stacked_queries",
        "T": "time_based",
        "Q": "inline_query",
    }

    # 风险级别
    RISK_LEVELS = {1: "low", 2: "medium", 3: "high"}

    def __init__(self, sqlmap_path: str = "sqlmap", timeout: int = 600):
        self.sqlmap_path = sqlmap_path
        self.timeout = timeout
        self._check_sqlmap()

    def _check_sqlmap(self) -> bool:
        """检查sqlmap是否可用"""
        try:
            result = subprocess.run(
                [self.sqlmap_path, "--version"],
                capture_output=True, text=True, timeout=10
            )
            self.available = result.returncode == 0
            self.version = result.stdout.strip() if result.stdout else ""
            return self.available
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.available = False
            self.version = ""
            return False

    def scan(self, url: str,
             data: str = "",
             cookie: str = "",
             parameter: str = "",
             risk: int = 1,
             level: int = 1,
             batch: bool = True,
             custom_args: str = "") -> SqlmapScanResult:
        """
        执行SQLMap扫描

        Args:
            url: 目标URL
            data: POST数据
            cookie: Cookie
            parameter: 指定测试参数
            risk: 风险级别 (1-3)
            level: 测试级别 (1-5)
            batch: 非交互模式
            custom_args: 自定义参数

        Returns:
            SqlmapScanResult扫描结果
        """
        result = SqlmapScanResult(
            target_url=url,
            start_time=datetime.now().isoformat()
        )

        if not self.available:
            result.raw_output = "ERROR: sqlmap not available"
            return result

        # 构建命令
        cmd = [self.sqlmap_path, "-u", url]

        # POST数据
        if data:
            cmd.extend(["--data", data])

        # Cookie
        if cookie:
            cmd.extend(["--cookie", cookie])

        # 指定参数
        if parameter:
            cmd.extend(["-p", parameter])

        # 风险和级别
        cmd.extend(["--risk", str(risk)])
        cmd.extend(["--level", str(level)])

        # 非交互模式
        if batch:
            cmd.append("--batch")

        # 输出格式
        cmd.extend(["--output-dir", tempfile.gettempdir()])

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

            result.raw_output = proc.stdout + proc.stderr
            result.end_time = datetime.now().isoformat()

            # 解析输出
            self._parse_output(proc.stdout, result)

        except subprocess.TimeoutExpired:
            result.raw_output = f"ERROR: scan timed out after {self.timeout}s"
        except Exception as e:
            result.raw_output = f"ERROR: {str(e)}"

        result.total_findings = len(result.findings)
        return result

    def _parse_output(self, output: str, result: SqlmapScanResult):
        """解析SQLMap输出"""
        # 检测可注入参数
        injectable_pattern = r"parameter '([^']+)' is vulnerable"
        for match in re.finditer(injectable_pattern, output, re.IGNORECASE):
            param = match.group(1)
            if param not in result.injectable_params:
                result.injectable_params.append(param)

        # 检测数据库类型
        db_pattern = r"the back-end DBMS is '([^']+)'"
        db_match = re.search(db_pattern, output, re.IGNORECASE)
        if db_match:
            result.db_identified = True
            result.db_type = db_match.group(1)

        # 检测注入类型
        for param in result.injectable_params:
            finding = SqlInjectionFinding(
                url=result.target_url,
                parameter=param,
                severity="critical",
                db_type=result.db_type,
            )

            # 查找该参数的注入类型
            type_pattern = rf"{re.escape(param)}.*?((?:boolean|error|time|union|stacked)[^ \n]*(?:\s+based)?)"
            type_match = re.search(type_pattern, output, re.IGNORECASE)
            if type_match:
                finding.injection_type = type_match.group(1).strip()

            # 查找payload
            payload_pattern = r"Payload:\s*(.+?)(?:\n|$)"
            payload_match = re.search(payload_pattern, output)
            if payload_match:
                finding.payload = payload_match.group(1).strip()[:200]

            finding.description = f"参数 '{param}' 存在SQL注入漏洞（{finding.injection_type}）"
            result.findings.append(finding)

    def quick_scan(self, url: str, data: str = "") -> SqlmapScanResult:
        """快速扫描"""
        return self.scan(url, data=data, risk=1, level=1)

    def deep_scan(self, url: str, data: str = "") -> SqlmapScanResult:
        """深度扫描"""
        return self.scan(url, data=data, risk=3, level=5)

    def get_databases(self, url: str, data: str = "",
                      cookie: str = "") -> SqlmapScanResult:
        """获取数据库列表"""
        custom = "--dbs --batch"
        return self.scan(url, data=data, cookie=cookie, custom_args=custom)

    def get_tables(self, url: str, database: str,
                   data: str = "", cookie: str = "") -> SqlmapScanResult:
        """获取表列表"""
        custom = f"-D {database} --tables --batch"
        return self.scan(url, data=data, cookie=cookie, custom_args=custom)

    def get_columns(self, url: str, database: str, table: str,
                    data: str = "", cookie: str = "") -> SqlmapScanResult:
        """获取列列表"""
        custom = f"-D {database} -T {table} --columns --batch"
        return self.scan(url, data=data, cookie=cookie, custom_args=custom)

    def dump_table(self, url: str, database: str, table: str,
                   data: str = "", cookie: str = "") -> SqlmapScanResult:
        """导出表数据"""
        custom = f"-D {database} -T {table} --dump --batch"
        return self.scan(url, data=data, cookie=cookie, custom_args=custom)

    def os_shell(self, url: str, data: str = "",
                 cookie: str = "") -> SqlmapScanResult:
        """尝试获取OS Shell"""
        custom = "--os-shell --batch"
        return self.scan(url, data=data, cookie=cookie, custom_args=custom)

    def to_dict(self, result: SqlmapScanResult) -> Dict:
        """转换为字典"""
        return {
            "target_url": result.target_url,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration": result.duration,
            "total_findings": result.total_findings,
            "injectable_params": result.injectable_params,
            "db_identified": result.db_identified,
            "db_type": result.db_type,
            "command": result.command,
            "findings": [
                {
                    "url": f.url,
                    "parameter": f.parameter,
                    "injection_type": f.injection_type,
                    "payload": f.payload,
                    "db_type": f.db_type,
                    "db_version": f.db_version,
                    "severity": f.severity,
                    "description": f.description,
                    "data_extracted": f.data_extracted,
                }
                for f in result.findings
            ],
        }
