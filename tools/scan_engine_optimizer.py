#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_engine_optimizer安全工具集成模块，提供相关安全工具的封装和调用。

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
import hashlib
import json
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from loguru import logger

try:
    import requests
except ImportError:
    requests = None
    logger.warning("requests未安装，部分扫描功能不可用")


class ScanStatus(Enum):
    """扫描状态"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(Enum):
    """扫描类型"""
    PORT_SCAN = "port_scan"
    SERVICE_DETECTION = "service_detection"
    WEB_SCAN = "web_scan"
    VULN_SCAN = "vuln_scan"
    DIRECTORY_SCAN = "directory_scan"
    SUBDOMAIN_SCAN = "subdomain_scan"
    FULL_SCAN = "full_scan"


class VulnerabilityConfidence(Enum):
    """漏洞置信度"""
    CONFIRMED = "confirmed"  # 已确认
    HIGH = "high"  # 高置信度
    MEDIUM = "medium"  # 中置信度
    LOW = "low"  # 低置信度
    FALSE_POSITIVE = "false_positive"  # 误报


@dataclass
class ScanTask:
    """扫描任务"""
    task_id: str
    target: str
    scan_type: str
    status: str = "pending"
    priority: int = 5  # 1-10, 10最高
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    progress: float = 0.0
    total_steps: int = 0
    completed_steps: int = 0
    vulnerabilities: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    config: Dict = field(default_factory=dict)
    result_summary: Dict = field(default_factory=dict)


@dataclass
class Vulnerability:
    """漏洞"""
    vuln_id: str
    name: str
    severity: str
    category: str
    description: str
    target: str
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""
    confidence: str = "medium"
    cvss_score: float = 0.0
    cve: str = ""
    cwe: str = ""
    fix_suggestion: str = ""
    references: List[str] = field(default_factory=list)
    discovered_at: str = ""
    verified: bool = False
    false_positive: bool = False
    tags: List[str] = field(default_factory=list)


class ScanEngineOptimizer:
    """扫描引擎优化器"""

    def __init__(self, max_workers: int = 10, output_dir: str = "./scan_results"):
        """初始化ScanEngineOptimizer实例。

            Args:
            self: 类实例。
        """
        self.max_workers = max_workers
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.tasks: Dict[str, ScanTask] = {}
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.fingerprint_cache: Dict[str, Dict] = {}
        self.false_positive_patterns: Set[str] = set()
        self._load_false_positive_patterns()
        logger.info(f"扫描引擎优化器初始化完成，最大并发: {max_workers}")

    def _load_false_positive_patterns(self):
        """加载误报模式"""
        # 常见误报模式
        self.false_positive_patterns = {
            "404 page not found",
            "page not found",
            "not found",
            "404",
            "no such file",
            "file not found",
            "directory not found",
            "object not found",
            "resource not found",
        }

    def create_scan_task(self, target: str, scan_type: str = "full_scan",
                         priority: int = 5, config: Dict = None) -> ScanTask:
        """创建扫描任务"""
        task_id = f"scan_{int(time.time())}_{hashlib.md5(target.encode()).hexdigest()[:8]}"

        task = ScanTask(
            task_id=task_id,
            target=target,
            scan_type=scan_type,
            priority=priority,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            config=config or {},
        )

        self.tasks[task_id] = task
        logger.info(f"创建扫描任务: {task_id}，目标: {target}，类型: {scan_type}")

        return task

    def run_scan(self, task_id: str) -> ScanTask:
        """运行扫描任务"""
        task = self.tasks.get(task_id)
        if not task:
            logger.error(f"扫描任务不存在: {task_id}")
            return None

        task.status = "running"
        task.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        logger.info(f"开始扫描任务: {task_id}，目标: {task.target}")

        try:
            if task.scan_type == ScanType.PORT_SCAN.value:
                self._run_port_scan(task)
            elif task.scan_type == ScanType.WEB_SCAN.value:
                self._run_web_scan(task)
            elif task.scan_type == ScanType.VULN_SCAN.value:
                self._run_vuln_scan(task)
            elif task.scan_type == ScanType.DIRECTORY_SCAN.value:
                self._run_directory_scan(task)
            elif task.scan_type == ScanType.FULL_SCAN.value:
                self._run_full_scan(task)
            else:
                self._run_full_scan(task)

            task.status = "completed"
            task.progress = 100.0

        except Exception as e:
            task.status = "failed"
            task.errors.append(str(e))
            logger.error(f"扫描任务失败: {task_id}，错误: {e}")

        task.completed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 保存结果
        self._save_scan_result(task)

        logger.info(f"扫描任务完成: {task_id}，发现漏洞: {len(task.vulnerabilities)}")

        return task

    def _run_full_scan(self, task: ScanTask):
        """运行完整扫描"""
        target = task.target

        # 步骤1: 端口扫描
        logger.info(f"[{task.task_id}] 步骤1/5: 端口扫描")
        self._run_port_scan(task)
        task.completed_steps += 1
        task.progress = 20.0

        # 步骤2: 服务识别
        logger.info(f"[{task.task_id}] 步骤2/5: 服务识别")
        self._run_service_detection(task)
        task.completed_steps += 1
        task.progress = 40.0

        # 步骤3: Web扫描
        logger.info(f"[{task.task_id}] 步骤3/5: Web扫描")
        if self._has_web_service(task):
            self._run_web_scan(task)
        task.completed_steps += 1
        task.progress = 60.0

        # 步骤4: 目录扫描
        logger.info(f"[{task.task_id}] 步骤4/5: 目录扫描")
        if self._has_web_service(task):
            self._run_directory_scan(task)
        task.completed_steps += 1
        task.progress = 80.0

        # 步骤5: 漏洞扫描
        logger.info(f"[{task.task_id}] 步骤5/5: 漏洞扫描")
        self._run_vuln_scan(task)
        task.completed_steps += 1
        task.progress = 100.0

        # 去重和误报过滤
        logger.info(f"[{task.task_id}] 漏洞去重和误报过滤")
        task.vulnerabilities = self._deduplicate_vulnerabilities(task.vulnerabilities)
        task.vulnerabilities = self._filter_false_positives(task.vulnerabilities)

        # 生成摘要
        task.result_summary = self._generate_summary(task)

    def _run_port_scan(self, task: ScanTask):
        """端口扫描"""
        target = task.target.replace("http://", "").replace("https://", "").split("/")[0]
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
                        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 9200, 11211, 27017]

        open_ports = []

        def check_port(port):
            """检查相关状态。

                Args:
                port: 相关参数。

                Returns:
                操作结果。
            """
            import socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None

        # 并发端口扫描
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_port, port): port for port in common_ports}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
                    logger.debug(f"端口开放: {target}:{port}")

        task.result_summary["open_ports"] = open_ports
        task.result_summary["port_scan_count"] = len(common_ports)

        # 检查常见端口漏洞
        for port in open_ports:
            vuln = self._check_port_vulnerability(target, port)
            if vuln:
                task.vulnerabilities.append(vuln)

    def _run_service_detection(self, task: ScanTask):
        """服务识别"""
        target = task.target.replace("http://", "").replace("https://", "").split("/")[0]
        open_ports = task.result_summary.get("open_ports", [])
        services = {}

        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-Proxy", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
        }

        for port in open_ports:
            services[port] = common_services.get(port, "Unknown")

        task.result_summary["services"] = services

        # 检查未授权访问
        for port in open_ports:
            if port in [6379, 9200, 11211, 27017, 9090]:
                vuln = self._check_unauthorized_access(target, port, services[port])
                if vuln:
                    task.vulnerabilities.append(vuln)

    def _run_web_scan(self, task: ScanTask):
        """Web扫描"""
        if not requests:
            return

        target = task.target if task.target.startswith("http") else f"http://{task.target}"

        try:
            resp = requests.get(target, timeout=10, allow_redirects=True)

            # 指纹识别
            fingerprint = self._identify_web_fingerprint(resp)
            task.result_summary["web_fingerprint"] = fingerprint

            # 安全头检查
            security_headers = self._check_security_headers(resp)
            if security_headers:
                task.vulnerabilities.extend(security_headers)

            # 检查常见Web漏洞
            web_vulns = self._check_common_web_vulnerabilities(target, fingerprint)
            task.vulnerabilities.extend(web_vulns)

        except Exception as e:
            task.errors.append(f"Web扫描错误: {e}")

    def _run_directory_scan(self, task: ScanTask):
        """目录扫描"""
        if not requests:
            return

        target = task.target if task.target.startswith("http") else f"http://{task.target}"

        common_dirs = [
            "/admin", "/administrator", "/login", "/wp-admin", "/wp-login.php",
            "/phpmyadmin", "/admin.php", "/config", "/backup", "/.git",
            "/.env", "/api", "/swagger", "/actuator", "/console",
            "/manager", "/jmx-console", "/web-console", "/invoker",
            "/.svn", "/.hg", "/CVS", "/backup.sql", "/database.yml",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/server-status", "/server-info", "/phpinfo.php",
            "/test", "/debug", "/upload", "/uploads", "/files",
        ]

        found_dirs = []

        def check_directory(directory):
            """检查相关状态。

                Args:
                directory: 相关参数。

                Returns:
                操作结果。
            """
            try:
                resp = requests.get(f"{target}{directory}", timeout=5, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 403] and len(resp.text) > 10:
                    return {"path": directory, "status": resp.status_code, "size": len(resp.text)}
            except:
                pass
            return None

        # 并发目录扫描
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_directory, d): d for d in common_dirs}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_dirs.append(result)

        task.result_summary["found_directories"] = found_dirs

        # 检查敏感目录漏洞
        for dir_info in found_dirs:
            vuln = self._check_directory_vulnerability(target, dir_info)
            if vuln:
                task.vulnerabilities.append(vuln)

    def _run_vuln_scan(self, task: ScanTask):
        """漏洞扫描"""
        target = task.target if task.target.startswith("http") else f"http://{task.target}"

        # 基于指纹和服务的智能漏洞扫描
        fingerprint = task.result_summary.get("web_fingerprint", {})
        open_ports = task.result_summary.get("open_ports", [])

        # 检查已知CVE漏洞
        cve_vulns = self._check_known_cves(target, fingerprint, open_ports)
        task.vulnerabilities.extend(cve_vulns)

        # 检查配置错误
        config_vulns = self._check_config_errors(target, fingerprint)
        task.vulnerabilities.extend(config_vulns)

    def _identify_web_fingerprint(self, resp) -> Dict:
        """识别Web指纹"""
        fingerprint = {
            "server": resp.headers.get("Server", ""),
            "x_powered_by": resp.headers.get("X-Powered-By", ""),
            "technology": [],
            "framework": "",
            "cms": "",
        }

        # 检测技术栈
        server = resp.headers.get("Server", "").lower()
        if "nginx" in server:
            fingerprint["technology"].append("Nginx")
        elif "apache" in server:
            fingerprint["technology"].append("Apache")
        elif "iis" in server:
            fingerprint["technology"].append("IIS")

        x_powered = resp.headers.get("X-Powered-By", "").lower()
        if "php" in x_powered:
            fingerprint["technology"].append("PHP")
        elif "asp" in x_powered:
            fingerprint["technology"].append("ASP.NET")
        elif "express" in x_powered:
            fingerprint["technology"].append("Node.js/Express")
        elif "django" in x_powered:
            fingerprint["technology"].append("Python/Django")
        elif "flask" in x_powered:
            fingerprint["technology"].append("Python/Flask")
        elif "spring" in x_powered:
            fingerprint["technology"].append("Java/Spring")

        # 检测CMS
        text = resp.text.lower()
        if "wordpress" in text or "wp-content" in text:
            fingerprint["cms"] = "WordPress"
        elif "drupal" in text:
            fingerprint["cms"] = "Drupal"
        elif "joomla" in text:
            fingerprint["cms"] = "Joomla"
        elif "laravel" in text:
            fingerprint["framework"] = "Laravel"

        return fingerprint

    def _check_security_headers(self, resp) -> List[Dict]:
        """检查安全头"""
        vulns = []
        headers = resp.headers

        security_headers = {
            "X-Frame-Options": {"severity": "low", "description": "缺少X-Frame-Options头，可能受到点击劫持攻击"},
            "X-Content-Type-Options": {"severity": "low", "description": "缺少X-Content-Type-Options头，可能受到MIME类型嗅探攻击"},
            "Content-Security-Policy": {"severity": "medium", "description": "缺少Content-Security-Policy头，可能受到XSS攻击"},
            "Strict-Transport-Security": {"severity": "medium", "description": "缺少Strict-Transport-Security头，可能受到SSL剥离攻击"},
            "Referrer-Policy": {"severity": "low", "description": "缺少Referrer-Policy头，可能泄露敏感信息"},
        }

        for header, info in security_headers.items():
            if header not in headers:
                vulns.append({
                    "name": f"缺少安全头: {header}",
                    "severity": info["severity"],
                    "category": "config",
                    "description": info["description"],
                    "target": resp.url,
                    "confidence": "high",
                    "fix_suggestion": f"配置{header}安全响应头",
                })

        return vulns

    def _check_common_web_vulnerabilities(self, target: str, fingerprint: Dict) -> List[Dict]:
        """检查常见Web漏洞"""
        vulns = []

        # 检查默认页面
        if requests:
            try:
                resp = requests.get(target, timeout=10)
                if "apache" in resp.text.lower() and "it works" in resp.text.lower():
                    vulns.append({
                        "name": "默认页面暴露",
                        "severity": "low",
                        "category": "info-disclosure",
                        "description": "Web服务器显示默认页面，可能泄露服务器信息",
                        "target": target,
                        "confidence": "high",
                    })
            except:
                pass

        return vulns

    def _check_port_vulnerability(self, target: str, port: int) -> Optional[Dict]:
        """检查端口漏洞"""
        port_vulns = {
            21: {"name": "FTP服务暴露", "severity": "low", "description": "FTP服务端口开放，可能存在弱密码或匿名访问"},
            23: {"name": "Telnet服务暴露", "severity": "high", "description": "Telnet服务端口开放，数据以明文传输，存在安全风险"},
            25: {"name": "SMTP服务暴露", "severity": "medium", "description": "SMTP服务端口开放，可能被用于发送垃圾邮件或存在命令注入"},
            139: {"name": "NetBIOS服务暴露", "severity": "medium", "description": "NetBIOS服务端口开放，可能存在信息泄露或SMB漏洞"},
            445: {"name": "SMB服务暴露", "severity": "high", "description": "SMB服务端口开放，可能存在永恒之蓝等SMB漏洞"},
            3389: {"name": "RDP服务暴露", "severity": "medium", "description": "RDP服务端口开放，可能存在弱密码或BlueKeep漏洞"},
            6379: {"name": "Redis服务暴露", "severity": "high", "description": "Redis服务端口开放，可能存在未授权访问"},
            9200: {"name": "Elasticsearch服务暴露", "severity": "high", "description": "Elasticsearch服务端口开放，可能存在未授权访问或数据泄露"},
            11211: {"name": "Memcached服务暴露", "severity": "medium", "description": "Memcached服务端口开放，可能存在未授权访问或DDoS放大攻击"},
            27017: {"name": "MongoDB服务暴露", "severity": "high", "description": "MongoDB服务端口开放，可能存在未授权访问或数据泄露"},
        }

        if port in port_vulns:
            vuln = port_vulns[port].copy()
            vuln["target"] = f"{target}:{port}"
            vuln["category"] = "exposure"
            vuln["confidence"] = "medium"
            return vuln

        return None

    def _check_unauthorized_access(self, target: str, port: int, service: str) -> Optional[Dict]:
        """检查未授权访问"""
        if not requests:
            return None

        try:
            if port == 6379:  # Redis
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, port))
                sock.send(b"INFO\r\n")
                response = sock.recv(1024).decode()
                sock.close()
                if "redis_version" in response:
                    return {
                        "name": "Redis未授权访问",
                        "severity": "critical",
                        "category": "auth",
                        "description": "Redis服务未设置密码，攻击者可以未授权访问，读取数据、写入SSH公钥或执行命令",
                        "target": f"{target}:{port}",
                        "confidence": "confirmed",
                        "evidence": "成功执行INFO命令，获取Redis版本信息",
                        "fix_suggestion": "1. 设置Redis密码(requirepass)\n2. 绑定内网IP\n3. 禁用危险命令\n4. 以低权限运行",
                    }

            elif port == 9200:  # Elasticsearch
                resp = requests.get(f"http://{target}:{port}/_cat/indices", timeout=5)
                if resp.status_code == 200:
                    return {
                        "name": "Elasticsearch未授权访问",
                        "severity": "critical",
                        "category": "auth",
                        "description": "Elasticsearch未设置认证，攻击者可以未授权访问，读取、修改或删除所有数据",
                        "target": f"{target}:{port}",
                        "confidence": "confirmed",
                        "evidence": "成功获取索引列表",
                        "fix_suggestion": "1. 启用X-Pack安全认证\n2. 绑定内网IP\n3. 配置防火墙规则\n4. 定期备份数据",
                    }

            elif port == 11211:  # Memcached
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, port))
                sock.send(b"stats\r\n")
                response = sock.recv(1024).decode()
                sock.close()
                if "STAT" in response:
                    return {
                        "name": "Memcached未授权访问",
                        "severity": "high",
                        "category": "auth",
                        "description": "Memcached未设置认证，攻击者可以未授权访问，读取缓存数据或进行DDoS放大攻击",
                        "target": f"{target}:{port}",
                        "confidence": "confirmed",
                        "evidence": "成功执行stats命令",
                        "fix_suggestion": "1. 绑定内网IP\n2. 配置防火墙规则\n3. 禁用UDP协议\n4. 设置SASL认证",
                    }

            elif port == 27017:  # MongoDB
                resp = requests.get(f"http://{target}:{port}/_listDatabases", timeout=5)
                if resp.status_code == 200 and "databases" in resp.text:
                    return {
                        "name": "MongoDB未授权访问",
                        "severity": "critical",
                        "category": "auth",
                        "description": "MongoDB未设置认证，攻击者可以未授权访问，读取、修改或删除所有数据库",
                        "target": f"{target}:{port}",
                        "confidence": "confirmed",
                        "evidence": "成功获取数据库列表",
                        "fix_suggestion": "1. 启用MongoDB认证\n2. 绑定内网IP\n3. 配置防火墙规则\n4. 定期备份数据",
                    }

        except:
            pass

        return None

    def _check_directory_vulnerability(self, target: str, dir_info: Dict) -> Optional[Dict]:
        """检查目录漏洞"""
        path = dir_info["path"]

        sensitive_dirs = {
            "/.git": {"name": "Git仓库暴露", "severity": "high", "description": ".git目录可公开访问，攻击者可以下载源代码并提取敏感信息"},
            "/.env": {"name": "环境配置文件暴露", "severity": "critical", "description": ".env文件可公开访问，可能包含数据库密码、API密钥等敏感信息"},
            "/.svn": {"name": "SVN仓库暴露", "severity": "high", "description": ".svn目录可公开访问，攻击者可以下载源代码"},
            "/backup.sql": {"name": "数据库备份文件暴露", "severity": "critical", "description": "数据库备份文件可公开下载，可能包含所有用户数据"},
            "/phpmyadmin": {"name": "phpMyAdmin暴露", "severity": "medium", "description": "phpMyAdmin管理界面可公开访问，可能受到暴力破解攻击"},
            "/wp-admin": {"name": "WordPress后台暴露", "severity": "medium", "description": "WordPress管理后台可公开访问，可能受到暴力破解攻击"},
            "/admin": {"name": "管理后台暴露", "severity": "medium", "description": "管理后台可公开访问，可能受到暴力破解或未授权访问"},
            "/actuator": {"name": "Spring Boot Actuator暴露", "severity": "high", "description": "Spring Boot Actuator端点可公开访问，可能泄露环境变量、堆转储等敏感信息"},
            "/swagger": {"name": "API文档暴露", "severity": "low", "description": "Swagger API文档可公开访问，可能泄露API接口信息"},
            "/server-status": {"name": "Apache状态页暴露", "severity": "low", "description": "Apache server-status页面可公开访问，可能泄露服务器状态信息"},
        }

        if path in sensitive_dirs:
            vuln = sensitive_dirs[path].copy()
            vuln["target"] = f"{target}{path}"
            vuln["category"] = "info-disclosure"
            vuln["confidence"] = "high"
            return vuln

        return None

    def _check_known_cves(self, target: str, fingerprint: Dict, open_ports: List[int]) -> List[Dict]:
        """检查已知CVE漏洞"""
        vulns = []

        # 基于服务和端口的CVE检查
        for port in open_ports:
            if port == 445:
                vulns.append({
                    "name": "SMB服务可能存在漏洞",
                    "severity": "high",
                    "category": "cve",
                    "description": "SMB服务端口开放，可能存在MS17-010(永恒之蓝)等SMB漏洞，建议进一步验证",
                    "target": f"{target}:{port}",
                    "cve": "CVE-2017-0144",
                    "confidence": "low",
                    "fix_suggestion": "1. 安装MS17-010补丁\n2. 禁用SMBv1\n3. 限制SMB端口访问",
                })
            elif port == 3389:
                vulns.append({
                    "name": "RDP服务可能存在BlueKeep漏洞",
                    "severity": "high",
                    "category": "cve",
                    "description": "RDP服务端口开放，可能存在CVE-2019-0708(BlueKeep)远程代码执行漏洞，建议进一步验证",
                    "target": f"{target}:{port}",
                    "cve": "CVE-2019-0708",
                    "confidence": "low",
                    "fix_suggestion": "1. 安装KB4499175补丁\n2. 启用网络级别身份验证(NLA)\n3. 限制RDP端口访问",
                })

        # 基于Web指纹的CVE检查
        server = fingerprint.get("server", "").lower()
        if "nginx" in server:
            # 检查Nginx版本漏洞
            pass
        elif "apache" in server:
            # 检查Apache版本漏洞
            pass

        return vulns

    def _check_config_errors(self, target: str, fingerprint: Dict) -> List[Dict]:
        """检查配置错误"""
        vulns = []

        # 检查HTTPS配置
        if target.startswith("http://"):
            vulns.append({
                "name": "未使用HTTPS加密",
                "severity": "medium",
                "category": "config",
                "description": "网站未使用HTTPS加密，数据以明文传输，可能被窃听或篡改",
                "target": target,
                "confidence": "high",
                "fix_suggestion": "1. 配置SSL/TLS证书\n2. 强制HTTPS重定向\n3. 启用HSTS",
            })

        return vulns

    def _has_web_service(self, task: ScanTask) -> bool:
        """检查是否有Web服务"""
        open_ports = task.result_summary.get("open_ports", [])
        web_ports = [80, 443, 8080, 8443, 8000, 8888, 9090]
        return any(port in open_ports for port in web_ports) or task.target.startswith("http")

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """漏洞去重"""
        seen = set()
        unique_vulns = []

        for vuln in vulnerabilities:
            # 生成唯一标识
            key = hashlib.md5(
                f"{vuln.get('name', '')}|{vuln.get('target', '')}|{vuln.get('parameter', '')}|{vuln.get('category', '')}".encode()
            ).hexdigest()

            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
            else:
                logger.debug(f"去重漏洞: {vuln.get('name')} - {vuln.get('target')}")

        return unique_vulns

    def _filter_false_positives(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """误报过滤"""
        filtered = []

        for vuln in vulnerabilities:
            is_false_positive = False

            # 检查证据中是否包含误报模式
            evidence = vuln.get("evidence", "").lower()
            for pattern in self.false_positive_patterns:
                if pattern in evidence:
                    is_false_positive = True
                    break

            # 低置信度且无证据的标记为待验证
            if vuln.get("confidence") == "low" and not vuln.get("evidence"):
                vuln["confidence"] = "low"
                vuln["needs_verification"] = True

            if not is_false_positive:
                filtered.append(vuln)
            else:
                logger.debug(f"过滤误报: {vuln.get('name')} - {vuln.get('target')}")

        return filtered

    def _generate_summary(self, task: ScanTask) -> Dict:
        """生成扫描摘要"""
        vulns = task.vulnerabilities

        summary = {
            "total_vulnerabilities": len(vulns),
            "by_severity": {
                "critical": len([v for v in vulns if v.get("severity") == "critical"]),
                "high": len([v for v in vulns if v.get("severity") == "high"]),
                "medium": len([v for v in vulns if v.get("severity") == "medium"]),
                "low": len([v for v in vulns if v.get("severity") == "low"]),
            },
            "by_category": {},
            "by_confidence": {
                "confirmed": len([v for v in vulns if v.get("confidence") == "confirmed"]),
                "high": len([v for v in vulns if v.get("confidence") == "high"]),
                "medium": len([v for v in vulns if v.get("confidence") == "medium"]),
                "low": len([v for v in vulns if v.get("confidence") == "low"]),
            },
            "open_ports": task.result_summary.get("open_ports", []),
            "services": task.result_summary.get("services", {}),
            "web_fingerprint": task.result_summary.get("web_fingerprint", {}),
            "found_directories": task.result_summary.get("found_directories", []),
            "scan_duration": "",
        }

        # 按类别统计
        for vuln in vulns:
            category = vuln.get("category", "other")
            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1

        return summary

    def _save_scan_result(self, task: ScanTask):
        """保存扫描结果"""
        result = {
            "task_id": task.task_id,
            "target": task.target,
            "scan_type": task.scan_type,
            "status": task.status,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
            "progress": task.progress,
            "vulnerabilities": task.vulnerabilities,
            "errors": task.errors,
            "summary": task.result_summary,
        }

        filepath = os.path.join(self.output_dir, f"{task.task_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        logger.debug(f"扫描结果已保存: {filepath}")

    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """获取任务状态"""
        task = self.tasks.get(task_id)
        if not task:
            return None

        return {
            "task_id": task.task_id,
            "target": task.target,
            "scan_type": task.scan_type,
            "status": task.status,
            "progress": task.progress,
            "completed_steps": task.completed_steps,
            "total_steps": task.total_steps,
            "vulnerabilities_count": len(task.vulnerabilities),
            "errors": task.errors,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
        }

    def list_tasks(self, status: str = None) -> List[Dict]:
        """列出所有任务"""
        tasks = []
        for task in self.tasks.values():
            if status and task.status != status:
                continue
            tasks.append({
                "task_id": task.task_id,
                "target": task.target,
                "scan_type": task.scan_type,
                "status": task.status,
                "progress": task.progress,
                "vulnerabilities_count": len(task.vulnerabilities),
                "created_at": task.created_at,
            })
        return sorted(tasks, key=lambda x: x["created_at"], reverse=True)

    def batch_scan(self, targets: List[str], scan_type: str = "full_scan",
                   max_concurrent: int = 5) -> List[ScanTask]:
        """批量扫描"""
        logger.info(f"开始批量扫描，共 {len(targets)} 个目标，最大并发: {max_concurrent}")

        tasks = []
        for target in targets:
            task = self.create_scan_task(target, scan_type)
            tasks.append(task)

        # 并发执行
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            futures = {executor.submit(self.run_scan, task.task_id): task for task in tasks}
            for future in as_completed(futures):
                task = future.result()
                logger.info(f"批量扫描完成: {task.task_id}，发现漏洞: {len(task.vulnerabilities)}")

        return tasks

    def generate_scan_report(self, task_id: str, output_format: str = "markdown") -> str:
        """生成扫描报告"""
        task = self.tasks.get(task_id)
        if not task:
            return ""

        if output_format == "markdown":
            return self._generate_markdown_report(task)
        elif output_format == "json":
            return json.dumps({
                "task": {
                    "task_id": task.task_id,
                    "target": task.target,
                    "scan_type": task.scan_type,
                    "status": task.status,
                },
                "summary": task.result_summary,
                "vulnerabilities": task.vulnerabilities,
            }, ensure_ascii=False, indent=2)
        else:
            return self._generate_markdown_report(task)

    def _generate_markdown_report(self, task: ScanTask) -> str:
        """生成Markdown报告"""
        summary = task.result_summary

        md = f"""# 安全扫描报告

## 扫描概览

| 项目 | 内容 |
|------|------|
| 扫描任务ID | {task.task_id} |
| 扫描目标 | {task.target} |
| 扫描类型 | {task.scan_type} |
| 扫描状态 | {task.status} |
| 开始时间 | {task.started_at} |
| 完成时间 | {task.completed_at} |
| 发现漏洞数 | {len(task.vulnerabilities)} |

## 漏洞统计

| 严重程度 | 数量 |
|----------|------|
| 严重 (Critical) | {summary.get('by_severity', {}).get('critical', 0)} |
| 高危 (High) | {summary.get('by_severity', {}).get('high', 0)} |
| 中危 (Medium) | {summary.get('by_severity', {}).get('medium', 0)} |
| 低危 (Low) | {summary.get('by_severity', {}).get('low', 0)} |

## 端口扫描结果

开放端口: {', '.join(map(str, summary.get('open_ports', [])))}

## 服务识别

"""

        services = summary.get("services", {})
        if services:
            md += "| 端口 | 服务 |\n|------|------|\n"
            for port, service in services.items():
                md += f"| {port} | {service} |\n"
        else:
            md += "未识别到服务\n"

        md += "\n## Web指纹识别\n\n"
        fingerprint = summary.get("web_fingerprint", {})
        if fingerprint:
            md += f"- 服务器: {fingerprint.get('server', '未知')}\n"
            md += f"- 技术栈: {', '.join(fingerprint.get('technology', []))}\n"
            md += f"- CMS: {fingerprint.get('cms', '未知')}\n"
            md += f"- 框架: {fingerprint.get('framework', '未知')}\n"
        else:
            md += "未识别到Web指纹\n"

        md += "\n## 目录扫描结果\n\n"
        dirs = summary.get("found_directories", [])
        if dirs:
            md += "| 路径 | 状态码 | 大小 |\n|------|--------|------|\n"
            for d in dirs:
                md += f"| {d['path']} | {d['status']} | {d['size']} |\n"
        else:
            md += "未发现敏感目录\n"

        md += "\n## 漏洞详情\n\n"

        # 按严重程度排序
        sorted_vulns = sorted(task.vulnerabilities,
                              key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity"), 4))

        for i, vuln in enumerate(sorted_vulns, 1):
            md += f"""### {i}. {vuln.get('name', '未知漏洞')}

| 项目 | 内容 |
|------|------|
| 严重程度 | **{vuln.get('severity', '').upper()}** |
| 漏洞类型 | {vuln.get('category', '')} |
| 置信度 | {vuln.get('confidence', '')} |
| 目标 | {vuln.get('target', '')} |
| CVE | {vuln.get('cve', '—')} |

**描述：** {vuln.get('description', '')}

**证据：** {vuln.get('evidence', '—')}

**修复建议：** {vuln.get('fix_suggestion', '—')}

---

"""

        md += f"""*报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*由 AI Hacking Agent 扫描引擎优化器自动生成*
"""

        return md


def main():
    """主函数"""
    print("=" * 60)
    print("  扫描引擎优化器")
    print("=" * 60)
    print()

    optimizer = ScanEngineOptimizer(max_workers=10)

    # 示例：创建扫描任务
    print("[1/3] 创建扫描任务...")
    task = optimizer.create_scan_task("http://testphp.vulnweb.com", scan_type="full_scan")
    print(f"  任务ID: {task.task_id}")
    print(f"  目标: {task.target}")
    print()

    # 运行扫描
    print("[2/3] 运行扫描任务...")
    print("  扫描中... (这可能需要几分钟)")
    task = optimizer.run_scan(task.task_id)
    print(f"  扫描完成，状态: {task.status}")
    print(f"  发现漏洞: {len(task.vulnerabilities)}")
    print()

    # 生成报告
    print("[3/3] 生成扫描报告...")
    report = optimizer.generate_scan_report(task.task_id, output_format="markdown")
    report_path = os.path.join(optimizer.output_dir, f"{task.task_id}_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"  报告已生成: {report_path}")
    print()

    # 显示摘要
    print("=" * 60)
    print("  扫描摘要")
    print("=" * 60)
    summary = task.result_summary
    print(f"  开放端口: {summary.get('open_ports', [])}")
    print(f"  发现目录: {len(summary.get('found_directories', []))}个")
    print(f"  漏洞统计:")
    print(f"    严重: {summary.get('by_severity', {}).get('critical', 0)}")
    print(f"    高危: {summary.get('by_severity', {}).get('high', 0)}")
    print(f"    中危: {summary.get('by_severity', {}).get('medium', 0)}")
    print(f"    低危: {summary.get('by_severity', {}).get('low', 0)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
