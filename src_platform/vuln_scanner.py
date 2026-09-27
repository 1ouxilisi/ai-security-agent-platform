#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_scanner模块，提供相关安全测试功能。

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
import time
import uuid
import re
import urllib.request
import urllib.parse
import urllib.error
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import log


@dataclass
class Vulnerability:
    """漏洞"""
    vuln_id: str
    name: str
    severity: str  # critical/high/medium/low/info
    category: str  # sqli/xss/ssrf/idor/rce/lfi/sqli/...
    url: str
    parameter: str = ""
    description: str = ""
    evidence: str = ""  # 漏洞证据（请求/响应片段）
    payload: str = ""  # 使用的payload
    cvss_score: float = 0.0
    cwe_id: str = ""
    confidence: str = "medium"  # high/medium/low
    steps_to_reproduce: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    discovered_at: float = field(default_factory=time.time)
    status: str = "new"  # new/verified/false_positive/submitted/resolved
    false_positive_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "vuln_id": self.vuln_id,
            "name": self.name,
            "severity": self.severity,
            "category": self.category,
            "url": self.url,
            "parameter": self.parameter,
            "description": self.description,
            "evidence": self.evidence[:500],
            "payload": self.payload,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence,
            "steps_to_reproduce": self.steps_to_reproduce,
            "impact": self.impact,
            "remediation": self.remediation,
            "status": self.status,
            "discovered_at": self.discovered_at
        }


@dataclass
class ScanResult:
    """扫描结果"""
    scan_id: str
    target: str
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scanned_urls: int = 0
    tested_parameters: int = 0
    errors: List[str] = field(default_factory=list)
    scan_profile: str = "full"  # quick/full/deep

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": round((self.completed_at or time.time()) - self.started_at, 2),
            "vulnerabilities_count": len(self.vulnerabilities),
            "vulnerabilities_by_severity": {
                "critical": sum(1 for v in self.vulnerabilities if v.severity == "critical"),
                "high": sum(1 for v in self.vulnerabilities if v.severity == "high"),
                "medium": sum(1 for v in self.vulnerabilities if v.severity == "medium"),
                "low": sum(1 for v in self.vulnerabilities if v.severity == "low"),
                "info": sum(1 for v in self.vulnerabilities if v.severity == "info")
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scanned_urls": self.scanned_urls,
            "tested_parameters": self.tested_parameters,
            "errors": self.errors
        }


class SRCVulnerabilityScanner:
    """SRC漏洞扫描引擎"""

    def __init__(self):
        """初始化SRCVulnerabilityScanner实例。

        Args:
            self: 类实例。
        """
        self.timeout = 10
        self.max_threads = 10
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.max_urls_per_scan = 50  # 每次扫描最多URL数
        self.max_params_per_url = 10  # 每个URL最多测试参数数

    async def scan_target(self, target: str, urls: List[str] = None,
                          profile: str = "full") -> ScanResult:
        """
        扫描目标
        :param target: 目标域名/URL
        :param urls: 要扫描的URL列表（如果不提供，会自动收集）
        :param profile: 扫描配置 quick/full/deep
        """
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        result = ScanResult(scan_id=scan_id, target=target, scan_profile=profile)

        log.info(f"开始漏洞扫描: {target}, 配置: {profile}")

        try:
            # 收集要扫描的URL
            if urls:
                target_urls = urls[:self.max_urls_per_scan]
            else:
                target_urls = [target.rstrip("/")]

            result.scanned_urls = len(target_urls)

            # 步骤1：常见漏洞快速检测（所有URL）
            log.info("步骤1/4: 常见漏洞快速检测...")
            for url in target_urls[:20]:
                vulns = await self._quick_vuln_check(url)
                result.vulnerabilities.extend(vulns)

            # 步骤2：参数fuzz（SQL注入/XSS/命令注入等）
            log.info("步骤2/4: 参数模糊测试...")
            for url in target_urls[:20]:
                params = self._extract_url_params(url)
                if params:
                    result.tested_parameters += len(params)
                    vulns = await self._fuzz_parameters(url, params)
                    result.vulnerabilities.extend(vulns)

            # 步骤3：高价值漏洞检测（SSRF/IDOR/LFI等）
            if profile in ["full", "deep"]:
                log.info("步骤3/4: 高价值漏洞检测...")
                for url in target_urls[:10]:
                    vulns = await self._high_value_vuln_check(url)
                    result.vulnerabilities.extend(vulns)

            # 步骤4：敏感信息泄露检测
            log.info("步骤4/4: 敏感信息泄露检测...")
            for url in target_urls[:10]:
                vulns = await self._info_disclosure_check(url)
                result.vulnerabilities.extend(vulns)

        except Exception as e:
            result.errors.append(f"扫描异常: {str(e)}")
            log.error(f"扫描异常: {e}")

        result.completed_at = time.time()
        log.info(f"扫描完成: 发现 {len(result.vulnerabilities)} 个漏洞, 耗时 {result.completed_at - result.started_at:.1f}秒")
        return result

    async def _quick_vuln_check(self, url: str) -> List[Vulnerability]:
        """常见漏洞快速检测"""
        vulns = []
        base_url = url.split("?")[0].rstrip("/")

        # 1. 检测开放重定向
        vulns.extend(self._check_open_redirect(base_url))

        # 2. 检测CORS配置错误
        vulns.extend(self._check_cors_misconfig(url))

        # 3. 检测缺失安全头
        vulns.extend(self._check_security_headers(url))

        # 4. 检测HTTP方法（PUT/DELETE等）
        vulns.extend(self._check_dangerous_methods(url))

        # 5. 检测目录列表
        vulns.extend(self._check_directory_listing(base_url))

        return vulns

    def _check_open_redirect(self, base_url: str) -> List[Vulnerability]:
        """检测开放重定向"""
        vulns = []
        redirect_params = ["url", "redirect", "next", "go", "to", "link", "return", "return_url", "callback", "dest", "destination", "redir", "redirect_url"]

        for param in redirect_params:
            test_url = f"{base_url}?{param}=https://evil.com"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    if "evil.com" in response.url.lower():
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name="开放重定向漏洞",
                            severity="medium",
                            category="open_redirect",
                            url=test_url,
                            parameter=param,
                            description=f"参数 {param} 存在开放重定向漏洞，可将用户重定向到任意网站",
                            evidence=f"重定向到: {response.url}",
                            payload=f"{param}=https://evil.com",
                            cwe_id="CWE-601",
                            confidence="high",
                            impact="可用于钓鱼攻击，将用户重定向到恶意网站",
                            remediation="对重定向URL进行白名单验证，仅允许重定向到可信域名"
                        ))
                        break
            except Exception:
                pass
        return vulns

    def _check_cors_misconfig(self, url: str) -> List[Vulnerability]:
        """检测CORS配置错误"""
        vulns = []
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": self.user_agent,
                "Origin": "https://evil.com"
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*" and acac.lower() == "true":
                    vulns.append(Vulnerability(
                        vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                        name="CORS配置错误 - 通配符+凭证",
                        severity="high",
                        category="cors",
                        url=url,
                        description="CORS配置允许任意来源访问且允许携带凭证，攻击者可窃取用户数据",
                        evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                        cwe_id="CWE-942",
                        confidence="high",
                        impact="攻击者可通过恶意网站窃取已登录用户的敏感数据",
                        remediation="不要同时使用通配符Origin和Allow-Credentials，使用白名单限制可信来源"
                    ))
                elif acao == "https://evil.com":
                    vulns.append(Vulnerability(
                        vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                        name="CORS配置错误 - 反射Origin",
                        severity="high",
                        category="cors",
                        url=url,
                        description="CORS配置反射任意Origin，攻击者可构造恶意网站窃取用户数据",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        cwe_id="CWE-942",
                        confidence="high",
                        impact="攻击者可通过恶意网站窃取已登录用户的敏感数据",
                        remediation="使用白名单限制可信Origin，不要反射任意Origin"
                    ))
        except Exception:
            pass
        return vulns

    def _check_security_headers(self, url: str) -> List[Vulnerability]:
        """检测缺失安全头"""
        vulns = []
        required_headers = {
            "X-Frame-Options": "防止点击劫持",
            "X-Content-Type-Options": "防止MIME类型嗅探",
            "Strict-Transport-Security": "强制HTTPS",
            "Content-Security-Policy": "防止XSS和数据注入",
            "X-XSS-Protection": "XSS过滤（旧浏览器）"
        }

        try:
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                headers_lower = {k.lower(): v for k, v in response.headers.items()}
                missing = []
                for header, desc in required_headers.items():
                    if header.lower() not in headers_lower:
                        missing.append(f"{header} ({desc})")

                if missing:
                    vulns.append(Vulnerability(
                        vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                        name="缺失安全响应头",
                        severity="low",
                        category="security_headers",
                        url=url,
                        description=f"缺少以下安全响应头: {', '.join(missing)}",
                        evidence=f"缺失头数量: {len(missing)}",
                        cwe_id="CWE-693",
                        confidence="high",
                        impact="可能增加点击劫持、XSS、MIME嗅探等攻击风险",
                        remediation="添加所有必要的安全响应头"
                    ))
        except Exception:
            pass
        return vulns

    def _check_dangerous_methods(self, url: str) -> List[Vulnerability]:
        """检测危险HTTP方法"""
        vulns = []
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]

        for method in dangerous_methods:
            try:
                req = urllib.request.Request(url, method=method, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    if response.status in [200, 201, 204]:
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name=f"危险HTTP方法启用: {method}",
                            severity="medium" if method in ["PUT", "DELETE"] else "low",
                            category="http_methods",
                            url=url,
                            description=f"服务器允许 {method} 方法，可能被用于未授权操作",
                            evidence=f"{method} 返回状态码: {response.status}",
                            cwe_id="CWE-650",
                            confidence="medium",
                            impact=f"PUT可上传文件，DELETE可删除资源，TRACE可用于XST攻击",
                            remediation="在服务器配置中禁用不必要的HTTP方法"
                        ))
                        break
            except Exception:
                pass
        return vulns

    def _check_directory_listing(self, base_url: str) -> List[Vulnerability]:
        """检测目录列表"""
        vulns = []
        test_dirs = ["", "/uploads", "/files", "/images", "/assets", "/backup", "/data"]

        for directory in test_dirs:
            test_url = base_url + directory + "/"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace").lower()
                    if "index of" in body or "directory listing" in body:
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name="目录列表泄露",
                            severity="low",
                            category="directory_listing",
                            url=test_url,
                            description=f"目录 {directory}/ 启用了目录列表，可能泄露敏感文件",
                            evidence="页面包含 'Index of' 或 'Directory Listing'",
                            cwe_id="CWE-548",
                            confidence="high",
                            impact="攻击者可浏览目录内容，发现敏感文件和备份",
                            remediation="在服务器配置中禁用目录列表"
                        ))
                        break
            except Exception:
                pass
        return vulns

    def _extract_url_params(self, url: str) -> Dict[str, str]:
        """提取URL参数"""
        params = {}
        if "?" in url:
            query = url.split("?")[1]
            for pair in query.split("&"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    params[key] = value
        return params

    async def _fuzz_parameters(self, url: str, params: Dict[str, str]) -> List[Vulnerability]:
        """参数模糊测试（SQL注入/XSS/命令注入）"""
        vulns = []
        base_url = url.split("?")[0]

        for param_name, param_value in list(params.items())[:self.max_params_per_url]:
            # SQL注入测试
            sqli_vulns = self._test_sqli(base_url, param_name, param_value)
            vulns.extend(sqli_vulns)

            # XSS测试
            xss_vulns = self._test_xss(base_url, param_name, param_value)
            vulns.extend(xss_vulns)

            # 命令注入测试
            cmdi_vulns = self._test_command_injection(base_url, param_name, param_value)
            vulns.extend(cmdi_vulns)

        return vulns

    def _test_sqli(self, base_url: str, param: str, original_value: str) -> List[Vulnerability]:
        """测试SQL注入"""
        vulns = []
        sqli_payloads = [
            ("'", "单引号测试"),
            ("1' OR '1'='1", "恒真测试"),
            ("1\" OR \"1\"=\"1", "双引号恒真"),
            ("1 ORDER BY 1--", "ORDER BY测试"),
            ("1 UNION SELECT NULL--", "UNION测试"),
            ("1 AND SLEEP(5)--", "时间盲注"),
        ]

        for payload, description in sqli_payloads:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                start = time.time()
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace").lower()
                    elapsed = time.time() - start

                    # 检测SQL错误
                    sql_errors = ["sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite3.",
                                 "unclosed quotation", "sqlstate", "syntax error"]
                    if any(err in body for err in sql_errors):
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name="SQL注入漏洞（报错型）",
                            severity="critical",
                            category="sqli",
                            url=test_url,
                            parameter=param,
                            description=f"参数 {param} 存在SQL注入漏洞（报错型）",
                            evidence=f"检测到SQL错误信息，payload: {payload}",
                            payload=payload,
                            cwe_id="CWE-89",
                            confidence="high",
                            impact="攻击者可读取、修改、删除数据库数据，甚至获取服务器权限",
                            remediation="使用参数化查询，对用户输入进行严格验证",
                            steps_to_reproduce=[
                                f"1. 访问 {test_url}",
                                f"2. 参数 {param} 的值被解释为SQL命令",
                                "3. 页面返回SQL错误信息"
                            ]
                        ))
                        break

                    # 时间盲注
                    if "SLEEP" in payload.upper() and elapsed > 4:
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name="SQL注入漏洞（时间盲注）",
                            severity="high",
                            category="sqli",
                            url=test_url,
                            parameter=param,
                            description=f"参数 {param} 存在SQL注入漏洞（时间盲注）",
                            evidence=f"响应时间 {elapsed:.1f}秒，预期延迟5秒",
                            payload=payload,
                            cwe_id="CWE-89",
                            confidence="medium",
                            impact="攻击者可通过时间延迟逐位提取数据库数据",
                            remediation="使用参数化查询，对用户输入进行严格验证"
                        ))
                        break

            except Exception:
                pass

        return vulns

    def _test_xss(self, base_url: str, param: str, original_value: str) -> List[Vulnerability]:
        """测试XSS"""
        vulns = []
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "'\"><script>alert(1)</script>",
        ]

        for payload in xss_payloads:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace")

                    # 检测payload是否未过滤输出
                    if payload in body:
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name="反射型XSS漏洞",
                            severity="high",
                            category="xss",
                            url=test_url,
                            parameter=param,
                            description=f"参数 {param} 存在反射型XSS漏洞",
                            evidence=f"payload未过滤直接输出: {payload}",
                            payload=payload,
                            cwe_id="CWE-79",
                            confidence="high",
                            impact="攻击者可窃取用户Cookie、会话令牌，进行钓鱼攻击",
                            remediation="对用户输入进行HTML实体编码，使用Content-Security-Policy",
                            steps_to_reproduce=[
                                f"1. 访问 {test_url}",
                                "2. 页面执行了注入的JavaScript代码",
                                "3. 弹出alert对话框"
                            ]
                        ))
                        break
            except Exception:
                pass

        return vulns

    def _test_command_injection(self, base_url: str, param: str, original_value: str) -> List[Vulnerability]:
        """测试命令注入"""
        vulns = []
        cmdi_payloads = [
            ("; id", "分号注入"),
            ("| id", "管道注入"),
            ("&& id", "AND注入"),
            ("`id`", "反引号注入"),
            ("$(id)", "命令替换"),
        ]

        for payload, description in cmdi_payloads:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace").lower()

                    # 检测命令执行结果
                    if "uid=" in body or "gid=" in body or "root:" in body:
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name="命令注入漏洞",
                            severity="critical",
                            category="command_injection",
                            url=test_url,
                            parameter=param,
                            description=f"参数 {param} 存在命令注入漏洞",
                            evidence=f"检测到系统命令执行结果，payload: {payload}",
                            payload=payload,
                            cwe_id="CWE-78",
                            confidence="high",
                            impact="攻击者可执行任意系统命令，读取敏感文件，获取服务器完全控制权",
                            remediation="避免直接拼接系统命令，使用参数化API，对输入进行白名单验证",
                            steps_to_reproduce=[
                                f"1. 访问 {test_url}",
                                "2. 参数值被解释为系统命令",
                                "3. 页面返回命令执行结果（如uid=...）"
                            ]
                        ))
                        break
            except Exception:
                pass

        return vulns

    async def _high_value_vuln_check(self, url: str) -> List[Vulnerability]:
        """高价值漏洞检测（SSRF/IDOR/LFI）"""
        vulns = []
        base_url = url.split("?")[0]
        params = self._extract_url_params(url)

        # SSRF测试
        ssrf_params = ["url", "uri", "target", "host", "server", "proxy", "callback", "webhook", "fetch", "request", "redirect", "path", "file", "download"]
        for param in params:
            if any(p in param.lower() for p in ssrf_params):
                ssrf_vulns = self._test_ssrf(base_url, param)
                vulns.extend(ssrf_vulns)
                if ssrf_vulns:
                    break

        # LFI测试
        lfi_params = ["file", "path", "filename", "template", "page", "view", "include", "document", "folder", "root"]
        for param in params:
            if any(p in param.lower() for p in lfi_params):
                lfi_vulns = self._test_lfi(base_url, param)
                vulns.extend(lfi_vulns)
                if lfi_vulns:
                    break

        return vulns

    def _test_ssrf(self, base_url: str, param: str) -> List[Vulnerability]:
        """测试SSRF"""
        vulns = []
        ssrf_payloads = [
            ("http://127.0.0.1", "本地回环"),
            ("http://localhost", "localhost"),
            ("http://169.254.169.254/latest/meta-data/", "AWS元数据"),
            ("file:///etc/passwd", "file协议"),
        ]

        for payload, description in ssrf_payloads:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace").lower()

                    if "root:x:" in body or "root:" in body:
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name="SSRF漏洞（文件读取）",
                            severity="high",
                            category="ssrf",
                            url=test_url,
                            parameter=param,
                            description=f"参数 {param} 存在SSRF漏洞，可读取本地文件",
                            evidence=f"成功读取/etc/passwd，payload: {payload}",
                            payload=payload,
                            cwe_id="CWE-918",
                            confidence="high",
                            impact="攻击者可读取服务器本地文件，访问内部服务，获取云元数据凭证",
                            remediation="限制可请求的协议和目标，禁止访问内网IP和云元数据地址"
                        ))
                        break

                    if "ami-id" in body or "instance-id" in body:
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name="SSRF漏洞（云元数据访问）",
                            severity="critical",
                            category="ssrf",
                            url=test_url,
                            parameter=param,
                            description=f"参数 {param} 存在SSRF漏洞，可访问云元数据服务",
                            evidence=f"成功访问AWS元数据，payload: {payload}",
                            payload=payload,
                            cwe_id="CWE-918",
                            confidence="high",
                            impact="攻击者可获取云服务临时凭证，控制云资源",
                            remediation="禁止访问169.254.169.254等云元数据地址"
                        ))
                        break

            except Exception:
                pass

        return vulns

    def _test_lfi(self, base_url: str, param: str) -> List[Vulnerability]:
        """测试LFI"""
        vulns = []
        lfi_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//etc/passwd",
        ]

        for payload in lfi_payloads:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace").lower()

                    if "root:x:" in body or "root:" in body:
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name="本地文件包含漏洞(LFI)",
                            severity="high",
                            category="lfi",
                            url=test_url,
                            parameter=param,
                            description=f"参数 {param} 存在本地文件包含漏洞",
                            evidence=f"成功读取/etc/passwd，payload: {payload}",
                            payload=payload,
                            cwe_id="CWE-98",
                            confidence="high",
                            impact="攻击者可读取服务器任意文件，包含敏感配置和源代码",
                            remediation="规范化文件路径，使用白名单限制可访问目录"
                        ))
                        break

                    if "[fonts]" in body or "[extensions]" in body:
                        vulns.append(Vulnerability(
                            vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                            name="本地文件包含漏洞(LFI) - Windows",
                            severity="high",
                            category="lfi",
                            url=test_url,
                            parameter=param,
                            description=f"参数 {param} 存在本地文件包含漏洞（Windows）",
                            evidence=f"成功读取win.ini，payload: {payload}",
                            payload=payload,
                            cwe_id="CWE-98",
                            confidence="high",
                            impact="攻击者可读取Windows系统文件和配置",
                            remediation="规范化文件路径，使用白名单限制可访问目录"
                        ))
                        break

            except Exception:
                pass

        return vulns

    async def _info_disclosure_check(self, url: str) -> List[Vulnerability]:
        """敏感信息泄露检测"""
        vulns = []
        base_url = url.split("?")[0].rstrip("/")

        sensitive_files = [
            ("/.env", "环境变量文件，可能包含数据库密码、API密钥"),
            ("/.git/config", "Git配置文件，可能泄露仓库信息"),
            ("/.git/HEAD", "Git HEAD文件"),
            ("/config.php", "PHP配置文件"),
            ("/config.json", "JSON配置文件"),
            ("/backup.sql", "数据库备份文件"),
            ("/database.sql", "数据库文件"),
            ("/phpinfo.php", "PHP信息文件，泄露服务器配置"),
            ("/server-status", "Apache服务器状态"),
            ("/.DS_Store", "macOS目录元数据文件"),
            ("/web.config", "IIS配置文件"),
            ("/.htaccess", "Apache配置文件"),
            ("/swagger-ui.html", "API文档，可能泄露API端点"),
            ("/api-docs", "API文档"),
            ("/graphql", "GraphQL端点，可能存在内省查询"),
        ]

        for path, description in sensitive_files:
            test_url = base_url + path
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    if response.status == 200:
                        body = response.read().decode("utf-8", errors="replace")
                        if len(body) > 10:  # 确保不是空页面
                            severity = "high" if any(x in path for x in [".env", ".git", "backup", "database", "phpinfo"]) else "medium"
                            vulns.append(Vulnerability(
                                vuln_id=f"vuln-{uuid.uuid4().hex[:6]}",
                                name=f"敏感文件泄露: {path}",
                                severity=severity,
                                category="info_disclosure",
                                url=test_url,
                                description=f"发现敏感文件 {path}: {description}",
                                evidence=f"文件可访问，大小: {len(body)}字节",
                                cwe_id="CWE-200",
                                confidence="high",
                                impact=description,
                                remediation=f"删除或限制访问 {path}，确保敏感文件不对外暴露"
                            ))
            except Exception:
                pass

        return vulns

    def get_scan_summary(self, result: ScanResult) -> Dict[str, Any]:
        """获取扫描摘要"""
        return {
            "scan_id": result.scan_id,
            "target": result.target,
            "status": "completed" if result.completed_at else "running",
            "duration_seconds": round((result.completed_at or time.time()) - result.started_at, 2),
            "total_vulnerabilities": len(result.vulnerabilities),
            "by_severity": {
                "critical": sum(1 for v in result.vulnerabilities if v.severity == "critical"),
                "high": sum(1 for v in result.vulnerabilities if v.severity == "high"),
                "medium": sum(1 for v in result.vulnerabilities if v.severity == "medium"),
                "low": sum(1 for v in result.vulnerabilities if v.severity == "low"),
                "info": sum(1 for v in result.vulnerabilities if v.severity == "info")
            },
            "high_value_vulns": [v.to_dict() for v in result.vulnerabilities if v.severity in ["critical", "high"]],
            "scanned_urls": result.scanned_urls,
            "tested_parameters": result.tested_parameters,
            "errors": result.errors
        }


# 全局实例
src_scanner = SRCVulnerabilityScanner()
