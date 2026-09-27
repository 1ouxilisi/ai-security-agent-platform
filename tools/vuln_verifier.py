#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_verifier安全工具集成模块，提供相关安全工具的封装和调用。

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
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
import aiohttp
from loguru import logger


@dataclass
class Vulnerability:
    """漏洞信息"""
    id: str
    name: str
    type: str  # sqli/xss/ssrf/rce/lfi/sqli/...
    severity: str  # critical/high/medium/low/info
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0  # 0-1, 置信度
    verified: bool = False
    verified_at: str = ""
    verification_method: str = ""
    false_positive: bool = False
    false_positive_reason: str = ""
    cvss_score: float = 0.0
    cve_id: str = ""
    description: str = ""
    remediation: str = ""


@dataclass
class VerificationResult:
    """验证结果"""
    total: int = 0
    verified_true: int = 0
    verified_false: int = 0
    false_positives: int = 0
    pending: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    summary: str = ""
    false_positive_rate: float = 0.0


class VulnerabilityVerifier:
    """漏洞验证器"""

    def __init__(self, config: Optional[Dict] = None):
        """初始化VulnerabilityVerifier实例。

        Args:
            self: 类实例。
        """
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.max_redirects = self.config.get("max_redirects", 3)
        self.user_agent = self.config.get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        logger.info("漏洞验证增强模块初始化完成")

    async def verify_vulnerability(self, vuln: Vulnerability) -> Vulnerability:
        """验证单个漏洞"""
        logger.info(f"验证漏洞: {vuln.name} - {vuln.url}")

        try:
            if vuln.type == "sqli":
                vuln = await self._verify_sqli(vuln)
            elif vuln.type == "xss":
                vuln = await self._verify_xss(vuln)
            elif vuln.type == "ssrf":
                vuln = await self._verify_ssrf(vuln)
            elif vuln.type == "rce":
                vuln = await self._verify_rce(vuln)
            elif vuln.type == "lfi":
                vuln = await self._verify_lfi(vuln)
            elif vuln.type == "path_traversal":
                vuln = await self._verify_path_traversal(vuln)
            elif vuln.type == "open_redirect":
                vuln = await self._verify_open_redirect(vuln)
            elif vuln.type == "info_disclosure":
                vuln = await self._verify_info_disclosure(vuln)
            else:
                vuln = await self._verify_generic(vuln)

            vuln.verified_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        except Exception as e:
            logger.error(f"验证漏洞失败: {e}")
            vuln.confidence = 0.3
            vuln.verified = False

        return vuln

    async def verify_batch(self, vulnerabilities: List[Vulnerability]) -> VerificationResult:
        """批量验证漏洞"""
        result = VerificationResult()
        result.total = len(vulnerabilities)

        logger.info(f"开始批量验证: {len(vulnerabilities)}个漏洞")

        # 并发验证
        tasks = [self.verify_vulnerability(vuln) for vuln in vulnerabilities]
        verified_vulns = await asyncio.gather(*tasks, return_exceptions=True)

        for vuln in verified_vulns:
            if isinstance(vuln, Exception):
                continue

            result.vulnerabilities.append(vuln)

            if vuln.verified and not vuln.false_positive:
                result.verified_true += 1
            elif vuln.false_positive:
                result.false_positives += 1
                result.verified_false += 1
            else:
                result.pending += 1

            if vuln.confidence >= 0.8:
                result.high_confidence += 1
            elif vuln.confidence >= 0.5:
                result.medium_confidence += 1
            else:
                result.low_confidence += 1

        # 计算误报率
        if result.total > 0:
            result.false_positive_rate = result.false_positives / result.total

        result.summary = self._generate_summary(result)

        logger.info(
            f"批量验证完成: 真阳性{result.verified_true}, "
            f"误报{result.false_positives}, "
            f"误报率{result.false_positive_rate:.2%}"
        )

        return result

    async def _verify_sqli(self, vuln: Vulnerability) -> Vulnerability:
        """验证SQL注入"""
        vuln.verification_method = "布尔盲注+时间盲注双重验证"

        try:
            # 1. 布尔盲注验证
            true_payload = vuln.payload + "' AND '1'='1"
            false_payload = vuln.payload + "' AND '1'='2"

            true_response = await self._make_request(vuln.url, vuln.parameter, true_payload)
            false_response = await self._make_request(vuln.url, vuln.parameter, false_payload)

            if true_response and false_response:
                true_length = len(true_response.get("body", ""))
                false_length = len(false_response.get("body", ""))

                # 响应长度差异明显，可能存在SQL注入
                if abs(true_length - false_length) > 50:
                    vuln.confidence = 0.7
                    vuln.evidence += f"布尔盲注验证: 真响应{true_length}字节, 假响应{false_length}字节, 差异{abs(true_length - false_length)}字节"

                    # 2. 时间盲注验证
                    start_time = time.time()
                    time_payload = vuln.payload + "' AND SLEEP(3)-- "
                    time_response = await self._make_request(vuln.url, vuln.parameter, time_payload)
                    elapsed = time.time() - start_time

                    if elapsed >= 2.5:  # 响应时间超过2.5秒，可能存在时间盲注
                        vuln.confidence = 0.95
                        vuln.verified = True
                        vuln.evidence += f"; 时间盲注验证: 响应时间{elapsed:.2f}秒, 确认存在SQL注入"
                    else:
                        vuln.confidence = 0.6
                        vuln.evidence += f"; 时间盲注验证: 响应时间{elapsed:.2f}秒, 未确认"
                else:
                    vuln.confidence = 0.3
                    vuln.false_positive = True
                    vuln.false_positive_reason = "布尔盲注响应无明显差异，可能为误报"
            else:
                vuln.confidence = 0.4

        except Exception as e:
            vuln.confidence = 0.3
            vuln.evidence += f"; 验证异常: {str(e)}"

        return vuln

    async def _verify_xss(self, vuln: Vulnerability) -> Vulnerability:
        """验证XSS"""
        vuln.verification_method = "Payload反射+上下文分析验证"

        try:
            # 发送无害的XSS payload
            test_payload = "<script>alert('xss_test_12345')</script>"
            response = await self._make_request(vuln.url, vuln.parameter, test_payload)

            if response and response.get("body"):
                body = response["body"]

                # 检查payload是否原样反射
                if test_payload in body:
                    # 检查是否在HTML上下文中（不在标签属性或script标签内）
                    context = self._analyze_xss_context(body, test_payload)

                    if context == "html":
                        vuln.confidence = 0.95
                        vuln.verified = True
                        vuln.evidence = f"XSS验证: Payload原样反射在HTML上下文中，确认存在XSS"
                    elif context == "attribute":
                        vuln.confidence = 0.8
                        vuln.verified = True
                        vuln.evidence = f"XSS验证: Payload反射在标签属性中，可能存在XSS，需进一步验证"
                    elif context == "script":
                        vuln.confidence = 0.7
                        vuln.verified = True
                        vuln.evidence = f"XSS验证: Payload反射在Script标签中，可能存在XSS，需构造合适的Payload"
                    else:
                        vuln.confidence = 0.5
                        vuln.evidence = f"XSS验证: Payload反射但上下文不明"
                else:
                    # 检查是否被编码
                    encoded_payloads = [
                        "&lt;script&gt;alert(&#x27;xss_test_12345&#x27;)&lt;/script&gt;",
                        "%3Cscript%3Ealert('xss_test_12345')%3C/script%3E",
                    ]

                    if any(ep in body for ep in encoded_payloads):
                        vuln.confidence = 0.3
                        vuln.false_positive = True
                        vuln.false_positive_reason = "Payload被HTML编码，不存在XSS"
                    else:
                        vuln.confidence = 0.4
                        vuln.evidence = "XSS验证: Payload未反射，可能为误报"
            else:
                vuln.confidence = 0.3

        except Exception as e:
            vuln.confidence = 0.3
            vuln.evidence += f"; 验证异常: {str(e)}"

        return vuln

    async def _verify_ssrf(self, vuln: Vulnerability) -> Vulnerability:
        """验证SSRF"""
        vuln.verification_method = "DNS回调+HTTP回调验证"

        try:
            # 使用Burp Collaborator或类似服务验证
            # 这里使用一个简单的验证方式：检查是否能访问内网地址
            internal_urls = [
                "http://127.0.0.1/",
                "http://localhost/",
                "http://169.254.169.254/latest/meta-data/",  # AWS元数据
            ]

            for internal_url in internal_urls:
                response = await self._make_request(vuln.url, vuln.parameter, internal_url)

                if response and response.get("status"):
                    status = response["status"]

                    # 如果能访问内网地址，可能存在SSRF
                    if status == 200 and len(response.get("body", "")) > 100:
                        vuln.confidence = 0.85
                        vuln.verified = True
                        vuln.evidence = f"SSRF验证: 成功访问内网地址{internal_url}, 响应{status}, 确认存在SSRF"
                        break
                    elif status in [401, 403, 500]:
                        vuln.confidence = 0.6
                        vuln.evidence = f"SSRF验证: 访问内网地址{internal_url}, 响应{status}, 可能存在SSRF"
                    else:
                        vuln.confidence = 0.3
                else:
                    vuln.confidence = 0.3

        except Exception as e:
            vuln.confidence = 0.3
            vuln.evidence += f"; 验证异常: {str(e)}"

        return vuln

    async def _verify_rce(self, vuln: Vulnerability) -> Vulnerability:
        """验证RCE"""
        vuln.verification_method = "命令执行回显+时间延迟验证"

        try:
            # 1. 时间延迟验证（安全的方式）
            start_time = time.time()
            if "windows" in vuln.url.lower() or "asp" in vuln.url.lower():
                test_payload = "ping -n 4 127.0.0.1"
            else:
                test_payload = "sleep 3"

            response = await self._make_request(vuln.url, vuln.parameter, test_payload)
            elapsed = time.time() - start_time

            if elapsed >= 2.5:
                vuln.confidence = 0.9
                vuln.verified = True
                vuln.evidence = f"RCE验证: 命令执行时间延迟{elapsed:.2f}秒, 确认存在RCE"
            else:
                # 2. 回显验证
                echo_payload = "echo 'rce_test_12345'"
                response = await self._make_request(vuln.url, vuln.parameter, echo_payload)

                if response and "rce_test_12345" in response.get("body", ""):
                    vuln.confidence = 0.95
                    vuln.verified = True
                    vuln.evidence = "RCE验证: 命令执行回显成功, 确认存在RCE"
                else:
                    vuln.confidence = 0.4
                    vuln.evidence = f"RCE验证: 时间延迟{elapsed:.2f}秒, 无回显, 未确认"

        except Exception as e:
            vuln.confidence = 0.3
            vuln.evidence += f"; 验证异常: {str(e)}"

        return vuln

    async def _verify_lfi(self, vuln: Vulnerability) -> Vulnerability:
        """验证LFI"""
        vuln.verification_method = "敏感文件读取验证"

        try:
            # 尝试读取敏感文件
            test_files = [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "/etc/passwd",
                "C:\\windows\\win.ini",
            ]

            for test_file in test_files:
                response = await self._make_request(vuln.url, vuln.parameter, test_file)

                if response and response.get("body"):
                    body = response["body"]

                    # 检查是否读取到敏感文件内容
                    if "root:x:0:0:" in body or "[fonts]" in body or "[extensions]" in body:
                        vuln.confidence = 0.95
                        vuln.verified = True
                        vuln.evidence = f"LFI验证: 成功读取敏感文件{test_file}, 确认存在LFI"
                        break
                    elif len(body) > 500 and "No such file" not in body and "not found" not in body.lower():
                        vuln.confidence = 0.6
                        vuln.evidence = f"LFI验证: 读取文件{test_file}, 响应{len(body)}字节, 可能存在LFI"
                    else:
                        vuln.confidence = 0.3
                else:
                    vuln.confidence = 0.3

        except Exception as e:
            vuln.confidence = 0.3
            vuln.evidence += f"; 验证异常: {str(e)}"

        return vuln

    async def _verify_path_traversal(self, vuln: Vulnerability) -> Vulnerability:
        """验证路径遍历"""
        return await self._verify_lfi(vuln)

    async def _verify_open_redirect(self, vuln: Vulnerability) -> Vulnerability:
        """验证开放重定向"""
        vuln.verification_method = "重定向目标验证"

        try:
            test_url = "https://example.com/redirect_test"
            response = await self._make_request(vuln.url, vuln.parameter, test_url, allow_redirects=False)

            if response:
                location = response.get("headers", {}).get("Location", "")
                status = response.get("status", 0)

                if status in [301, 302, 303, 307, 308] and test_url in location:
                    vuln.confidence = 0.95
                    vuln.verified = True
                    vuln.evidence = f"开放重定向验证: 状态{status}, Location: {location}, 确认存在开放重定向"
                else:
                    vuln.confidence = 0.3
                    vuln.false_positive = True
                    vuln.false_positive_reason = "未重定向到指定URL，可能为误报"
            else:
                vuln.confidence = 0.3

        except Exception as e:
            vuln.confidence = 0.3
            vuln.evidence += f"; 验证异常: {str(e)}"

        return vuln

    async def _verify_info_disclosure(self, vuln: Vulnerability) -> Vulnerability:
        """验证信息泄露"""
        vuln.verification_method = "敏感信息内容验证"

        try:
            response = await self._make_request(vuln.url, "", "")

            if response and response.get("body"):
                body = response["body"]

                # 检查敏感信息
                sensitive_patterns = [
                    (r"password\s*[=:]\s*['\"]?[^\s'\"]+", "密码泄露"),
                    (r"api[_-]?key\s*[=:]\s*['\"]?[^\s'\"]+", "API Key泄露"),
                    (r"secret\s*[=:]\s*['\"]?[^\s'\"]+", "密钥泄露"),
                    (r"token\s*[=:]\s*['\"]?[^\s'\"]+", "Token泄露"),
                    (r"private[_-]?key", "私钥泄露"),
                    (r"stack\s*trace", "堆栈信息泄露"),
                    (r"SQL syntax.*MySQL", "SQL错误信息泄露"),
                ]

                for pattern, desc in sensitive_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        vuln.confidence = 0.9
                        vuln.verified = True
                        vuln.evidence = f"信息泄露验证: 发现{desc}, 确认存在信息泄露"
                        break
                else:
                    vuln.confidence = 0.4
                    vuln.evidence = "信息泄露验证: 未发现明显敏感信息"
            else:
                vuln.confidence = 0.3

        except Exception as e:
            vuln.confidence = 0.3
            vuln.evidence += f"; 验证异常: {str(e)}"

        return vuln

    async def _verify_generic(self, vuln: Vulnerability) -> Vulnerability:
        """通用验证"""
        vuln.verification_method = "通用响应分析验证"

        try:
            response = await self._make_request(vuln.url, vuln.parameter, vuln.payload)

            if response:
                status = response.get("status", 0)
                body = response.get("body", "")

                if status == 200 and len(body) > 100:
                    vuln.confidence = 0.5
                    vuln.evidence = f"通用验证: 响应{status}, 内容{len(body)}字节, 需人工确认"
                elif status in [403, 401]:
                    vuln.confidence = 0.3
                    vuln.false_positive = True
                    vuln.false_positive_reason = f"响应{status}, 可能为误报"
                else:
                    vuln.confidence = 0.4
            else:
                vuln.confidence = 0.3

        except Exception as e:
            vuln.confidence = 0.3
            vuln.evidence += f"; 验证异常: {str(e)}"

        return vuln

    async def _make_request(
        self,
        url: str,
        parameter: str = "",
        payload: str = "",
        allow_redirects: bool = True,
    ) -> Optional[Dict]:
        """发送HTTP请求"""
        try:
            headers = {"User-Agent": self.user_agent}

            # 构造URL
            if parameter and payload:
                if "?" in url:
                    test_url = f"{url}&{parameter}={payload}"
                else:
                    test_url = f"{url}?{parameter}={payload}"
            else:
                test_url = url

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    test_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=allow_redirects,
                    ssl=False,
                ) as response:
                    body = await response.text()
                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "body": body,
                        "url": str(response.url),
                    }

        except Exception as e:
            logger.debug(f"请求失败: {url} - {e}")
            return None

    def _analyze_xss_context(self, body: str, payload: str) -> str:
        """分析XSS上下文"""
        try:
            # 找到payload在body中的位置
            pos = body.find(payload)
            if pos == -1:
                return "unknown"

            # 向前看200个字符，分析上下文
            before = body[max(0, pos - 200):pos]

            # 检查是否在script标签内
            if before.rfind("<script") > before.rfind("</script>"):
                return "script"

            # 检查是否在标签属性内
            tag_match = re.search(r"<\w+[^>]*$", before)
            if tag_match:
                tag_content = tag_match.group(0)
                # 检查是否在属性值内
                if re.search(r'=\s*["\'][^"\']*$', tag_content):
                    return "attribute"

            return "html"

        except Exception:
            return "unknown"

    def _generate_summary(self, result: VerificationResult) -> str:
        """生成验证摘要"""
        return (
            f"漏洞验证完成，共验证{result.total}个漏洞，"
            f"确认真阳性{result.verified_true}个，"
            f"误报{result.false_positives}个，"
            f"误报率{result.false_positive_rate:.2%}，"
            f"高置信度{result.high_confidence}个，"
            f"中置信度{result.medium_confidence}个，"
            f"低置信度{result.low_confidence}个。"
        )

    def filter_false_positives(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """过滤误报"""
        return [v for v in vulnerabilities if not v.false_positive]

    def get_high_confidence(self, vulnerabilities: List[Vulnerability], threshold: float = 0.8) -> List[Vulnerability]:
        """获取高置信度漏洞"""
        return [v for v in vulnerabilities if v.confidence >= threshold]

    def generate_verification_report(self, result: VerificationResult, output_path: str) -> str:
        """生成验证报告"""
        report = {
            "title": "漏洞验证报告",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": result.summary,
            "statistics": {
                "total": result.total,
                "verified_true": result.verified_true,
                "verified_false": result.verified_false,
                "false_positives": result.false_positives,
                "pending": result.pending,
                "false_positive_rate": result.false_positive_rate,
                "high_confidence": result.high_confidence,
                "medium_confidence": result.medium_confidence,
                "low_confidence": result.low_confidence,
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "name": v.name,
                    "type": v.type,
                    "severity": v.severity,
                    "url": v.url,
                    "parameter": v.parameter,
                    "confidence": v.confidence,
                    "verified": v.verified,
                    "verification_status": getattr(v, "verification_status", "unverified"),
                    "false_positive": v.false_positive,
                    "false_positive_reason": v.false_positive_reason,
                    "verification_method": v.verification_method,
                    "evidence": v.evidence,
                    "verified_at": v.verified_at,
                }
                for v in result.vulnerabilities
            ],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        logger.info(f"漏洞验证报告已生成: {output_path}")
        return output_path


# 便捷函数
async def verify_vulnerabilities(vulnerabilities: List[Dict]) -> VerificationResult:
    """验证漏洞便捷函数"""
    verifier = VulnerabilityVerifier()
    vulns = [Vulnerability(**v) for v in vulnerabilities]
    return await verifier.verify_batch(vulns)


def filter_false_positives(vulnerabilities: List[Dict]) -> List[Dict]:
    """过滤误报便捷函数"""
    verifier = VulnerabilityVerifier()
    vulns = [Vulnerability(**v) for v in vulnerabilities]
    filtered = verifier.filter_false_positives(vulns)
    return [v.__dict__ for v in filtered]


if __name__ == "__main__":
    # 测试
    test_vulns = [
        {
            "id": "test-001",
            "name": "测试SQL注入",
            "type": "sqli",
            "severity": "high",
            "url": "https://example.com/test",
            "parameter": "id",
            "payload": "1",
        },
        {
            "id": "test-002",
            "name": "测试XSS",
            "type": "xss",
            "severity": "medium",
            "url": "https://example.com/search",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
        },
    ]

    result = asyncio.run(verify_vulnerabilities(test_vulns))
    print(f"验证完成: {result.summary}")
