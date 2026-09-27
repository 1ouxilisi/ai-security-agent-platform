#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
移动端漏洞扫描器
Mobile Vulnerability Scanner

功能：移动端API安全测试、移动端配置检测、移动端渗透测试
"""

import os
import re
import json
import hashlib
import requests
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from loguru import logger


@dataclass
class MobileAPITestResult:
    """移动端API测试结果"""
    url: str
    method: str
    is_vulnerable: bool = False
    vulnerability_type: str = ""
    severity: str = "low"
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    request_headers: Dict = field(default_factory=dict)
    response_status: int = 0
    response_headers: Dict = field(default_factory=dict)
    response_body: str = ""

    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'method': self.method,
            'is_vulnerable': self.is_vulnerable,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence[:500] if self.evidence else '',
            'recommendation': self.recommendation,
            'response_status': self.response_status,
        }


@dataclass
class MobileConfigCheck:
    """移动端配置检查"""
    check_name: str
    is_vulnerable: bool = False
    severity: str = "low"
    description: str = ""
    current_value: str = ""
    recommended_value: str = ""

    def to_dict(self) -> Dict:
        return {
            'check_name': self.check_name,
            'is_vulnerable': self.is_vulnerable,
            'severity': self.severity,
            'description': self.description,
            'current_value': self.current_value,
            'recommended_value': self.recommended_value,
        }


@dataclass
class MobileScanResult:
    """移动端扫描结果"""
    target: str
    scan_type: str
    api_tests: List[MobileAPITestResult] = field(default_factory=list)
    config_checks: List[MobileConfigCheck] = field(default_factory=list)
    total_tests: int = 0
    vulnerable_count: int = 0
    risk_score: float = 0.0
    risk_level: str = "low"
    summary: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'target': self.target,
            'scan_type': self.scan_type,
            'api_tests': [t.to_dict() for t in self.api_tests],
            'config_checks': [c.to_dict() for c in self.config_checks],
            'total_tests': self.total_tests,
            'vulnerable_count': self.vulnerable_count,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'summary': self.summary,
        }


class MobileScanner:
    """移动端漏洞扫描器"""

    def __init__(self, target: str = None, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
        })

    def scan_api(self, api_url: str, method: str = 'GET',
                 headers: Dict = None, data: Dict = None) -> MobileScanResult:
        """扫描移动端API"""
        logger.info(f"开始扫描移动端API: {api_url}")

        result = MobileScanResult(target=api_url, scan_type='api')

        # 1. 基础安全测试
        result.api_tests.extend(self._test_api_security(api_url, method, headers, data))

        # 2. 认证授权测试
        result.api_tests.extend(self._test_auth(api_url, method, headers, data))

        # 3. 输入验证测试
        result.api_tests.extend(self._test_input_validation(api_url, method, headers, data))

        # 4. 配置检查
        result.config_checks = self._check_mobile_config(api_url)

        # 5. 汇总
        result.total_tests = len(result.api_tests) + len(result.config_checks)
        result.vulnerable_count = len([t for t in result.api_tests if t.is_vulnerable]) + \
                                   len([c for c in result.config_checks if c.is_vulnerable])

        # 风险评分
        critical = len([t for t in result.api_tests if t.severity == 'critical'])
        high = len([t for t in result.api_tests if t.severity == 'high'])
        medium = len([t for t in result.api_tests if t.severity == 'medium'])
        result.risk_score = min(100, critical * 15 + high * 8 + medium * 3)

        if result.risk_score >= 70:
            result.risk_level = 'critical'
        elif result.risk_score >= 50:
            result.risk_level = 'high'
        elif result.risk_score >= 30:
            result.risk_level = 'medium'
        else:
            result.risk_level = 'low'

        result.summary = {
            'api_tests': len(result.api_tests),
            'config_checks': len(result.config_checks),
            'vulnerable': result.vulnerable_count,
            'critical': critical,
            'high': high,
            'medium': medium,
        }

        logger.info(f"API扫描完成: 发现 {result.vulnerable_count} 个问题")
        return result

    def _test_api_security(self, url: str, method: str,
                            headers: Dict = None, data: Dict = None) -> List[MobileAPITestResult]:
        """API安全测试"""
        results = []

        try:
            # 1. HTTPS检测
            if url.startswith('http://'):
                results.append(MobileAPITestResult(
                    url=url, method=method,
                    is_vulnerable=True,
                    vulnerability_type='cleartext_transport',
                    severity='high',
                    description='API使用明文HTTP传输，存在中间人攻击风险',
                    recommendation='改用HTTPS加密传输',
                ))

            # 2. 发送请求获取响应
            resp = self._send_request(url, method, headers, data)
            if resp:
                # 3. 安全头检测
                security_headers = {
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': 'DENY',
                    'X-XSS-Protection': '1; mode=block',
                    'Strict-Transport-Security': 'max-age=',
                    'Content-Security-Policy': '',
                }

                for header, expected in security_headers.items():
                    if header not in resp.headers:
                        results.append(MobileAPITestResult(
                            url=url, method=method,
                            is_vulnerable=True,
                            vulnerability_type=f'missing_{header.lower()}',
                            severity='medium',
                            description=f'缺少安全响应头: {header}',
                            recommendation=f'添加 {header} 响应头',
                            response_status=resp.status_code,
                        ))

                # 4. 错误信息泄露
                if resp.status_code >= 500:
                    results.append(MobileAPITestResult(
                        url=url, method=method,
                        is_vulnerable=True,
                        vulnerability_type='error_disclosure',
                        severity='medium',
                        description=f'服务器返回500错误，可能泄露敏感信息',
                        evidence=resp.text[:200],
                        recommendation='统一错误处理，不返回详细错误信息',
                        response_status=resp.status_code,
                    ))

                # 5. CORS配置检测
                cors_header = resp.headers.get('Access-Control-Allow-Origin', '')
                if cors_header == '*':
                    results.append(MobileAPITestResult(
                        url=url, method=method,
                        is_vulnerable=True,
                        vulnerability_type='cors_misconfiguration',
                        severity='high',
                        description='CORS配置允许任意来源(Access-Control-Allow-Origin: *)',
                        recommendation='限制允许的来源域名',
                        response_status=resp.status_code,
                    ))

        except Exception as e:
            logger.warning(f"API安全测试失败: {e}")

        return results

    def _test_auth(self, url: str, method: str,
                   headers: Dict = None, data: Dict = None) -> List[MobileAPITestResult]:
        """认证授权测试"""
        results = []

        try:
            # 1. 无认证访问测试
            resp_no_auth = self._send_request(url, method, {}, data)
            if resp_no_auth and resp_no_auth.status_code == 200:
                results.append(MobileAPITestResult(
                    url=url, method=method,
                    is_vulnerable=True,
                    vulnerability_type='missing_authentication',
                    severity='critical',
                    description='API无需认证即可访问，存在未授权访问风险',
                    recommendation='添加认证机制，验证用户身份',
                    response_status=resp_no_auth.status_code,
                ))

            # 2. Token过期测试（模拟）
            if headers and ('Authorization' in headers or 'token' in headers):
                results.append(MobileAPITestResult(
                    url=url, method=method,
                    is_vulnerable=False,
                    vulnerability_type='token_expiration',
                    severity='info',
                    description='API使用认证Token，建议检查Token过期机制',
                    recommendation='设置合理的Token过期时间，支持Token刷新',
                ))

        except Exception as e:
            logger.warning(f"认证测试失败: {e}")

        return results

    def _test_input_validation(self, url: str, method: str,
                                headers: Dict = None, data: Dict = None) -> List[MobileAPITestResult]:
        """输入验证测试"""
        results = []

        # 1. SQL注入测试（简化）
        sql_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users;--", "1' AND SLEEP(5)--"]
        for payload in sql_payloads[:2]:  # 限制测试数量
            try:
                test_data = data.copy() if data else {}
                for key in test_data:
                    test_data[key] = payload

                resp = self._send_request(url, method, headers, test_data)
                if resp and resp.status_code == 500:
                    results.append(MobileAPITestResult(
                        url=url, method=method,
                        is_vulnerable=True,
                        vulnerability_type='sql_injection',
                        severity='critical',
                        description=f'可能存在SQL注入漏洞，Payload: {payload}',
                        evidence=f'返回状态码: {resp.status_code}',
                        recommendation='使用参数化查询，过滤用户输入',
                        response_status=resp.status_code,
                    ))
                    break
            except Exception:
                pass

        # 2. XSS测试（简化）
        xss_payload = '<script>alert(1)</script>'
        try:
            test_data = data.copy() if data else {}
            for key in test_data:
                test_data[key] = xss_payload

            resp = self._send_request(url, method, headers, test_data)
            if resp and xss_payload in resp.text:
                results.append(MobileAPITestResult(
                    url=url, method=method,
                    is_vulnerable=True,
                    vulnerability_type='xss',
                    severity='high',
                    description='可能存在XSS漏洞，用户输入未经过滤直接输出',
                    evidence=f'Payload在响应中反射: {xss_payload}',
                    recommendation='对用户输入进行HTML转义，使用Content-Security-Policy',
                    response_status=resp.status_code,
                ))
        except Exception:
            pass

        return results

    def _check_mobile_config(self, url: str) -> List[MobileConfigCheck]:
        """移动端配置检查"""
        checks = []

        # 1. API版本控制
        if '/api/' in url and not re.search(r'/api/v\d+/', url):
            checks.append(MobileConfigCheck(
                check_name='api_versioning',
                is_vulnerable=True,
                severity='medium',
                description='API未使用版本控制，可能导致兼容性问题',
                current_value='无版本控制',
                recommended_value='使用 /api/v1/ 格式',
            ))

        # 2. 速率限制（模拟检查）
        checks.append(MobileConfigCheck(
            check_name='rate_limiting',
            is_vulnerable=False,
            severity='info',
            description='建议检查API是否实施速率限制，防止暴力破解和DDoS',
            current_value='未检测',
            recommended_value='实施速率限制，如100次/分钟',
        ))

        # 3. 数据加密
        checks.append(MobileConfigCheck(
            check_name='data_encryption',
            is_vulnerable=False,
            severity='info',
            description='建议检查移动端本地数据加密，敏感数据应加密存储',
            current_value='未检测',
            recommended_value='使用AES-256加密敏感数据',
        ))

        # 4. 证书锁定
        checks.append(MobileConfigCheck(
            check_name='certificate_pinning',
            is_vulnerable=False,
            severity='info',
            description='建议检查移动端是否实施证书锁定，防止中间人攻击',
            current_value='未检测',
            recommended_value='实施SSL Pinning',
        ))

        # 5. 代码混淆
        checks.append(MobileConfigCheck(
            check_name='code_obfuscation',
            is_vulnerable=False,
            severity='info',
            description='建议检查移动端代码是否混淆，防止逆向工程',
            current_value='未检测',
            recommended_value='使用ProGuard/R8进行代码混淆',
        ))

        return checks

    def _send_request(self, url: str, method: str,
                      headers: Dict = None, data: Dict = None) -> Optional[requests.Response]:
        """发送HTTP请求"""
        try:
            if method.upper() == 'GET':
                resp = self.session.get(url, headers=headers, params=data, timeout=self.timeout, verify=False)
            else:
                resp = self.session.post(url, headers=headers, json=data, timeout=self.timeout, verify=False)
            return resp
        except requests.exceptions.Timeout:
            logger.warning(f"请求超时: {url}")
            return None
        except requests.exceptions.ConnectionError:
            logger.warning(f"连接失败: {url}")
            return None
        except Exception as e:
            logger.warning(f"请求失败: {url}: {e}")
            return None


def quick_mobile_scan(target: str, scan_type: str = 'api') -> Dict:
    """快速移动端扫描"""
    scanner = MobileScanner(target=target)
    if scan_type == 'api':
        result = scanner.scan_api(target)
    else:
        result = MobileScanResult(target=target, scan_type=scan_type)
    return result.to_dict()
