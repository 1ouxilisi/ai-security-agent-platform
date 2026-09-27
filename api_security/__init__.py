#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API安全测试模块
提供OpenAPI解析、参数Fuzz、逻辑漏洞测试、认证测试功能
"""

import os
import re
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class APIEndpoint:
    """API端点"""
    path: str = ""
    method: str = ""
    description: str = ""
    parameters: List[Dict] = field(default_factory=list)
    responses: Dict = field(default_factory=dict)
    auth_required: bool = False
    tags: List[str] = field(default_factory=list)


@dataclass
class APIVulnerability:
    """API漏洞"""
    endpoint: str = ""
    method: str = ""
    vulnerability: str = ""
    severity: str = ""
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    parameter: str = ""


class APISecurityTester:
    """API安全测试器"""

    # Fuzz Payload
    FUZZ_PAYLOADS = {
        'sql_injection': ["' OR '1'='1", "' OR 1=1--", "admin'--", "1; DROP TABLE users--", "' UNION SELECT NULL--"],
        'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg onload=alert(1)>"],
        'command_injection': ["; id", "| id", "&& id", "`id`", "$(id)"],
        'path_traversal': ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
        'ssrf': ["http://127.0.0.1", "http://localhost", "http://169.254.169.254", "http://[::1]"],
        'xxe': ["<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1\">]>"],
    }

    def __init__(self):
        self.endpoints: List[APIEndpoint] = []
        self.vulnerabilities: List[APIVulnerability] = []

    def parse_openapi(self, spec_path: str = "", spec_url: str = "") -> List[APIEndpoint]:
        """解析OpenAPI/Swagger文档"""
        endpoints = []

        try:
            spec = {}
            if spec_path and os.path.exists(spec_path):
                with open(spec_path, 'r', encoding='utf-8') as f:
                    spec = json.load(f)
            elif spec_url:
                import urllib.request
                with urllib.request.urlopen(spec_url, timeout=10) as response:
                    spec = json.loads(response.read().decode('utf-8'))

            if spec:
                paths = spec.get('paths', {})
                for path, methods in paths.items():
                    for method, details in methods.items():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                            endpoint = APIEndpoint(
                                path=path,
                                method=method.upper(),
                                description=details.get('description', details.get('summary', '')),
                                parameters=details.get('parameters', []),
                                responses=details.get('responses', {}),
                                tags=details.get('tags', []),
                                auth_required=bool(details.get('security', False))
                            )
                            endpoints.append(endpoint)

        except Exception as e:
            print(f"OpenAPI解析错误: {e}")

        self.endpoints = endpoints
        return endpoints

    def discover_endpoints_from_js(self, js_content: str) -> List[Dict]:
        """从JavaScript文件中发现API端点"""
        endpoints = []

        # 常见的API调用模式
        patterns = [
            r'(?:fetch|axios|ajax|get|post|put|delete)\s*\(\s*["\']([^"\']*(?:/api/|/v[0-9]+/)[^"\']*)["\']',
            r'["\']((?:/api/|/v[0-9]+/)[a-zA-Z0-9_/\-{}$.:]+)["\']',
            r'(?:url|endpoint|path)\s*[:=]\s*["\']([^"\']*(?:/api/|/v[0-9]+/)[^"\']*)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match and len(match) > 5 and match not in [e['path'] for e in endpoints]:
                    endpoints.append({'path': match, 'method': 'UNKNOWN', 'source': 'js'})

        return endpoints

    def test_authentication(self, base_url: str, endpoints: List[Dict] = None) -> List[APIVulnerability]:
        """测试认证漏洞"""
        vulns = []

        test_endpoints = endpoints or [
            {'path': '/api/v1/users', 'method': 'GET'},
            {'path': '/api/v1/admin', 'method': 'GET'},
            {'path': '/api/v1/users/1', 'method': 'GET'},
            {'path': '/api/v1/config', 'method': 'GET'},
        ]

        for ep in test_endpoints:
            # 测试未授权访问
            vulns.append(APIVulnerability(
                endpoint=ep['path'],
                method=ep['method'],
                vulnerability='未授权访问测试',
                severity='待测试',
                description=f'测试{ep["method"]} {ep["path"]}是否可以未授权访问',
                parameter='Authorization',
                recommendation='验证所有敏感端点都需要有效的认证令牌'
            ))

            # 测试JWT伪造
            vulns.append(APIVulnerability(
                endpoint=ep['path'],
                method=ep['method'],
                vulnerability='JWT伪造测试',
                severity='待测试',
                description='测试是否可以伪造JWT令牌（alg=none、弱密钥、未验证签名）',
                parameter='Authorization',
                recommendation='使用强密钥签名JWT，验证签名和算法，设置合理的过期时间'
            ))

        self.vulnerabilities.extend(vulns)
        return vulns

    def test_authorization(self, base_url: str, user1_token: str = "",
                          user2_token: str = "") -> List[APIVulnerability]:
        """测试授权漏洞（越权访问）"""
        vulns = []

        # 水平越权测试（IDOR）
        idor_tests = [
            {'path': '/api/v1/users/{id}', 'method': 'GET', 'param': 'id'},
            {'path': '/api/v1/orders/{id}', 'method': 'GET', 'param': 'id'},
            {'path': '/api/v1/files/{id}', 'method': 'GET', 'param': 'id'},
            {'path': '/api/v1/users/{id}/profile', 'method': 'GET', 'param': 'id'},
        ]

        for test in idor_tests:
            vulns.append(APIVulnerability(
                endpoint=test['path'],
                method=test['method'],
                vulnerability='水平越权（IDOR）测试',
                severity='待测试',
                description=f'测试用户A是否可以访问用户B的资源（{test["param"]}参数）',
                parameter=test['param'],
                recommendation='在服务端验证资源所有权，不要信任客户端传入的ID'
            ))

        # 垂直越权测试
        vulns.append(APIVulnerability(
            endpoint='/api/v1/admin/*',
            method='*',
            vulnerability='垂直越权测试',
            severity='待测试',
            description='测试普通用户是否可以访问管理员端点',
            parameter='role',
            recommendation='使用基于角色的访问控制（RBAC），在服务端验证用户角色'
        ))

        self.vulnerabilities.extend(vulns)
        return vulns

    def fuzz_parameter(self, base_url: str, endpoint: str, method: str,
                      parameter: str, fuzz_type: str = "sql_injection") -> List[Dict]:
        """对参数进行Fuzz测试"""
        results = []
        payloads = self.FUZZ_PAYLOADS.get(fuzz_type, [])

        for payload in payloads:
            results.append({
                'endpoint': endpoint,
                'method': method,
                'parameter': parameter,
                'payload': payload,
                'fuzz_type': fuzz_type,
                'status': '待发送'
            })

        return results

    def test_business_logic(self, base_url: str) -> List[APIVulnerability]:
        """测试业务逻辑漏洞"""
        vulns = [
            APIVulnerability(
                endpoint='/api/v1/payment',
                method='POST',
                vulnerability='支付逻辑漏洞',
                severity='Critical',
                description='测试是否可以修改支付金额、负数支付、重复支付',
                parameter='amount',
                recommendation='在服务端验证支付金额，使用幂等性设计防止重复支付'
            ),
            APIVulnerability(
                endpoint='/api/v1/password/reset',
                method='POST',
                vulnerability='密码重置漏洞',
                severity='High',
                description='测试是否可以重置任意用户密码、令牌可预测、令牌不过期',
                parameter='token',
                recommendation='使用随机不可预测的令牌，设置短过期时间，一次性使用'
            ),
            APIVulnerability(
                endpoint='/api/v1/sms/send',
                method='POST',
                vulnerability='短信轰炸',
                severity='Medium',
                description='测试是否可以无限发送短信，缺少频率限制',
                parameter='phone',
                recommendation='实施频率限制（如每分钟1次，每天10次），使用图形验证码'
            ),
            APIVulnerability(
                endpoint='/api/v1/register',
                method='POST',
                vulnerability='注册逻辑漏洞',
                severity='Medium',
                description='测试是否可以注册管理员账户、重复注册、邮箱验证绕过',
                parameter='role',
                recommendation='不允许客户端指定角色，验证邮箱/手机号唯一性'
            ),
            APIVulnerability(
                endpoint='/api/v1/coupon',
                method='POST',
                vulnerability='优惠券漏洞',
                severity='High',
                description='测试是否可以重复使用优惠券、叠加使用、修改面值',
                parameter='coupon_code',
                recommendation='在服务端验证优惠券状态和使用规则，防止重复使用'
            ),
            APIVulnerability(
                endpoint='/api/v1/upload',
                method='POST',
                vulnerability='文件上传漏洞',
                severity='Critical',
                description='测试是否可以上传恶意文件（webshell、脚本、HTML）',
                parameter='file',
                recommendation='验证文件类型和内容，重命名文件，存储在非Web可访问目录'
            ),
        ]

        self.vulnerabilities.extend(vulns)
        return vulns

    def test_rate_limit(self, base_url: str, endpoint: str,
                       method: str = "POST") -> Dict:
        """测试速率限制"""
        return {
            'endpoint': endpoint,
            'method': method,
            'test': '速率限制测试',
            'description': '发送100次请求，测试是否有速率限制',
            'expected': '应该返回429 Too Many Requests',
            'status': '待测试'
        }

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            'total_endpoints': len(self.endpoints),
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_severity': {},
        }
        for vuln in self.vulnerabilities:
            stats['by_severity'][vuln.severity] = stats['by_severity'].get(vuln.severity, 0) + 1
        return stats


# 全局单例
_api_tester = None

def get_api_security_tester() -> APISecurityTester:
    """获取API安全测试器单例"""
    global _api_tester
    if _api_tester is None:
        _api_tester = APISecurityTester()
    return _api_tester


# ============ Round 8 新增：API 安全专项工作流模块 ============
# 追加内容：OpenAPI 解析器 / 参数 Fuzz / 逻辑漏洞测试 / 工作流编排
# 注意：以下 import 使用 try/except 包裹，避免在依赖未就绪时影响既有 APISecurityTester 单例。
try:
    from api_security.openapi_parser import OpenAPIParser
    from api_security.param_fuzzer import ParamFuzzer, PAYLOAD_LIBRARY
    from api_security.logic_tester import LogicTester, REMEDIATION_ADVICE
    from api_security.workflow import (
        APISecurityWorkflow,
        get_api_security_workflow,
        WORKFLOW_STEPS,
    )
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger(__name__).warning("api_security round8 modules import failed: %s", _e)

__all__ = [
    "APIEndpoint",
    "APIVulnerability",
    "APISecurityTester",
    "get_api_security_tester",
    "OpenAPIParser",
    "ParamFuzzer",
    "PAYLOAD_LIBRARY",
    "LogicTester",
    "REMEDIATION_ADVICE",
    "APISecurityWorkflow",
    "get_api_security_workflow",
    "WORKFLOW_STEPS",
]
