#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_security_tools模块，提供相关安全测试功能。

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
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

from utils.logger import log


@dataclass
class APIEndpoint:
    """API端点"""
    path: str
    method: str
    parameters: List[Dict[str, Any]]
    description: str = ""
    auth_required: bool = False
    responses: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "path": self.path,
            "method": self.method.upper(),
            "parameters": self.parameters,
            "description": self.description,
            "auth_required": self.auth_required,
            "responses": self.responses or {}
        }


class APISecurityTools:
    """API安全测试工具集"""

    # 常见敏感参数名
    SENSITIVE_PARAMS = ["password", "passwd", "pwd", "secret", "token", "apikey",
                         "api_key", "access_key", "private_key", "credit_card", "ssn",
                         "id_card", "phone", "mobile", "email"]

    # 常见fuzz payload
    FUZZ_PAYLOADS = {
        "sql_injection": ["'", '"', "1' OR '1'='1", "1; DROP TABLE users--",
                          "1 UNION SELECT NULL--", "admin'--"],
        "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "javascript:alert(1)", "<svg onload=alert(1)>"],
        "command_injection": ["; ls", "| whoami", "&& id", "`id`", "$(id)",
                              "; cat /etc/passwd"],
        "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                           "%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
        "ssrf": ["http://127.0.0.1", "http://localhost", "http://169.254.169.254/latest/meta-data/",
                 "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO"],
        "open_redirect": ["//evil.com", "/\\evil.com", "https://evil.com",
                          "javascript:alert(1)"],
        "nosql_injection": ["{\"$ne\": null}", "{\"$gt\": \"\"}", "admin' || '1'=='1"],
    }

    def __init__(self):
        """初始化APISecurityTools实例。

        Args:
            self: 类实例。
        """
        self.timeout = 10.0

    async def parse_openapi(self, url: str) -> Dict[str, Any]:
        """
        解析OpenAPI/Swagger文档，提取API端点
        :param url: OpenAPI文档URL（支持JSON/YAML）
        """
        log.info(f"解析OpenAPI文档: {url}")
        results = {
            "url": url,
            "endpoints": [],
            "total_endpoints": 0,
            "auth_methods": [],
            "sensitive_endpoints": [],
            "errors": []
        }

        try:
            # 下载文档
            response = await self._http_request(url)
            if response["status_code"] != 200:
                results["errors"].append(f"无法获取文档，HTTP状态: {response['status_code']}")
                return results

            spec = json.loads(response["body"])

            # 检测OpenAPI版本
            is_openapi3 = "openapi" in spec
            is_swagger2 = "swagger" in spec

            if not is_openapi3 and not is_swagger2:
                results["errors"].append("无法识别的API文档格式（需要OpenAPI 3.x或Swagger 2.0）")
                return results

            # 提取认证方式
            if is_openapi3:
                components = spec.get("components", {})
                security_schemes = components.get("securitySchemes", {})
                results["auth_methods"] = list(security_schemes.keys())
            else:
                security_defs = spec.get("securityDefinitions", {})
                results["auth_methods"] = list(security_defs.keys())

            # 提取端点
            paths = spec.get("paths", {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.lower() not in ("get", "post", "put", "delete", "patch", "head", "options"):
                        continue

                    parameters = details.get("parameters", [])
                    # OpenAPI 3.x的requestBody
                    if is_openapi3 and "requestBody" in details:
                        content = details["requestBody"].get("content", {})
                        for content_type, schema in content.items():
                            if "schema" in schema:
                                props = schema["schema"].get("properties", {})
                                for prop_name, prop_details in props.items():
                                    parameters.append({
                                        "name": prop_name,
                                        "in": "body",
                                        "required": prop_name in schema["schema"].get("required", []),
                                        "type": prop_details.get("type", "string"),
                                        "description": prop_details.get("description", "")
                                    })

                    endpoint = APIEndpoint(
                        path=path,
                        method=method,
                        parameters=parameters,
                        description=details.get("summary", details.get("description", "")),
                        auth_required=bool(details.get("security", spec.get("security", []))),
                        responses=details.get("responses", {})
                    )
                    results["endpoints"].append(endpoint.to_dict())

                    # 检测敏感端点
                    sensitive_keywords = ["admin", "user", "password", "token", "secret",
                                          "config", "backup", "debug", "internal", "private"]
                    if any(kw in path.lower() for kw in sensitive_keywords):
                        results["sensitive_endpoints"].append(endpoint.to_dict())

            results["total_endpoints"] = len(results["endpoints"])
            log.info(f"OpenAPI解析完成: {results['total_endpoints']}个端点, {len(results['sensitive_endpoints'])}个敏感端点")

        except json.JSONDecodeError as e:
            results["errors"].append(f"JSON解析失败: {str(e)}")
        except Exception as e:
            results["errors"].append(f"解析失败: {str(e)}")
            log.error(f"OpenAPI解析失败: {e}")

        return results

    async def parameter_fuzz(self, target_url: str, param_name: str, fuzz_type: str = "all",
                             method: str = "GET", headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        参数fuzz测试
        :param target_url: 目标URL
        :param param_name: 要fuzz的参数名
        :param fuzz_type: fuzz类型 sql_injection/xss/command_injection/path_traversal/ssrf/open_redirect/nosql_injection/all
        :param method: HTTP方法
        :param headers: 自定义请求头
        """
        log.info(f"参数fuzz: {target_url}, 参数: {param_name}, 类型: {fuzz_type}")
        results = {
            "target_url": target_url,
            "param_name": param_name,
            "fuzz_type": fuzz_type,
            "total_tests": 0,
            "findings": [],
            "errors": []
        }

        # 选择payload
        if fuzz_type == "all":
            payloads = []
            for p in self.FUZZ_PAYLOADS.values():
                payloads.extend(p)
        else:
            payloads = self.FUZZ_PAYLOADS.get(fuzz_type, [])

        if not payloads:
            results["errors"].append(f"未知的fuzz类型: {fuzz_type}")
            return results

        # 基线请求（正常参数值）
        baseline = await self._http_request(target_url, method, {param_name: "test"}, headers)
        baseline_status = baseline["status_code"]
        baseline_length = len(baseline["body"])

        results["baseline"] = {
            "status_code": baseline_status,
            "response_length": baseline_length
        }

        # fuzz测试
        for payload in payloads:
            try:
                response = await self._http_request(target_url, method, {param_name: payload}, headers)
                results["total_tests"] += 1

                # 异常检测
                anomalies = []
                if response["status_code"] >= 500:
                    anomalies.append(f"服务器错误 (HTTP {response['status_code']})")
                if response["status_code"] != baseline_status and response["status_code"] not in (404, 403):
                    anomalies.append(f"状态码变化: {baseline_status} -> {response['status_code']}")
                if abs(len(response["body"]) - baseline_length) > baseline_length * 0.5 and baseline_length > 100:
                    anomalies.append(f"响应长度显著变化: {baseline_length} -> {len(response['body'])}")

                # 错误信息检测
                error_patterns = ["sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite3.",
                                  "warning: mysql", "unclosed quotation", "stack trace", "traceback",
                                  "exception", "nullpointer", "internal server error"]
                body_lower = response["body"].lower()
                for pattern in error_patterns:
                    if pattern in body_lower:
                        anomalies.append(f"检测到错误信息: {pattern}")
                        break

                if anomalies:
                    results["findings"].append({
                        "payload": payload,
                        "status_code": response["status_code"],
                        "response_length": len(response["body"]),
                        "anomalies": anomalies,
                        "severity": "high" if response["status_code"] >= 500 or any("sql" in a.lower() for a in anomalies) else "medium"
                    })

            except Exception as e:
                results["errors"].append(f"Payload '{payload[:30]}' 测试失败: {str(e)}")

        log.info(f"参数fuzz完成: {results['total_tests']}个测试, {len(results['findings'])}个发现")
        return results

    async def test_broken_object_level_authorization(self, target_url: str, param_name: str = "id",
                                                       start_id: int = 1, end_id: int = 10,
                                                       headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        测试BOLA（Broken Object Level Authorization，即IDOR）
        OWASP API Security Top 10 #1
        """
        log.info(f"BOLA/IDOR测试: {target_url}, 参数: {param_name}, 范围: {start_id}-{end_id}")
        results = {
            "target_url": target_url,
            "param_name": param_name,
            "tested_ids": [],
            "accessible_ids": [],
            "vulnerable": False,
            "details": []
        }

        for obj_id in range(start_id, end_id + 1):
            try:
                url = f"{target_url}?{param_name}={obj_id}"
                response = await self._http_request(url, "GET", headers=headers)
                results["tested_ids"].append(obj_id)

                if response["status_code"] == 200 and len(response["body"]) > 50:
                    # 检测是否返回了其他用户的数据
                    data_found = False
                    try:
                        data = json.loads(response["body"])
                        if isinstance(data, dict) and any(k in data for k in ("id", "user_id", "email", "name", "username")):
                            data_found = True
                    except json.JSONDecodeError:
                        if any(kw in response["body"].lower() for kw in ["email", "username", "user_id", "phone"]):
                            data_found = True

                    if data_found:
                        results["accessible_ids"].append(obj_id)
                        results["details"].append({
                            "id": obj_id,
                            "status_code": response["status_code"],
                            "response_length": len(response["body"]),
                            "data_leaked": True
                        })

            except Exception as e:
                results["details"].append({"id": obj_id, "error": str(e)})

        results["vulnerable"] = len(results["accessible_ids"]) > 1
        if results["vulnerable"]:
            results["severity"] = "high"
            results["description"] = f"存在BOLA/IDOR漏洞，可访问 {len(results['accessible_ids'])} 个对象的数据"
        else:
            results["severity"] = "info"
            results["description"] = "未检测到明显的BOLA/IDOR漏洞"

        log.info(f"BOLA测试完成: 脆弱={results['vulnerable']}, 可访问ID数={len(results['accessible_ids'])}")
        return results

    async def test_mass_assignment(self, target_url: str, method: str = "POST",
                                    headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        测试批量赋值（Mass Assignment）漏洞
        OWASP API Security Top 10 #6
        """
        log.info(f"批量赋值测试: {target_url}")
        results = {
            "target_url": target_url,
            "method": method,
            "tested_params": [],
            "vulnerable": False,
            "findings": []
        }

        # 常见的敏感参数，尝试在请求中添加这些参数
        sensitive_params = ["is_admin", "admin", "role", "is_active", "activated",
                            "email_verified", "verified", "balance", "money", "credits",
                            "points", "level", "vip", "is_vip", "permissions", "access_level"]

        for param in sensitive_params:
            try:
                # 基线请求
                baseline = await self._http_request(target_url, method, {}, headers)

                # 添加敏感参数
                test_data = {param: "true" if param.startswith("is_") or param in ("admin", "activated", "verified", "vip") else "999999"}
                test_response = await self._http_request(target_url, method, test_data, headers)

                results["tested_params"].append(param)

                # 检测异常
                if test_response["status_code"] == 200 and baseline["status_code"] == 200:
                    if test_response["body"] != baseline["body"]:
                        results["findings"].append({
                            "parameter": param,
                            "value": test_data[param],
                            "status_code": test_response["status_code"],
                            "response_changed": True,
                            "severity": "medium"
                        })

            except Exception as e:
                results["findings"].append({"parameter": param, "error": str(e)})

        results["vulnerable"] = len(results["findings"]) > 0
        log.info(f"批量赋值测试完成: 脆弱={results['vulnerable']}, 发现={len(results['findings'])}")
        return results

    async def detect_sensitive_info_leak(self, target_url: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        检测API敏感信息泄露
        """
        log.info(f"敏感信息泄露检测: {target_url}")
        results = {
            "target_url": target_url,
            "leaked_info": [],
            "vulnerable": False
        }

        try:
            response = await self._http_request(target_url, "GET", headers=headers)
            body = response["body"]
            headers_resp = response.get("headers", {})

            # 检测API密钥泄露
            api_key_patterns = [
                (r'(?i)api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', "API Key"),
                (r'(?i)secret["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', "Secret"),
                (r'(?i)token["\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})', "Token"),
                (r'(?i)password["\s:=]+["\']?([^\s"\'<>]{6,})', "Password"),
                (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
                (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', "Private Key"),
                (r'Bearer\s+[a-zA-Z0-9_\-\.]+', "Bearer Token"),
            ]

            for pattern, leak_type in api_key_patterns:
                matches = re.findall(pattern, body)
                if matches:
                    results["leaked_info"].append({
                        "type": leak_type,
                        "count": len(matches),
                        "sample": str(matches[0])[:50] if matches else ""
                    })

            # 检测响应头中的敏感信息
            sensitive_headers = ["x-powered-by", "server", "x-aspnet-version", "x-php-version",
                                 "access-control-allow-origin", "x-amz-request-id"]
            for header in sensitive_headers:
                if header in headers_resp:
                    results["leaked_info"].append({
                        "type": f"Header: {header}",
                        "value": str(headers_resp[header])[:100]
                    })

            # 检测堆栈跟踪
            if any(kw in body.lower() for kw in ["stack trace", "traceback", "at line", "exception in"]):
                results["leaked_info"].append({"type": "Stack Trace", "description": "响应中包含堆栈跟踪信息"})

            results["vulnerable"] = len(results["leaked_info"]) > 0
            results["status_code"] = response["status_code"]

        except Exception as e:
            results["error"] = str(e)

        log.info(f"敏感信息泄露检测完成: 泄露类型={len(results['leaked_info'])}")
        return results

    async def _http_request(self, url: str, method: str = "GET",
                             data: Dict[str, Any] = None,
                             headers: Dict[str, str] = None) -> Dict[str, Any]:
        """发送HTTP请求"""
        try:
            req_headers = headers or {}
            req_headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

            if method.upper() == "GET" and data:
                query_string = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in data.items())
                url = f"{url}{'&' if '?' in url else '?'}{query_string}"
                req = urllib.request.Request(url, headers=req_headers, method="GET")
            else:
                req_data = json.dumps(data).encode("utf-8") if data else None
                if req_data:
                    req_headers["Content-Type"] = "application/json"
                req = urllib.request.Request(url, data=req_data, headers=req_headers, method=method.upper())

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                return {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                    "url": response.url
                }
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            return {
                "status_code": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": body,
                "error": str(e)
            }
        except Exception as e:
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "error": str(e)
            }


# 全局实例
api_security_tools = APISecurityTools()
