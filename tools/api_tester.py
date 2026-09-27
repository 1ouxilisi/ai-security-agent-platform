"""
api_tester安全工具集成模块，提供相关安全工具的封装和调用。

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
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.logger import log


class APITester:
    """API安全测试器 - REST API/GraphQL/OpenAPI全面测试"""

    def __init__(self):
        """初始化APITester实例。

        Args:
            self: 类实例。
        """
        self._common_api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/graphiql",
            "/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs",
            "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/openapi.yaml",
            "/admin", "/admin/api", "/internal", "/debug", "/actuator",
            "/health", "/status", "/metrics", "/env", "/config",
            "/users", "/user", "/accounts", "/auth", "/login", "/register",
            "/tokens", "/token", "/keys", "/key", "/secrets", "/secret",
            "/backup", "/exports", "/import", "/upload", "/download",
            "/webhooks", "/webhook", "/callbacks", "/callback",
            "/graphql/explorer", "/playground", "/altair",
        ]
        log.info("✅ API安全测试器初始化成功")

    # ========== OpenAPI/Swagger解析 ==========

    def parse_openapi(self, spec: Dict[str, Any]) -> Dict:
        """解析OpenAPI/Swagger规范，提取端点和安全信息"""
        result = {
            "valid_spec": False,
            "version": None,
            "title": None,
            "description": None,
            "endpoints": [],
            "security_schemes": {},
            "global_security": [],
            "issues": [],
            "recommendations": [],
            "stats": {},
        }

        try:
            # 检测版本
            if "openapi" in spec:
                result["version"] = f"OpenAPI {spec['openapi']}"
            elif "swagger" in spec:
                result["version"] = f"Swagger {spec['swagger']}"
            else:
                result["issues"].append({"severity": "high", "description": "无法识别API规范版本"})
                return result

            result["valid_spec"] = True

            # 基本信息
            info = spec.get("info", {})
            result["title"] = info.get("title", "Unknown")
            result["description"] = info.get("description", "")

            # 安全方案
            components = spec.get("components", {})
            security_schemes = components.get("securitySchemes", {})
            result["security_schemes"] = security_schemes

            if not security_schemes:
                result["issues"].append({
                    "severity": "high",
                    "description": "API未定义任何安全认证方案",
                    "cwe": "CWE-306",
                })
                result["recommendations"].append("定义安全认证方案（如Bearer JWT、OAuth2、API Key）")

            # 检查安全方案强度
            for name, scheme in security_schemes.items():
                scheme_type = scheme.get("type", "")
                if scheme_type == "apiKey":
                    if scheme.get("in") == "query":
                        result["issues"].append({
                            "severity": "medium",
                            "description": f"API Key '{name}'通过URL查询参数传递，可能被日志记录",
                            "cwe": "CWE-598",
                        })
                        result["recommendations"].append("使用Authorization头传递API Key")
                elif scheme_type == "http":
                    if scheme.get("scheme") == "basic":
                        result["issues"].append({
                            "severity": "medium",
                            "description": f"使用HTTP Basic认证（{name}），安全性较弱",
                            "cwe": "CWE-522",
                        })
                        result["recommendations"].append("使用Bearer Token（JWT）替代Basic认证")

            # 全局安全要求
            result["global_security"] = spec.get("security", [])
            if not result["global_security"]:
                result["issues"].append({
                    "severity": "high",
                    "description": "API未定义全局安全要求，端点可能未受保护",
                    "cwe": "CWE-306",
                })

            # 解析端点
            paths = spec.get("paths", {})
            endpoints = []
            methods_without_security = 0
            sensitive_endpoints = []

            for path, path_item in paths.items():
                for method, operation in path_item.items():
                    if method.lower() not in ["get", "post", "put", "delete", "patch", "head", "options"]:
                        continue

                    endpoint = {
                        "path": path,
                        "method": method.upper(),
                        "summary": operation.get("summary", ""),
                        "description": operation.get("description", ""),
                        "tags": operation.get("tags", []),
                        "parameters": operation.get("parameters", []),
                        "request_body": operation.get("requestBody", {}),
                        "responses": operation.get("responses", {}),
                        "security": operation.get("security", []),
                        "deprecated": operation.get("deprecated", False),
                    }
                    endpoints.append(endpoint)

                    # 检查端点级安全
                    if not endpoint["security"] and not result["global_security"]:
                        methods_without_security += 1
                        if method.upper() in ["POST", "PUT", "DELETE", "PATCH"]:
                            sensitive_endpoints.append(endpoint)

                    # 检查废弃端点
                    if endpoint["deprecated"]:
                        result["issues"].append({
                            "severity": "low",
                            "description": f"端点已废弃: {method.upper()} {path}",
                        })

                    # 检查参数
                    for param in endpoint["parameters"]:
                        if param.get("in") == "query" and param.get("name", "").lower() in ["password", "token", "secret", "key", "api_key"]:
                            result["issues"].append({
                                "severity": "high",
                                "description": f"敏感参数通过URL传递: {param['name']} in {method.upper()} {path}",
                                "cwe": "CWE-598",
                            })

            result["endpoints"] = endpoints
            result["stats"] = {
                "total_endpoints": len(endpoints),
                "total_paths": len(paths),
                "methods_without_security": methods_without_security,
                "sensitive_unprotected_endpoints": len(sensitive_endpoints),
                "deprecated_endpoints": sum(1 for e in endpoints if e["deprecated"]),
            }

            if methods_without_security > 0:
                result["issues"].append({
                    "severity": "high",
                    "description": f"{methods_without_security}个端点未定义安全要求",
                    "cwe": "CWE-306",
                })

            if sensitive_endpoints:
                result["issues"].append({
                    "severity": "critical",
                    "description": f"{len(sensitive_endpoints)}个写操作端点未受保护",
                    "cwe": "CWE-306",
                    "endpoints": [f"{e['method']} {e['path']}" for e in sensitive_endpoints[:10]],
                })

            # 检查响应中是否泄露敏感信息
            for endpoint in endpoints:
                responses = endpoint.get("responses", {})
                for status, response in responses.items():
                    content = response.get("content", {})
                    for content_type, schema in content.items():
                        schema_ref = schema.get("schema", {}).get("$ref", "")
                        if any(s in schema_ref.lower() for s in ["user", "account", "profile"]):
                            result["issues"].append({
                                "severity": "info",
                                "description": f"端点可能返回用户敏感信息: {endpoint['method']} {endpoint['path']} -> {status}",
                            })

            # 风险评分
            critical_count = sum(1 for i in result["issues"] if i["severity"] == "critical")
            high_count = sum(1 for i in result["issues"] if i["severity"] == "high")
            medium_count = sum(1 for i in result["issues"] if i["severity"] == "medium")

            risk_score = min(100, critical_count * 25 + high_count * 15 + medium_count * 8)
            result["risk_score"] = risk_score
            result["risk_level"] = "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low"

        except Exception as e:
            result["issues"].append({"severity": "high", "description": f"OpenAPI解析失败: {e}"})

        return result

    def discover_api_endpoints(self, base_url: str) -> List[str]:
        """发现常见API端点路径"""
        discovered = []
        parsed = urlparse(base_url)
        base_path = parsed.path.rstrip("/")

        for path in self._common_api_paths:
            full_path = f"{base_path}{path}" if base_path else path
            discovered.append(full_path)

        # 去重并排序
        return sorted(list(set(discovered)))

    # ========== GraphQL测试 ==========

    def analyze_graphql_schema(self, schema: Dict[str, Any]) -> Dict:
        """分析GraphQL Schema安全性"""
        result = {
            "valid_schema": False,
            "types": [],
            "queries": [],
            "mutations": [],
            "subscriptions": [],
            "issues": [],
            "recommendations": [],
            "stats": {},
        }

        try:
            data = schema.get("data", schema)
            schema_data = data.get("__schema", {})

            if not schema_data:
                result["issues"].append({"severity": "high", "description": "无效的GraphQL Schema"})
                return result

            result["valid_schema"] = True

            # 提取类型
            types = schema_data.get("types", [])
            result["types"] = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")]

            # 提取Query
            query_type = schema_data.get("queryType", {})
            if query_type:
                query_name = query_type.get("name", "Query")
                for t in types:
                    if t.get("name") == query_name:
                        result["queries"] = [f.get("name", "") for f in t.get("fields", [])]
                        break

            # 提取Mutation
            mutation_type = schema_data.get("mutationType", {})
            if mutation_type:
                mutation_name = mutation_type.get("name", "Mutation")
                for t in types:
                    if t.get("name") == mutation_name:
                        result["mutations"] = [f.get("name", "") for f in t.get("fields", [])]
                        break

            # 提取Subscription
            subscription_type = schema_data.get("subscriptionType", {})
            if subscription_type:
                subscription_name = subscription_type.get("name", "Subscription")
                for t in types:
                    if t.get("name") == subscription_name:
                        result["subscriptions"] = [f.get("name", "") for f in t.get("fields", [])]
                        break

            # 安全检查
            # 1. 内省查询是否启用
            result["issues"].append({
                "severity": "info",
                "description": "GraphQL内省查询已启用（可获取完整Schema）",
            })
            result["recommendations"].append("生产环境考虑禁用内省查询")

            # 2. 检查敏感操作
            sensitive_mutations = []
            for mutation in result["mutations"]:
                if any(k in mutation.lower() for k in ["delete", "remove", "admin", "reset", "password", "token", "key", "secret"]):
                    sensitive_mutations.append(mutation)

            if sensitive_mutations:
                result["issues"].append({
                    "severity": "high",
                    "description": f"发现{len(sensitive_mutations)}个敏感Mutation操作",
                    "mutations": sensitive_mutations,
                })

            # 3. 检查敏感查询
            sensitive_queries = []
            for query in result["queries"]:
                if any(k in query.lower() for k in ["admin", "internal", "debug", "secret", "token", "key", "user", "all"]):
                    sensitive_queries.append(query)

            if sensitive_queries:
                result["issues"].append({
                    "severity": "medium",
                    "description": f"发现{len(sensitive_queries)}个可能敏感的Query",
                    "queries": sensitive_queries,
                })

            # 4. 检查是否有认证相关类型
            auth_types = [t for t in result["types"] if any(k in t.lower() for k in ["auth", "login", "token", "session", "user"])]
            if auth_types:
                result["issues"].append({
                    "severity": "info",
                    "description": f"发现{len(auth_types)}个认证相关类型",
                    "types": auth_types,
                })

            result["stats"] = {
                "total_types": len(result["types"]),
                "total_queries": len(result["queries"]),
                "total_mutations": len(result["mutations"]),
                "total_subscriptions": len(result["subscriptions"]),
                "sensitive_mutations": len(sensitive_mutations),
                "sensitive_queries": len(sensitive_queries),
            }

            # 风险评分
            critical_count = sum(1 for i in result["issues"] if i["severity"] == "critical")
            high_count = sum(1 for i in result["issues"] if i["severity"] == "high")
            medium_count = sum(1 for i in result["issues"] if i["severity"] == "medium")

            risk_score = min(100, critical_count * 25 + high_count * 15 + medium_count * 8)
            result["risk_score"] = risk_score
            result["risk_level"] = "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low"

        except Exception as e:
            result["issues"].append({"severity": "high", "description": f"GraphQL Schema分析失败: {e}"})

        return result

    def generate_graphql_introspection_query(self) -> str:
        """生成GraphQL内省查询"""
        return """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type { name kind ofType { name kind } }
        }
        type { name kind ofType { name kind } }
      }
    }
  }
}
""".strip()

    def generate_graphql_batched_queries(self, base_query: str, count: int = 10) -> str:
        """生成批量查询（DoS测试）"""
        queries = []
        for i in range(count):
            alias = re.sub(r'[^a-zA-Z0-9]', '_', base_query.strip())[:30]
            queries.append(f"{alias}_{i}: {base_query}")
        return "{\n  " + "\n  ".join(queries) + "\n}"

    def generate_graphql_deep_nested_query(self, field_name: str, depth: int = 10) -> str:
        """生成深度嵌套查询（DoS测试）"""
        nested = field_name
        for i in range(depth):
            nested = f"{field_name} {{ {nested} }}"
        return f"{{ {nested} }}"

    # ========== REST API测试 ==========

    def generate_rest_api_injection_tests(self, endpoint: str, params: Dict[str, str]) -> List[Dict]:
        """生成REST API参数注入测试"""
        tests = []

        # SQL注入payload
        sql_payloads = ["'", "\"", "' OR '1'='1", "' AND '1'='2", "1' ORDER BY 1--", "1 UNION SELECT NULL--", "1 AND SLEEP(5)--"]
        for param, value in params.items():
            for payload in sql_payloads:
                tests.append({
                    "param": param,
                    "original_value": value,
                    "payload": payload,
                    "type": "sql_injection",
                    "url": self._inject_param(endpoint, param, payload),
                })

        # XSS payload
        xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"'><script>alert(1)</script>"]
        for param, value in params.items():
            for payload in xss_payloads:
                tests.append({
                    "param": param,
                    "original_value": value,
                    "payload": payload,
                    "type": "xss",
                    "url": self._inject_param(endpoint, param, payload),
                })

        # 命令注入
        cmd_payloads = ["; id", "&& id", "| id", "`id`", "$(id)"]
        for param, value in params.items():
            for payload in cmd_payloads:
                tests.append({
                    "param": param,
                    "original_value": value,
                    "payload": payload,
                    "type": "command_injection",
                    "url": self._inject_param(endpoint, param, payload),
                })

        return tests

    def generate_api_fuzzing_tests(self, endpoint: str, params: Dict[str, str]) -> List[Dict]:
        """生成API模糊测试用例"""
        tests = []

        for param, value in params.items():
            # 类型混淆
            fuzz_values = [
                "null", "undefined", "NaN", "Infinity",
                "true", "false",
                "[]", "{}", "[1,2,3]", '{"key":"value"}',
                "", " ", "\t", "\n", "\r\n",
                "0", "-1", "99999999999999999999",
                "a" * 100, "a" * 1000,
                "<script>alert(1)</script>",
                "' OR '1'='1",
                "../../../../etc/passwd",
            ]

            for fuzz_value in fuzz_values:
                tests.append({
                    "param": param,
                    "original_value": value,
                    "fuzz_value": fuzz_value,
                    "url": self._inject_param(endpoint, param, fuzz_value),
                })

        return tests

    def check_api_security_headers(self, headers: Dict[str, str]) -> Dict:
        """检查API安全响应头"""
        security_headers = {
            "Content-Security-Policy": {"required": True, "description": "内容安全策略"},
            "X-Content-Type-Options": {"required": True, "expected": "nosniff", "description": "MIME类型嗅探保护"},
            "X-Frame-Options": {"required": True, "expected": ["DENY", "SAMEORIGIN"], "description": "点击劫持保护"},
            "Strict-Transport-Security": {"required": True, "description": "HTTPS强制"},
            "X-XSS-Protection": {"required": False, "description": "XSS过滤（已废弃但仍有用）"},
            "Referrer-Policy": {"required": False, "description": "Referrer策略"},
            "Permissions-Policy": {"required": False, "description": "权限策略"},
            "Cache-Control": {"required": False, "description": "缓存控制（敏感数据应no-store）"},
        }

        result = {
            "headers_present": [],
            "headers_missing": [],
            "headers_misconfigured": [],
            "issues": [],
            "recommendations": [],
        }

        for header_name, config in security_headers.items():
            header_value = headers.get(header_name) or headers.get(header_name.lower())

            if header_value:
                result["headers_present"].append({"name": header_name, "value": header_value})

                # 检查期望值
                if "expected" in config:
                    expected = config["expected"]
                    if isinstance(expected, list):
                        if not any(e.lower() in header_value.lower() for e in expected):
                            result["headers_misconfigured"].append({
                                "name": header_name,
                                "current": header_value,
                                "expected": expected,
                            })
                    else:
                        if expected.lower() not in header_value.lower():
                            result["headers_misconfigured"].append({
                                "name": header_name,
                                "current": header_value,
                                "expected": expected,
                            })
            else:
                result["headers_missing"].append({"name": header_name, "description": config["description"]})
                if config["required"]:
                    result["issues"].append({
                        "severity": "medium",
                        "description": f"缺少安全响应头: {header_name} ({config['description']})",
                    })
                    result["recommendations"].append(f"添加{header_name}响应头")

        return result

    # ========== 辅助方法 ==========

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        """在URL参数中注入值"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            query_params[param] = [value]
            new_query = urlencode(query_params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        except:
            separator = "&" if "?" in url else "?"
            return f"{url}{separator}{param}={value}"

    async def comprehensive_api_test(self, base_url: str, openapi_spec: Optional[Dict] = None) -> Dict:
        """综合API安全测试"""
        result = {
            "base_url": base_url,
            "openapi_analysis": None,
            "endpoint_discovery": [],
            "security_headers": None,
            "issues": [],
            "summary": "",
        }

        # 1. OpenAPI分析
        if openapi_spec:
            result["openapi_analysis"] = self.parse_openapi(openapi_spec)
            if result["openapi_analysis"]["issues"]:
                result["issues"].extend(result["openapi_analysis"]["issues"])

        # 2. 端点发现
        result["endpoint_discovery"] = self.discover_api_endpoints(base_url)

        # 3. 安全头检查（需要实际请求）
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(base_url, timeout=10) as resp:
                    result["security_headers"] = self.check_api_security_headers(dict(resp.headers))
                    if result["security_headers"]["issues"]:
                        result["issues"].extend(result["security_headers"]["issues"])
        except ImportError:
            result["summary"] = "aiohttp未安装，跳过安全头检查"
        except Exception as e:
            result["summary"] = f"安全头检查失败: {e}"

        # 汇总
        high_count = sum(1 for i in result["issues"] if i["severity"] in ["high", "critical"])
        result["summary"] = f"综合API测试完成，发现{len(result['issues'])}个问题（{high_count}个高危），发现{len(result['endpoint_discovery'])}个潜在端点"

        return result


# 全局单例
api_tester = APITester()
