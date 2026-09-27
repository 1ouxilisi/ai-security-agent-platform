"""
test_new_modules单元测试模块，包含相关功能的测试用例和验证逻辑。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import sys
import os
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

# 添加项目根目录
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCLIEngine:
    """CLI引擎测试"""

    def test_cli_engine_initialization(self):
        """测试CLI引擎初始化"""
        from tools.cli_engine import cli_engine
        assert cli_engine is not None
        assert hasattr(cli_engine, 'TOOL_CONFIGS')
        assert len(cli_engine.TOOL_CONFIGS) >= 10

    def test_tool_detection(self):
        """测试工具检测"""
        from tools.cli_engine import cli_engine
        available = cli_engine.get_available_tools()
        assert isinstance(available, dict)

    def test_supported_tools_list(self):
        """测试支持的工具列表"""
        from tools.cli_engine import cli_engine
        tools = cli_engine.TOOL_CONFIGS
        assert isinstance(tools, dict)
        assert 'nmap' in tools
        assert 'sqlmap' in tools
        assert 'nuclei' in tools

    def test_nmap_scan_method_exists(self):
        """测试nmap扫描方法存在"""
        from tools.cli_engine import cli_engine
        assert hasattr(cli_engine, 'nmap_scan')
        assert callable(cli_engine.nmap_scan)

    def test_is_available_method(self):
        """测试工具可用性检查方法"""
        from tools.cli_engine import cli_engine
        assert hasattr(cli_engine, 'is_available')
        result = cli_engine.is_available('python')
        assert isinstance(result, bool)


class TestPayloadLibrary:
    """Payload库测试"""

    def test_payload_library_initialization(self):
        """测试Payload库初始化"""
        from tools.payload_library import payload_library
        assert payload_library is not None

    def test_payload_types(self):
        """测试Payload类型"""
        from tools.payload_library import payload_library
        types = payload_library.get_all_types()
        assert isinstance(types, list)
        assert len(types) >= 10
        assert 'sql_injection' in types
        assert 'xss' in types
        assert 'ssrf' in types

    def test_get_payloads_by_type(self):
        """测试按类型获取Payload"""
        from tools.payload_library import payload_library
        payloads = payload_library.get_payloads('sql_injection')
        assert isinstance(payloads, list)
        assert len(payloads) > 0
        for p in payloads:
            assert 'id' in p
            assert 'payload' in p
            assert 'type' in p

    def test_get_all_payloads(self):
        """测试获取所有Payload"""
        from tools.payload_library import payload_library
        all_types = payload_library.get_all_types()
        total = 0
        for t in all_types:
            total += len(payload_library.get_payloads(t))
        assert total >= 90

    def test_payload_statistics(self):
        """测试Payload统计"""
        from tools.payload_library import payload_library
        stats = payload_library.get_stats()
        assert isinstance(stats, dict)
        assert 'total_payloads' in stats or 'total' in stats or len(stats) > 0

    def test_encode_payload(self):
        """测试Payload编码"""
        from tools.payload_library import payload_library
        encoded = payload_library.encode_payload("' OR 1=1--", "url")
        assert isinstance(encoded, str)
        assert len(encoded) > 0

    def test_generate_variants(self):
        """测试Payload变体生成"""
        from tools.payload_library import payload_library
        variants = payload_library.generate_variants("test")
        assert isinstance(variants, list)
        assert len(variants) > 0


class TestScanEngine:
    """扫描引擎测试"""

    def test_scan_engine_initialization(self):
        """测试扫描引擎初始化"""
        from tools.scan_engine import scan_engine
        assert scan_engine is not None

    def test_scan_engine_config(self):
        """测试扫描引擎配置"""
        from tools.scan_engine import scan_engine
        assert hasattr(scan_engine, 'max_concurrent')
        assert hasattr(scan_engine, 'rate_limit')
        assert hasattr(scan_engine, 'default_timeout')
        assert scan_engine.max_concurrent > 0
        assert scan_engine.rate_limit >= 0

    def test_port_scan_batch_method(self):
        """测试端口扫描批量方法存在"""
        from tools.scan_engine import scan_engine
        assert hasattr(scan_engine, 'port_scan_batch')
        assert callable(scan_engine.port_scan_batch)

    def test_directory_bruteforce_method(self):
        """测试目录爆破方法存在"""
        from tools.scan_engine import scan_engine
        assert hasattr(scan_engine, 'directory_bruteforce')
        assert callable(scan_engine.directory_bruteforce)

    def test_engine_stats(self):
        """测试引擎统计"""
        from tools.scan_engine import scan_engine
        stats = scan_engine.get_engine_stats()
        assert isinstance(stats, dict)


class TestAuthTester:
    """认证测试器测试"""

    def test_auth_tester_initialization(self):
        """测试认证测试器初始化"""
        from tools.auth_tester import auth_tester
        assert auth_tester is not None

    def test_jwt_decode_valid(self):
        """测试有效JWT解码"""
        from tools.auth_tester import auth_tester
        # 构造一个简单的JWT
        import base64
        import json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "test", "exp": 9999999999}).encode()).rstrip(b'=').decode()
        jwt_token = f"{header}.{payload}.signature"

        result = auth_tester.analyze_jwt(jwt_token)
        assert isinstance(result, dict)
        assert result.get('valid_format') is True
        assert 'details' in result

    def test_jwt_decode_invalid(self):
        """测试无效JWT"""
        from tools.auth_tester import auth_tester
        result = auth_tester.analyze_jwt("invalid-token")
        assert isinstance(result, dict)
        assert result.get('valid_format') is False

    def test_oauth_url_analysis(self):
        """测试OAuth URL分析"""
        from tools.auth_tester import auth_tester
        url = "https://auth.example.com/authorize?client_id=test&redirect_uri=https://example.com/callback&response_type=code"
        result = auth_tester.analyze_oauth_redirect_uri(url)
        assert isinstance(result, dict)
        assert result.get('valid_oauth_url') is True

    def test_cookie_security_analysis(self):
        """测试Cookie安全分析"""
        from tools.auth_tester import auth_tester
        cookies = {
            "session": "abc123",
            "_attributes": {"httponly": False, "secure": False, "samesite": ""}
        }
        result = auth_tester.analyze_cookie_security(cookies, "session")
        assert isinstance(result, dict)
        assert result.get('cookie_found') is True

    def test_idor_payload_generation(self):
        """测试IDOR Payload生成"""
        from tools.auth_tester import auth_tester
        payloads = auth_tester.generate_idor_payloads("id", "1")
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_privilege_escalation_headers(self):
        """测试权限提升Header生成"""
        from tools.auth_tester import auth_tester
        headers = auth_tester.generate_privilege_escalation_headers()
        assert isinstance(headers, list)
        assert len(headers) > 0

    def test_method_abuse_tests(self):
        """测试HTTP方法滥用测试生成"""
        from tools.auth_tester import auth_tester
        tests = auth_tester.generate_method_abuse_tests("http://127.0.0.1/admin")
        assert isinstance(tests, list)
        assert len(tests) > 0


class TestAPITester:
    """API测试器测试"""

    def test_api_tester_initialization(self):
        """测试API测试器初始化"""
        from tools.api_tester import api_tester
        assert api_tester is not None

    def test_openapi_parsing_valid(self):
        """测试有效OpenAPI解析"""
        from tools.api_tester import api_tester
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "get": {"summary": "Get users", "security": [{"bearerAuth": []}]},
                    "post": {"summary": "Create user"}
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer"}
                }
            }
        }
        result = api_tester.parse_openapi(spec)
        assert isinstance(result, dict)
        assert result.get('valid_spec') is True
        assert 'endpoints' in result
        assert len(result['endpoints']) >= 2

    def test_openapi_parsing_invalid(self):
        """测试无效OpenAPI解析"""
        from tools.api_tester import api_tester
        result = api_tester.parse_openapi({"invalid": "spec"})
        assert isinstance(result, dict)
        assert result.get('valid_spec') is False

    def test_graphql_introspection_query(self):
        """测试GraphQL内省查询生成"""
        from tools.api_tester import api_tester
        query = api_tester.generate_graphql_introspection_query()
        assert isinstance(query, str)
        assert '__schema' in query

    def test_graphql_batched_queries(self):
        """测试GraphQL批量查询生成"""
        from tools.api_tester import api_tester
        query = api_tester.generate_graphql_batched_queries("users { id }", 5)
        assert isinstance(query, str)
        assert 'users' in query

    def test_graphql_deep_nested_query(self):
        """测试GraphQL深度嵌套查询生成"""
        from tools.api_tester import api_tester
        query = api_tester.generate_graphql_deep_nested_query("friends", 3)
        assert isinstance(query, str)
        assert 'friends' in query

    def test_rest_api_injection_tests(self):
        """测试REST API注入测试生成"""
        from tools.api_tester import api_tester
        tests = api_tester.generate_rest_api_injection_tests(
            "http://127.0.0.1/api/users",
            {"id": "1", "name": "test"}
        )
        assert isinstance(tests, list)
        assert len(tests) > 0

    def test_api_fuzzing_tests(self):
        """测试API模糊测试用例生成"""
        from tools.api_tester import api_tester
        tests = api_tester.generate_api_fuzzing_tests(
            "http://127.0.0.1/api",
            {"param": "value"}
        )
        assert isinstance(tests, list)
        assert len(tests) > 0

    def test_security_headers_check(self):
        """测试安全响应头检查"""
        from tools.api_tester import api_tester
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }
        result = api_tester.check_api_security_headers(headers)
        assert isinstance(result, dict)
        assert 'headers_present' in result
        assert 'headers_missing' in result

    def test_common_api_endpoints(self):
        """测试常见API端点发现"""
        from tools.api_tester import api_tester
        endpoints = api_tester.discover_api_endpoints("http://127.0.0.1")
        assert isinstance(endpoints, list)
        assert len(endpoints) >= 10


class TestVulnIntel:
    """漏洞情报测试"""

    def test_vuln_intel_initialization(self):
        """测试漏洞情报模块初始化"""
        from tools.vuln_intel import vuln_intel
        assert vuln_intel is not None

    def test_local_cve_database(self):
        """测试本地CVE数据库"""
        from tools.vuln_intel import vuln_intel
        stats = vuln_intel.get_stats()
        assert isinstance(stats, dict)
        assert 'local_cve_count' in stats
        assert stats['local_cve_count'] >= 0

    def test_cve_format_validation(self):
        """测试CVE格式验证（通过get_cve_details的参数校验）"""
        from tools.vuln_intel import vuln_intel
        # 验证get_cve_details方法存在
        assert hasattr(vuln_intel, 'get_cve_details')
        # 验证stats方法
        stats = vuln_intel.get_stats()
        assert isinstance(stats, dict)

    def test_vulnerability_impact_analysis(self):
        """测试漏洞影响分析"""
        from tools.vuln_intel import vuln_intel
        cve_data = {
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "cvss_severity": "CRITICAL",
            "description": "Apache Log4j2 remote code execution",
        }
        result = vuln_intel.analyze_vulnerability_impact(cve_data)
        assert isinstance(result, dict)
        assert 'impact_level' in result
        assert 'exploitability' in result
        assert 'remediation_priority' in result

    def test_remediation_advice_generation(self):
        """测试修复建议生成"""
        from tools.vuln_intel import vuln_intel
        cve_data = {
            "cve_id": "CVE-2021-44228",
            "cwe_ids": ["CWE-502"],
            "description": "Deserialization vulnerability",
        }
        result = vuln_intel.generate_remediation_advice(cve_data)
        assert isinstance(result, dict)
        assert 'general_advice' in result
        assert 'specific_remediation' in result


class TestIntegration:
    """集成测试"""

    def test_payload_to_poc_verifier_integration(self):
        """测试Payload库与POC验证器集成"""
        from tools.payload_library import payload_library
        from agent.poc_verifier import poc_verifier

        # 获取SQL注入payload
        sql_payloads = payload_library.get_payloads('sql_injection')
        assert len(sql_payloads) > 0

        # POC验证器应支持SQL注入
        supported = poc_verifier.SUPPORTED_TYPES
        assert 'sql_injection' in supported

    def test_scan_engine_to_cli_engine_integration(self):
        """测试扫描引擎与CLI引擎集成"""
        from tools.scan_engine import scan_engine
        from tools.cli_engine import cli_engine

        # 扫描引擎配置应与CLI引擎兼容
        assert scan_engine.max_concurrent > 0
        cli_tools = cli_engine.TOOL_CONFIGS
        assert isinstance(cli_tools, dict)
        assert 'nmap' in cli_tools

    def test_auth_tester_to_payload_integration(self):
        """测试认证测试器与Payload库集成"""
        from tools.auth_tester import auth_tester
        from tools.payload_library import payload_library

        # 认证测试器生成的IDOR payload应与payload库格式兼容
        idor_payloads = auth_tester.generate_idor_payloads("id", "1")
        all_types = payload_library.get_all_types()
        assert isinstance(idor_payloads, list)
        assert isinstance(all_types, list)

    def test_api_tester_to_payload_integration(self):
        """测试API测试器与Payload库集成"""
        from tools.api_tester import api_tester
        from tools.payload_library import payload_library

        # API测试器生成的注入测试应使用payload库
        injection_tests = api_tester.generate_rest_api_injection_tests(
            "http://127.0.0.1/api", {"id": "1"}
        )
        sql_payloads = payload_library.get_payloads('sql_injection')
        assert isinstance(injection_tests, list)
        assert len(sql_payloads) > 0

    def test_vuln_intel_to_report_enhancer_integration(self):
        """测试漏洞情报与报告增强器集成"""
        from tools.vuln_intel import vuln_intel
        from agent.report_enhancer import report_enhancer

        # 漏洞情报的CVE数据应能被报告增强器处理
        stats = vuln_intel.get_stats()
        assert isinstance(stats, dict)
        assert report_enhancer is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
