"""
test_unit单元测试模块，包含相关功能的测试用例和验证逻辑。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import sys
import json
import tempfile
import unittest
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestConfiguration(unittest.TestCase):
    """配置加载测试"""

    def test_env_file_exists(self):
        """测试.env文件存在"""
        env_path = Path(__file__).parent.parent / ".env"
        self.assertTrue(env_path.exists(), ".env文件不存在")

    def test_env_required_keys(self):
        """测试.env包含必要的配置项"""
        env_path = Path(__file__).parent.parent / ".env"
        content = env_path.read_text(encoding="utf-8")
        required_keys = ["LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL", "ALLOWED_TARGETS"]
        for key in required_keys:
            self.assertIn(key, content, f".env缺少必要配置: {key}")

    def test_api_auth_config(self):
        """测试API鉴权配置"""
        env_path = Path(__file__).parent.parent / ".env"
        content = env_path.read_text(encoding="utf-8")
        self.assertIn("API_AUTH_KEY", content, "缺少API_AUTH_KEY配置")
        self.assertIn("API_AUTH_ENABLED", content, "缺少API_AUTH_ENABLED配置")


class TestDatabase(unittest.TestCase):
    """数据库操作测试"""

    def setUp(self):
        """设置临时数据库"""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()

    def tearDown(self):
        """清理临时数据库"""
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_database_module_import(self):
        """测试数据库模块可导入"""
        try:
            from database.db import Database
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"数据库模块导入失败: {e}")

    def test_database_initialization(self):
        """测试数据库初始化"""
        try:
            from database.db import Database
            db = Database(self.temp_db.name)
            self.assertIsNotNone(db)
        except Exception as e:
            self.fail(f"数据库初始化失败: {e}")


class TestTools(unittest.TestCase):
    """安全工具模块测试"""

    def test_recon_tools_import(self):
        """测试侦察工具模块可导入"""
        try:
            from mcp_server.recon_tools import recon_tools
            self.assertIsNotNone(recon_tools)
        except ImportError as e:
            self.fail(f"侦察工具模块导入失败: {e}")

    def test_web_tools_import(self):
        """测试Web工具模块可导入"""
        try:
            from mcp_server.web_tools import web_tools
            self.assertIsNotNone(web_tools)
        except ImportError as e:
            self.fail(f"Web工具模块导入失败: {e}")

    def test_tool_definitions_count(self):
        """测试工具定义数量（应>=30）"""
        try:
            from mcp_server.server import TOOL_DEFINITIONS
            self.assertGreaterEqual(len(TOOL_DEFINITIONS), 30, f"工具数量不足: {len(TOOL_DEFINITIONS)}")
        except ImportError as e:
            self.fail(f"工具定义导入失败: {e}")

    def test_tool_definitions_structure(self):
        """测试工具定义结构完整性"""
        try:
            from mcp_server.server import TOOL_DEFINITIONS
            for tool in TOOL_DEFINITIONS:
                self.assertIn("name", tool, "工具缺少name字段")
                self.assertIn("description", tool, f"工具 {tool.get('name')} 缺少description字段")
                self.assertIn("inputSchema", tool, f"工具 {tool.get('name')} 缺少inputSchema字段")
                self.assertIn("handler", tool, f"工具 {tool.get('name')} 缺少handler字段")
        except ImportError as e:
            self.fail(f"工具定义导入失败: {e}")


class TestReportEnhancer(unittest.TestCase):
    """报告增强模块测试"""

    def test_cvss_scorer_import(self):
        """测试CVSS评分器可导入"""
        try:
            from agent.report_enhancer import CVSSScorer
            self.assertIsNotNone(CVSSScorer)
        except ImportError as e:
            self.fail(f"CVSS评分器导入失败: {e}")

    def test_cvss_calculation(self):
        """测试CVSS评分计算"""
        from agent.report_enhancer import CVSSScorer
        result = CVSSScorer.calculate("sql_injection")
        self.assertIn("base_score", result)
        self.assertIn("severity", result)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertGreaterEqual(result["base_score"], 9.0)

    def test_cvss_calculation_xss(self):
        """测试XSS的CVSS评分"""
        from agent.report_enhancer import CVSSScorer
        result = CVSSScorer.calculate("xss")
        self.assertEqual(result["severity"], "HIGH")

    def test_remediation_advisor(self):
        """测试修复建议生成器"""
        from agent.report_enhancer import RemediationAdvisor
        result = RemediationAdvisor.get_remediation("sql_injection")
        self.assertIn("summary", result)
        self.assertIn("remediation_steps", result)
        self.assertIn("references", result)
        self.assertGreater(len(result["remediation_steps"]), 0)
        self.assertGreater(len(result["references"]), 0)

    def test_report_enhancer_generate(self):
        """测试增强报告生成"""
        from agent.report_enhancer import report_enhancer
        task_data = {
            "task_id": "test-001",
            "target": "127.0.0.1",
            "task_type": "scan",
            "description": "测试扫描",
        }
        findings = [
            {"type": "sql_injection", "name": "SQL注入", "description": "测试SQL注入"},
            {"type": "xss", "name": "XSS", "description": "测试XSS"},
        ]
        report = report_enhancer.generate_enhanced_report(task_data, findings)
        self.assertIn("executive_summary", report)
        self.assertIn("findings", report)
        self.assertEqual(report["executive_summary"]["total_findings"], 2)
        self.assertIn("cvss", report["findings"][0])
        self.assertIn("remediation", report["findings"][0])

    def test_report_to_markdown(self):
        """测试报告转Markdown"""
        from agent.report_enhancer import report_enhancer
        task_data = {"task_id": "test-001", "target": "127.0.0.1", "task_type": "scan"}
        findings = [{"type": "sql_injection", "name": "SQL注入"}]
        report = report_enhancer.generate_enhanced_report(task_data, findings)
        md = report_enhancer.report_to_markdown(report)
        self.assertIn("# 安全测试报告", md)
        self.assertIn("## 📊 执行摘要", md)
        self.assertIn("## 🔍 漏洞详情", md)


class TestPOCVerifier(unittest.TestCase):
    """POC验证模块测试"""

    def test_poc_verifier_import(self):
        """测试POC验证器可导入"""
        try:
            from agent.poc_verifier import POCVerifier
            self.assertIsNotNone(POCVerifier)
        except ImportError as e:
            self.fail(f"POC验证器导入失败: {e}")

    def test_poc_verifier_initialization(self):
        """测试POC验证器初始化"""
        from agent.poc_verifier import POCVerifier
        verifier = POCVerifier()
        self.assertEqual(verifier.verified_findings, [])
        self.assertEqual(verifier.false_positives, [])

    def test_inject_param(self):
        """测试参数注入方法"""
        from agent.poc_verifier import POCVerifier
        url = "http://example.com/page?id=1"
        result = POCVerifier._inject_param(url, "id", "test'")
        self.assertIn("id=test", result)

    def test_check_xss_context(self):
        """测试XSS上下文检测"""
        from agent.poc_verifier import POCVerifier
        content = "<html><body><script>alert('test')</script></body></html>"
        payload = "alert('test')"
        context = POCVerifier._check_xss_context(content, payload)
        self.assertIn(context, ["script_tag", "html_body", "attribute_value", "javascript_uri", "unknown"])


class TestAPIAuth(unittest.TestCase):
    """API鉴权测试"""

    def test_api_auth_module_structure(self):
        """测试API鉴权代码结构"""
        app_path = Path(__file__).parent.parent / "api_server" / "app.py"
        content = app_path.read_text(encoding="utf-8")
        self.assertIn("verify_api_key", content, "缺少verify_api_key函数")
        self.assertIn("API_AUTH_KEY", content, "缺少API_AUTH_KEY引用")
        self.assertIn("API_AUTH_ENABLED", content, "缺少API_AUTH_ENABLED引用")
        self.assertIn("X-API-Key", content, "缺少X-API-Key头")

    def test_protected_endpoints_have_auth(self):
        """测试受保护端点都有鉴权依赖"""
        app_path = Path(__file__).parent.parent / "api_server" / "app.py"
        content = app_path.read_text(encoding="utf-8")
        # 检查所有 @app. 装饰器中，除了 / 和 /health 之外都有 verify_api_key
        import re
        decorators = re.findall(r'@app\.(get|post|put|delete|websocket)\("([^"]+)"[^)]*\)', content)
        for method, path in decorators:
            if not path.startswith("/api/") or path in ("/api/v1/auth/register", "/api/v1/auth/login") or method == "websocket":
                continue  # 只检查API端点，注册/登录、WebSocket不需要HTTP头鉴权
            # 找到这个装饰器在文件中的位置，检查附近是否有verify_api_key
            idx = content.find(f'@app.{method}("{path}"')
            if idx != -1:
                # 检查装饰器行本身是否包含dependencies
                line_end = content.find("\n", idx)
                decorator_line = content[idx:line_end]
                if "dependencies" not in decorator_line:
                    # 检查下一行是否有dependencies（多行装饰器）
                    next_lines = content[line_end:line_end+200]
                    if "verify_api_key" not in next_lines and "dependencies" not in next_lines:
                        self.fail(f"端点 {method} {path} 缺少鉴权依赖")


class TestAgents(unittest.TestCase):
    """智能体模块测试"""

    def test_react_engine_import(self):
        """测试ReAct引擎可导入"""
        try:
            from agent.react_engine import ReActEngine
            self.assertIsNotNone(ReActEngine)
        except ImportError as e:
            self.fail(f"ReAct引擎导入失败: {e}")

    def test_rag_engine_import(self):
        """测试RAG引擎可导入"""
        try:
            from agent.rag_engine import rag_engine
            self.assertIsNotNone(rag_engine)
        except ImportError as e:
            self.fail(f"RAG引擎导入失败: {e}")


class TestKnowledgeBase(unittest.TestCase):
    """知识库测试"""

    def test_cve_kb_import(self):
        """测试CVE知识库可导入"""
        try:
            from knowledge.cve import cve_kb
            self.assertIsNotNone(cve_kb)
        except ImportError as e:
            self.fail(f"CVE知识库导入失败: {e}")

    def test_cve_kb_has_data(self):
        """测试CVE知识库有数据"""
        try:
            from knowledge.cve import cve_kb
            stats = cve_kb.get_statistics()
            self.assertGreater(stats["total"], 0, "CVE知识库为空")
        except ImportError as e:
            self.fail(f"CVE知识库导入失败: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
