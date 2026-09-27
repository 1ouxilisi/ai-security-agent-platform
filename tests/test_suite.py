"""test_suite单元测试模块，包含相关功能的测试用例和验证逻辑。"""
import asyncio
import inspect
import json
import time
import sys
from pathlib import Path
from typing import Any, Dict, List


class TestResult:
    """测试结果"""
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.error: str = ""
        self.duration_ms: float = 0
        self.details: str = ""


class TestSuite:
    """测试套件"""
    def __init__(self):
        self.results: List[TestResult] = []
        self.passed_count = 0
        self.failed_count = 0

    def run_test(self, name: str, test_func) -> TestResult:
        result = TestResult(name)
        start = time.time()
        try:
            if inspect.iscoroutinefunction(test_func):
                asyncio.run(test_func())
            else:
                test_func()
            result.passed = True
            self.passed_count += 1
        except Exception as e:
            result.passed = False
            result.error = str(e)
            self.failed_count += 1
        result.duration_ms = round((time.time() - start) * 1000, 2)
        self.results.append(result)
        return result

    def print_results(self):
        print("\n" + "=" * 70)
        print("测试结果")
        print("=" * 70)
        for r in self.results:
            icon = "PASS" if r.passed else "FAIL"
            print(f"  [{icon}] {r.name} ({r.duration_ms}ms)")
            if not r.passed:
                print(f"     错误: {r.error[:100]}")
        print("-" * 70)
        print(f"总计: {len(self.results)} | 通过: {self.passed_count} | 失败: {self.failed_count}")
        if self.results:
            print(f"通过率: {round(self.passed_count / len(self.results) * 100, 1)}%")
        print("=" * 70)
        return self.failed_count == 0


# ============== 测试用例 ==============

def test_config_loading():
    """测试配置加载"""
    from config.settings import settings
    assert settings.llm is not None
    assert settings.mcp is not None
    assert settings.project_root is not None


def test_logger():
    """测试日志模块"""
    from utils.logger import log
    assert log is not None
    log.info("测试日志输出")


def test_helpers():
    """测试辅助函数"""
    from utils.helpers import validate_target, rate_limit
    assert validate_target("127.0.0.1") is True
    assert validate_target("localhost") is True


def test_memory_module():
    """测试智能体记忆模块"""
    from agent.memory import AgentMemory, TaskStep
    memory = AgentMemory(task_id="test-001", task_description="测试任务")
    assert memory.task_id == "test-001"
    assert memory.task_description == "测试任务"
    step = TaskStep(step_id="s1", step_number=1, description="测试步骤")
    memory.add_step(step)
    assert len(memory.plan) == 1


def test_react_engine_init():
    """测试ReAct引擎初始化"""
    try:
        import openai
    except ImportError:
        return
    from agent.react_engine import ReActEngine, ReActResult
    engine = ReActEngine(tool_registry={}, max_iterations=5)
    assert engine.max_iterations == 5
    result = ReActResult(task="test")
    assert result.task == "test"


def test_rag_engine():
    """测试RAG引擎"""
    from agent.rag_engine import rag_engine
    stats = rag_engine.get_statistics()
    assert stats["total_entries"] > 0
    result = rag_engine.retrieve("SQL注入", top_k=3)
    assert result.total_found >= 0


def test_result_analyzer():
    """测试结果分析器"""
    from agent.result_analyzer import result_analyzer, VulnerabilityFinding
    finding = VulnerabilityFinding(type="sqli", severity="high", title="测试SQL注入")
    assert finding.type == "sqli"
    stats = result_analyzer.get_statistics()
    assert "total_findings" in stats


def test_base_agent():
    """测试通用Agent基类"""
    try:
        import openai
    except ImportError:
        return
    from agent.base_agent import BaseAgent, AgentConfig, ToolDefinition
    config = AgentConfig(name="TestAgent", role="测试")
    agent = BaseAgent(config=config)
    assert agent.config.name == "TestAgent"
    assert agent.config.role == "测试"


def test_database():
    """测试数据库模块"""
    from database.db import Database
    import tempfile
    import os
    tmp_db = tempfile.mktemp(suffix=".db")
    try:
        db = Database(db_path=tmp_db)
        assert db is not None
        db.save_task({"task_id": "test", "task_description": "测试任务", "target": "127.0.0.1", "status": "pending", "task_type": "scan"})
        tasks = db.list_tasks()
        assert tasks is not None
    finally:
        if os.path.exists(tmp_db):
            os.remove(tmp_db)


def test_cve_knowledge():
    """测试CVE知识库"""
    from knowledge.cve import cve_kb
    assert len(cve_kb.local_db) > 0
    stats = cve_kb.get_statistics()
    assert stats is not None


def test_nuclei_engine():
    """测试Nuclei POC引擎"""
    from nuclei_engine.engine import nuclei_engine
    stats = nuclei_engine.get_stats()
    assert stats["total_templates"] > 0
    templates = nuclei_engine.list_templates()
    assert len(templates) > 0


def test_api_auth():
    """测试API认证系统"""
    from security.api_auth import api_security
    key = api_security.generate_api_key(name="测试密钥", rate_limit=1000)
    assert key.startswith("aha-")
    valid, msg = api_security.validate_api_key(key, client_ip="127.0.0.1", endpoint="/test")
    assert valid is True
    api_security.revoke_api_key(key)


def test_cache_manager():
    """测试缓存管理器"""
    from cache.cache_manager import cache_manager, LRUCache
    cache = LRUCache(max_size=10, ttl=60)
    cache.set("test_key", "test_value")
    assert cache.get("test_key") == "test_value"
    assert cache.get("nonexistent") is None
    stats = cache.get_stats()
    assert stats["size"] == 1


def test_plugin_system():
    """测试插件系统"""
    from plugins.base import BasePlugin, PluginTool
    from plugins.manager import PluginManager
    manager = PluginManager()
    assert manager is not None


def test_report_exporter():
    """测试报告导出器"""
    from reporting.report_exporter import report_exporter, ReportConfig
    config = ReportConfig(title="测试报告", target="127.0.0.1")
    data = {"findings": [], "target": "127.0.0.1"}
    results = report_exporter.generate_report(data, config)
    assert "markdown" in results
    assert "html" in results
    assert "json" in results


def test_task_scheduler():
    """测试任务调度器"""
    from scheduler.task_scheduler import TaskScheduler, TaskStatus
    scheduler = TaskScheduler()
    assert scheduler is not None
    stats = scheduler.get_statistics()
    assert "total_tasks" in stats


def test_mcp_tools_registry():
    """测试MCP工具注册表"""
    try:
        from mcp_server.server import TOOL_DEFINITIONS
        assert len(TOOL_DEFINITIONS) >= 25
        tool_names = [t["name"] for t in TOOL_DEFINITIONS]
        assert "port_scan" in tool_names
        assert "dns_lookup" in tool_names
    except ImportError:
        pass


def test_api_server_models():
    """测试API服务模型"""
    try:
        from api_server.app import TaskCreateRequest, ToolCallRequest, SystemStatsResponse
        req = TaskCreateRequest(target="127.0.0.1", task_type="scan")
        assert req.target == "127.0.0.1"
    except ImportError:
        pass


# ============== 主测试运行器 ==============

def run_all_tests() -> bool:
    """运行所有测试"""
    print("=" * 70)
    print("AI Hacking Agent v5.0 - 集成测试套件")
    print("=" * 70)
    suite = TestSuite()
    tests = [
        ("配置加载", test_config_loading),
        ("日志模块", test_logger),
        ("辅助函数", test_helpers),
        ("智能体记忆", test_memory_module),
        ("ReAct引擎初始化", test_react_engine_init),
        ("RAG知识库引擎", test_rag_engine),
        ("智能结果分析器", test_result_analyzer),
        ("通用Agent基类", test_base_agent),
        ("数据库模块", test_database),
        ("CVE知识库", test_cve_knowledge),
        ("Nuclei POC引擎", test_nuclei_engine),
        ("API认证系统", test_api_auth),
        ("缓存管理器", test_cache_manager),
        ("插件系统", test_plugin_system),
        ("报告导出器", test_report_exporter),
        ("任务调度器", test_task_scheduler),
        ("MCP工具注册表", test_mcp_tools_registry),
        ("API服务模型", test_api_server_models),
    ]
    for name, test_func in tests:
        suite.run_test(name, test_func)
    return suite.print_results()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
