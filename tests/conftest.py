#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
conftest单元测试模块，包含相关功能的测试用例和验证逻辑。

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
import pytest

# 添加项目根目录到sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="session")
def project_root():
    """项目根目录路径"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session")
def test_data_dir():
    """测试数据目录"""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


@pytest.fixture(scope="function")
def temp_file():
    """临时文件fixture，测试后自动清理"""
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".tmp")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture(scope="function")
def temp_dir():
    """临时目录fixture，测试后自动清理"""
    import tempfile
    import shutil
    path = tempfile.mkdtemp()
    yield path
    if os.path.exists(path):
        shutil.rmtree(path)


@pytest.fixture(scope="session")
def sample_poc_data():
    """示例PoC数据"""
    return {
        "id": "TEST-POC-001",
        "name": "Test SQL Injection PoC",
        "description": "A test SQL injection proof of concept",
        "severity": "high",
        "category": "injection",
        "cve": "CVE-2026-0001",
        "affected_versions": ["1.0", "1.1", "2.0"],
    }


@pytest.fixture(scope="session")
def sample_vulnerability_data():
    """示例漏洞数据"""
    return {
        "id": "VULN-001",
        "title": "Test Vulnerability",
        "description": "A test vulnerability for unit testing",
        "severity": "critical",
        "cvss_score": 9.8,
        "cve_id": "CVE-2026-0001",
        "affected_product": "TestProduct",
        "affected_version": "1.0.0",
    }


@pytest.fixture(scope="session")
def sample_scan_target():
    """示例扫描目标"""
    return {
        "target": "https://example.com",
        "target_type": "url",
        "scan_type": "full",
        "options": {
            "rate_limit": 10,
            "max_concurrency": 5,
            "timeout": 30,
        }
    }


def pytest_configure(config):
    """pytest配置钩子"""
    # 注册自定义标记
    config.addinivalue_line("markers", "slow: 标记慢速测试")
    config.addinivalue_line("markers", "integration: 标记集成测试")
    config.addinivalue_line("markers", "unit: 标记单元测试")
    config.addinivalue_line("markers", "security: 标记安全测试")


def pytest_collection_modifyitems(config, items):
    """测试收集修改钩子，自动添加标记"""
    for item in items:
        if "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        elif "test_" in item.nodeid:
            item.add_marker(pytest.mark.unit)
