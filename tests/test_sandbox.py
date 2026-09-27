#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_sandbox单元测试模块，包含相关功能的测试用例和验证逻辑。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDockerSandbox:
    """Docker沙箱测试"""

    def test_sandbox_module_import(self):
        """测试沙箱模块导入"""
        from sandbox.docker_sandbox import docker_sandbox
        assert docker_sandbox is not None

    def test_sandbox_config_defaults(self):
        """测试沙箱配置默认值（实际值）"""
        from sandbox.docker_sandbox import SandboxConfig
        config = SandboxConfig()
        assert config.memory_limit == "512m"
        assert config.cpu_limit == 1.0
        assert config.timeout == 300
        assert config.network_enabled == True
        assert "kali" in config.image.lower()

    def test_sandbox_config_custom(self):
        """测试自定义沙箱配置"""
        from sandbox.docker_sandbox import SandboxConfig
        config = SandboxConfig(
            memory_limit="1g",
            cpu_limit=2.0,
            timeout=120,
            network_enabled=False
        )
        assert config.memory_limit == "1g"
        assert config.cpu_limit == 2.0
        assert config.timeout == 120
        assert config.network_enabled == False

    def test_sandbox_statistics(self):
        """测试沙箱统计信息"""
        from sandbox.docker_sandbox import docker_sandbox
        stats = docker_sandbox.get_statistics()
        assert isinstance(stats, dict)
        assert "docker_available" in stats

    def test_sandbox_check_docker_available(self):
        """测试Docker可用性检查"""
        from sandbox.docker_sandbox import docker_sandbox
        result = docker_sandbox.check_docker_available()
        assert isinstance(result, bool)


class TestSandboxResult:
    """沙箱执行结果测试"""

    def test_sandbox_result_class(self):
        """测试沙箱执行结果数据类"""
        from sandbox.docker_sandbox import SandboxResult
        result = SandboxResult(
            success=True,
            exit_code=0,
            stdout="hello world",
            stderr="",
            execution_time=1.5
        )
        assert result.success == True
        assert result.exit_code == 0
        assert result.stdout == "hello world"

    def test_sandbox_result_failure(self):
        """测试沙箱执行失败结果"""
        from sandbox.docker_sandbox import SandboxResult
        result = SandboxResult(
            success=False,
            exit_code=1,
            stdout="",
            stderr="command not found",
            execution_time=0.1
        )
        assert result.success == False
        assert result.exit_code == 1
