#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_workflow单元测试模块，包含相关功能的测试用例和验证逻辑。

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


class TestAutonomousPentest:
    """全自动渗透测试工作流测试"""

    def test_workflow_engine_import(self):
        """测试工作流引擎导入"""
        from workflow.autonomous_pentest import autonomous_pentest_engine
        assert autonomous_pentest_engine is not None

    def test_workflow_statistics(self):
        """测试工作流统计信息"""
        from workflow.autonomous_pentest import autonomous_pentest_engine
        stats = autonomous_pentest_engine.get_statistics()
        assert "total_steps" in stats
        assert stats["total_steps"] > 0
        assert "phases" in stats

    def test_workflow_phases_constant(self):
        """测试工作流阶段常量"""
        from workflow.autonomous_pentest import autonomous_pentest_engine
        assert hasattr(autonomous_pentest_engine, "PHASES")
        assert len(autonomous_pentest_engine.PHASES) >= 5

    def test_create_workflow_url(self):
        """测试创建URL目标的工作流"""
        from workflow.autonomous_pentest import autonomous_pentest_engine
        workflow = autonomous_pentest_engine.create_workflow(
            target="https://example.com",
            target_type="url",
            use_sandbox=False,
            ai_enabled=True
        )
        assert workflow is not None
        assert workflow.target == "https://example.com"
        assert len(workflow.steps) > 0

    def test_create_workflow_ip(self):
        """测试创建IP目标的工作流"""
        from workflow.autonomous_pentest import autonomous_pentest_engine
        workflow = autonomous_pentest_engine.create_workflow(
            target="192.168.1.1",
            target_type="ip",
            use_sandbox=False,
            ai_enabled=False
        )
        assert workflow is not None
        assert workflow.target == "192.168.1.1"

    def test_workflow_list_workflows(self):
        """测试列出工作流"""
        from workflow.autonomous_pentest import autonomous_pentest_engine
        # 先创建一个工作流
        autonomous_pentest_engine.create_workflow(
            target="https://test.com",
            target_type="url",
            use_sandbox=False,
            ai_enabled=True
        )
        workflows = autonomous_pentest_engine.list_workflows()
        assert isinstance(workflows, list)
        assert len(workflows) > 0

    def test_workflow_id_format(self):
        """测试工作流ID格式（实际字段是workflow_id）"""
        from workflow.autonomous_pentest import autonomous_pentest_engine
        workflow = autonomous_pentest_engine.create_workflow(
            target="https://example.com",
            target_type="url",
            use_sandbox=False,
            ai_enabled=True
        )
        assert hasattr(workflow, "workflow_id")
        assert workflow.workflow_id is not None
        assert len(str(workflow.workflow_id)) > 3
        assert str(workflow.workflow_id).startswith("PT-")

    def test_workflow_status(self):
        """测试工作流状态"""
        from workflow.autonomous_pentest import autonomous_pentest_engine
        workflow = autonomous_pentest_engine.create_workflow(
            target="https://example.com",
            target_type="url",
            use_sandbox=False,
            ai_enabled=True
        )
        assert hasattr(workflow, "status")
        # 新创建的工作流应该是pending状态
        assert workflow.status in ["pending", "created", "pending_approval"]


class TestWorkflowStep:
    """工作流步骤测试"""

    def test_workflow_step_class_exists(self):
        """测试工作流步骤数据类存在"""
        from workflow.autonomous_pentest import WorkflowStep
        assert WorkflowStep is not None
