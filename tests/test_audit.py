#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_audit单元测试模块，包含相关功能的测试用例和验证逻辑。

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


class TestAuditLogger:
    """企业审计日志测试"""

    def test_audit_logger_import(self):
        """测试审计日志模块导入"""
        from enterprise.audit_log import audit_logger
        assert audit_logger is not None

    def test_log_event_basic(self):
        """测试记录基本审计事件"""
        from enterprise.audit_log import audit_logger
        event_id = audit_logger.log_event(
            action="test.action",
            severity="info",
            username="testuser",
            source_ip="127.0.0.1",
            description="测试审计事件"
        )
        assert event_id is not None

    def test_log_event_with_details(self):
        """测试记录带详细信息的审计事件"""
        from enterprise.audit_log import audit_logger
        event_id = audit_logger.log_event(
            action="user.login",
            severity="warning",
            username="admin",
            source_ip="192.168.1.100",
            description="管理员登录"
        )
        assert event_id is not None

    def test_log_event_severity_levels(self):
        """测试不同严重级别的审计事件"""
        from enterprise.audit_log import audit_logger
        for severity in ["info", "warning", "error", "critical"]:
            event_id = audit_logger.log_event(
                action=f"test.{severity}",
                severity=severity,
                username="testuser",
                source_ip="127.0.0.1",
                description=f"测试{severity}级别事件"
            )
            assert event_id is not None

    def test_log_login_method(self):
        """测试登录日志专用方法"""
        from enterprise.audit_log import audit_logger
        assert hasattr(audit_logger, "log_login")

    def test_log_scan_method(self):
        """测试扫描日志专用方法"""
        from enterprise.audit_log import audit_logger
        assert hasattr(audit_logger, "log_scan")

    def test_log_vuln_exploit_method(self):
        """测试漏洞利用日志专用方法"""
        from enterprise.audit_log import audit_logger
        assert hasattr(audit_logger, "log_vuln_exploit")

    def test_log_config_change_method(self):
        """测试配置变更日志专用方法"""
        from enterprise.audit_log import audit_logger
        assert hasattr(audit_logger, "log_config_change")

    def test_audit_statistics(self):
        """测试审计统计信息"""
        from enterprise.audit_log import audit_logger
        # 先记录一些事件
        for i in range(3):
            audit_logger.log_event(
                action=f"test.stat.{i}",
                severity="info",
                username="testuser",
                source_ip="127.0.0.1",
                description=f"统计测试事件{i}"
            )
        stats = audit_logger.get_statistics()
        assert isinstance(stats, dict)
        assert "total_events" in stats
        assert stats["total_events"] > 0

    def test_audit_hash_chain(self):
        """测试审计哈希链"""
        from enterprise.audit_log import audit_logger
        assert hasattr(audit_logger, "last_hash")
        # 记录一些事件以建立哈希链
        for i in range(5):
            audit_logger.log_event(
                action=f"test.hash.{i}",
                severity="info",
                username="testuser",
                source_ip="127.0.0.1",
                description=f"哈希链测试事件{i}"
            )
        stats = audit_logger.get_statistics()
        # 哈希链相关字段应该存在
        assert "hash_chain_intact" in stats or "last_hash" in stats or "event_counter" in stats

    def test_audit_query_events(self):
        """测试审计事件查询"""
        from enterprise.audit_log import audit_logger
        result = audit_logger.query_events(limit=10)
        assert isinstance(result, dict)
        assert "total" in result
        assert "events" in result
        assert isinstance(result["events"], list)

    def test_audit_query_by_severity(self):
        """测试按严重级别查询审计事件"""
        from enterprise.audit_log import audit_logger
        result = audit_logger.query_events(severity="warning", limit=10)
        assert isinstance(result, dict)
        assert "events" in result

    def test_audit_export_logs(self):
        """测试导出审计日志"""
        from enterprise.audit_log import audit_logger
        assert hasattr(audit_logger, "export_logs")

    def test_audit_get_alerts(self):
        """测试获取告警"""
        from enterprise.audit_log import audit_logger
        assert hasattr(audit_logger, "get_alerts")

    def test_audit_acknowledge_alert(self):
        """测试确认告警方法存在"""
        from enterprise.audit_log import audit_logger
        assert hasattr(audit_logger, "acknowledge_alert")

    def test_audit_event_counter(self):
        """测试事件计数器"""
        from enterprise.audit_log import audit_logger
        assert hasattr(audit_logger, "event_counter")
        assert audit_logger.event_counter > 0
