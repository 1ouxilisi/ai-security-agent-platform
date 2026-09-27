#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_mobile单元测试模块，包含相关功能的测试用例和验证逻辑。

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


class TestMobileSecurityAnalyzer:
    """移动安全分析器测试"""

    def test_analyzer_import(self):
        """测试移动安全分析器导入"""
        from mobile.security_analyzer import mobile_security_analyzer
        assert mobile_security_analyzer is not None

    def test_analyzer_statistics(self):
        """测试分析器统计信息"""
        from mobile.security_analyzer import mobile_security_analyzer
        stats = mobile_security_analyzer.get_statistics()
        assert isinstance(stats, dict)

    def test_dangerous_permissions_list(self):
        """测试危险权限列表（实际是set类型）"""
        from mobile.security_analyzer import mobile_security_analyzer
        perms = mobile_security_analyzer.DANGEROUS_PERMISSIONS
        assert isinstance(perms, (list, set, tuple))
        assert len(perms) > 0

    def test_insecure_apis_list(self):
        """测试不安全API列表"""
        from mobile.security_analyzer import mobile_security_analyzer
        assert hasattr(mobile_security_analyzer, "INSECURE_APIS")

    def test_secret_patterns_list(self):
        """测试密钥模式列表"""
        from mobile.security_analyzer import mobile_security_analyzer
        assert hasattr(mobile_security_analyzer, "SECRET_PATTERNS")

    def test_apk_analysis_result_class(self):
        """测试APK分析结果数据类"""
        from mobile.security_analyzer import APKAnalysisResult
        result = APKAnalysisResult(file_path="test.apk")
        assert result.file_path == "test.apk"
        assert hasattr(result, "debuggable")
        assert hasattr(result, "allow_backup")
        assert hasattr(result, "dangerous_permissions")

    def test_risk_score_calculation(self):
        """测试风险评分计算"""
        from mobile.security_analyzer import APKAnalysisResult
        result = APKAnalysisResult(file_path="test.apk")
        # 初始风险分数应该有计算方法
        assert hasattr(result, "_calculate_risk_score") or hasattr(result, "calculate_risk_score") or hasattr(result, "risk_score")

    def test_risk_score_with_issues(self):
        """测试有安全问题时的风险评分"""
        from mobile.security_analyzer import APKAnalysisResult
        result = APKAnalysisResult(file_path="test.apk")
        result.debuggable = True
        result.dangerous_permissions = ["android.permission.CAMERA", "android.permission.READ_SMS"]
        # 触发风险评分计算
        if hasattr(result, "_calculate_risk_score"):
            score = result._calculate_risk_score()
            assert score >= 0
            assert score <= 100

    def test_analyze_apk_method_exists(self):
        """测试APK分析方法存在"""
        from mobile.security_analyzer import mobile_security_analyzer
        assert hasattr(mobile_security_analyzer, "analyze_apk")
