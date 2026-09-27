#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_knowledge单元测试模块，包含相关功能的测试用例和验证逻辑。

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


class TestPOCLibrary:
    """PoC库测试"""

    def test_poc_library_initialized(self):
        """测试PoC库是否正确初始化"""
        from knowledge.poc_library import poc_library
        assert poc_library is not None

    def test_poc_library_statistics(self):
        """测试PoC库统计信息"""
        from knowledge.poc_library import poc_library
        stats = poc_library.get_statistics()
        assert "total_pocs" in stats
        assert stats["total_pocs"] > 0
        assert "by_severity" in stats
        assert "by_vuln_type" in stats

    def test_poc_library_search_pocs(self):
        """测试搜索PoC（实际方法名search_pocs）"""
        from knowledge.poc_library import poc_library
        results = poc_library.search_pocs("sql")
        assert isinstance(results, list)

    def test_poc_library_get_by_vuln_type(self):
        """测试按漏洞类型获取PoC"""
        from knowledge.poc_library import poc_library
        results = poc_library.get_poc_by_vuln_type("sql_injection")
        assert isinstance(results, list)

    def test_poc_library_get_poc(self):
        """测试获取单个PoC"""
        from knowledge.poc_library import poc_library
        stats = poc_library.get_statistics()
        if stats["total_pocs"] > 0:
            # 获取第一个PoC的ID
            all_pocs = poc_library.search_pocs("")
            if all_pocs:
                poc_id = all_pocs[0].get("id") or all_pocs[0].get("poc_id")
                if poc_id:
                    poc = poc_library.get_poc(poc_id)
                    assert poc is not None

    def test_poc_class_fields(self):
        """测试PoC数据类实际字段"""
        from knowledge.poc_library import PoC
        # PoC实际需要poc_id, name, vuln_type, severity
        poc = PoC(
            poc_id="TEST-001",
            name="Test PoC",
            vuln_type="sql_injection",
            severity="high",
            description="Test PoC description",
            payload="test payload"
        )
        assert poc.poc_id == "TEST-001"
        assert poc.name == "Test PoC"
        assert poc.severity == "high"


class TestFingerprintLibrary:
    """指纹库测试"""

    def test_fingerprint_library_initialized(self):
        """测试指纹库是否正确初始化"""
        from knowledge.fingerprint_library import fingerprint_library
        assert fingerprint_library is not None

    def test_fingerprint_library_statistics(self):
        """测试指纹库统计信息"""
        from knowledge.fingerprint_library import fingerprint_library
        stats = fingerprint_library.get_statistics()
        assert "total_rules" in stats
        assert stats["total_rules"] > 0

    def test_fingerprint_library_search_rules(self):
        """测试搜索指纹规则（实际方法名search_rules）"""
        from knowledge.fingerprint_library import fingerprint_library
        results = fingerprint_library.search_rules("apache")
        assert isinstance(results, list)

    def test_fingerprint_library_identify(self):
        """测试指纹识别方法存在"""
        from knowledge.fingerprint_library import fingerprint_library
        assert hasattr(fingerprint_library, "identify")

    def test_fingerprint_rule_fields(self):
        """测试指纹规则数据类实际字段"""
        from knowledge.fingerprint_library import FingerprintRule
        rule = FingerprintRule(
            rule_id="FP-001",
            name="Test Fingerprint",
            category="web",
            product="TestProduct",
            vendor="TestVendor"
        )
        assert rule.rule_id == "FP-001"
        assert rule.name == "Test Fingerprint"


class TestRemediationLibrary:
    """修复方案库测试"""

    def test_remediation_library_initialized(self):
        """测试修复方案库是否正确初始化"""
        from knowledge.remediation_library import remediation_library
        assert remediation_library is not None

    def test_remediation_library_statistics(self):
        """测试修复方案库统计信息"""
        from knowledge.remediation_library import remediation_library
        stats = remediation_library.get_statistics()
        assert "total_remediations" in stats
        assert stats["total_remediations"] > 0

    def test_remediation_library_search(self):
        """测试搜索修复方案"""
        from knowledge.remediation_library import remediation_library
        results = remediation_library.search("sql")
        assert isinstance(results, list)

    def test_remediation_class_fields(self):
        """测试修复方案数据类存在"""
        from knowledge.remediation_library import Remediation
        assert Remediation is not None


class TestAttackChainLibrary:
    """攻击链库测试"""

    def test_attack_chain_library_initialized(self):
        """测试攻击链库是否正确初始化"""
        from knowledge.attack_chains import attack_chain_library
        assert attack_chain_library is not None

    def test_attack_chain_library_statistics(self):
        """测试攻击链库统计信息"""
        from knowledge.attack_chains import attack_chain_library
        stats = attack_chain_library.get_statistics()
        assert "total_chains" in stats
        assert stats["total_chains"] > 0

    def test_attack_chain_alias_import(self):
        """测试单数别名导入"""
        from knowledge.attack_chain import attack_chain_library as ac1
        from knowledge.attack_chains import attack_chain_library as ac2
        assert ac1 is ac2

    def test_attack_chain_class(self):
        """测试攻击链数据类存在"""
        from knowledge.attack_chains import AttackChain, AttackStep
        assert AttackChain is not None
        assert AttackStep is not None


class TestKnowledgeModuleImports:
    """知识库模块导入测试"""

    def test_import_from_knowledge_init(self):
        """测试从knowledge包导入所有模块"""
        from knowledge import (
            poc_library, fingerprint_library, remediation_library,
            attack_chain_library, AttackChain,
            attack_chain_lib, AttackChainLib
        )
        assert poc_library is not None
        assert fingerprint_library is not None
        assert remediation_library is not None
        assert attack_chain_library is not None
        assert attack_chain_lib is attack_chain_library
