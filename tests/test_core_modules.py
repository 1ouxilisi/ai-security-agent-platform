#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
核心模块单元测试（简化版）
测试所有核心模块的导入、初始化、基本stats功能
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCoreModules(unittest.TestCase):
    """核心模块导入和基本功能测试"""

    def test_01_task_queue(self):
        """任务队列系统"""
        from core.task_queue import TaskQueue
        queue = TaskQueue()
        self.assertIsNotNone(queue)
        stats = queue.get_stats()
        self.assertIsInstance(stats, dict)

    def test_02_user_manager(self):
        """用户权限系统"""
        from core.user_manager import UserManager, UserRole
        manager = UserManager()
        self.assertIsNotNone(manager)
        self.assertGreaterEqual(len([e for e in UserRole]), 3)

    def test_03_report_generator(self):
        """报告模板系统"""
        from core.report_generator import ReportGenerator
        generator = ReportGenerator()
        self.assertIsNotNone(generator)
        templates = generator.list_templates()
        self.assertIsInstance(templates, list)

    def test_04_exploit_library(self):
        """漏洞利用库"""
        from core.exploit_library import ExploitLibrary
        library = ExploitLibrary()
        self.assertIsNotNone(library)
        stats = library.get_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn('total_exploits', stats)

    def test_05_plugin_system(self):
        """插件系统"""
        from core.plugin_system import PluginManager
        manager = PluginManager()
        self.assertIsNotNone(manager)
        plugins = manager.list_plugins()
        self.assertIsInstance(plugins, list)

    def test_06_team_collaboration(self):
        """团队协作系统"""
        from core.team_collaboration import TeamCollaborationManager
        manager = TeamCollaborationManager()
        self.assertIsNotNone(manager)
        teams = manager.list_teams()
        self.assertIsInstance(teams, list)

    def test_07_realtime_monitor(self):
        """实时监控系统"""
        from core.realtime_monitor import RealTimeMonitor
        monitor = RealTimeMonitor()
        self.assertIsNotNone(monitor)
        metrics = monitor.get_current_metrics()
        self.assertIsNotNone(metrics)
        self.assertTrue(hasattr(metrics, 'cpu_usage'))

    def test_08_api_platform(self):
        """API开放平台"""
        from core.api_platform import APIPlatformManager
        platform = APIPlatformManager()
        self.assertIsNotNone(platform)
        stats = platform.get_platform_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn('plans', stats)

    def test_09_mobile_security(self):
        """移动端安全深化"""
        from core.mobile_security_advanced import MobileSecurityAnalyzer
        analyzer = MobileSecurityAnalyzer()
        self.assertIsNotNone(analyzer)
        hooks = analyzer.list_hooks()
        self.assertIsInstance(hooks, list)
        self.assertGreaterEqual(len(hooks), 6)

    def test_10_distributed_scan(self):
        """分布式扫描架构"""
        from core.distributed_scan import DistributedScanManager
        manager = DistributedScanManager()
        self.assertIsNotNone(manager)
        stats = manager.get_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn('total_nodes', stats)

    def test_11_ai_decision_engine(self):
        """AI自主决策引擎"""
        from core.ai_decision_engine import AIDecisionEngine
        engine = AIDecisionEngine()
        self.assertIsNotNone(engine)
        stats = engine.get_learning_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn('total_experiences', stats)

    def test_12_ai_plan_task(self):
        """AI任务规划功能"""
        from core.ai_decision_engine import AIDecisionEngine
        engine = AIDecisionEngine()
        decision = engine.plan_task(
            target="http://example.com",
            task_type="penetration_test"
        )
        self.assertIsNotNone(decision.decision_id)
        self.assertGreater(len(decision.options), 0)

    def test_13_ai_attack_path(self):
        """AI攻击路径规划"""
        from core.ai_decision_engine import AIDecisionEngine
        engine = AIDecisionEngine()
        path = engine.plan_attack_path(
            target="192.168.1.100",
            goal="full_access"
        )
        self.assertIsNotNone(path.path_id)
        self.assertGreater(path.total_steps, 0)

    def test_14_health_check_script(self):
        """健康检查脚本"""
        from scripts.health_check import HealthChecker
        checker = HealthChecker()
        self.assertIsNotNone(checker)
        result = checker.check_python_version()
        self.assertIn(result['status'], ['pass', 'fail'])

    def test_15_all_modules_import(self):
        """所有核心模块导入测试"""
        modules = [
            'core.task_queue',
            'core.user_manager',
            'core.report_generator',
            'core.exploit_library',
            'core.plugin_system',
            'core.team_collaboration',
            'core.realtime_monitor',
            'core.api_platform',
            'core.mobile_security_advanced',
            'core.distributed_scan',
            'core.ai_decision_engine',
        ]
        failed = []
        for mod in modules:
            try:
                __import__(mod)
            except Exception as e:
                failed.append(f"{mod}: {e}")
        self.assertEqual(len(failed), 0, f"导入失败: {failed}")


def run_tests():
    """运行所有测试"""
    print("=" * 60)
    print("  AI Hacking Agent v7.0 核心模块单元测试")
    print("=" * 60)
    print()

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestCoreModules)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print()
    print("=" * 60)
    print("  测试总结")
    print("=" * 60)
    print(f"总测试数: {result.testsRun}")
    print(f"成功: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"失败: {len(result.failures)}")
    print(f"错误: {len(result.errors)}")
    print()

    if result.wasSuccessful():
        print("状态: [全部通过] 所有核心模块功能正常")
    else:
        print("状态: [存在失败] 请检查失败项并修复")

    print("=" * 60)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
