#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实战能力模块单元测试
"""
import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSQLMapIntegrator(unittest.TestCase):
    """SQLMap集成模块测试"""

    def setUp(self):
        from combat.sqlmap.integrator import SQLMapIntegrator
        self.integrator = SQLMapIntegrator()

    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.integrator)
        self.assertIsNotNone(self.integrator.temp_dir)
        self.assertTrue(os.path.exists(self.integrator.temp_dir))

    def test_simulate_scan(self):
        """测试模拟扫描"""
        result = self.integrator._simulate_scan('http://example.com/page?id=1')
        self.assertTrue(result.vulnerable)
        self.assertIn('sql', result.db_type.lower())
        self.assertGreater(len(result.databases), 0)
        self.assertGreater(len(result.injection_types), 0)

    def test_simulate_dump(self):
        """测试模拟Dump"""
        result = self.integrator._simulate_dump('http://example.com/page?id=1')
        self.assertTrue(result.vulnerable)
        self.assertIn('users', result.dumped_data)

    def test_quick_scan_function(self):
        """测试快速扫描函数"""
        from combat.sqlmap.integrator import quick_scan
        result = quick_scan('http://example.com/page?id=1')
        self.assertIn('vulnerable', result)

    def test_result_to_dict(self):
        """测试结果转换为字典"""
        result = self.integrator._simulate_scan('http://example.com')
        d = result.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn('url', d)
        self.assertIn('vulnerable', d)
        self.assertIn('injection_types', d)

    def tearDown(self):
        self.integrator.cleanup()


class TestMetasploitEnhanced(unittest.TestCase):
    """Metasploit增强模块测试"""

    def setUp(self):
        from combat.metasploit.enhanced import MetasploitEnhanced
        self.msf = MetasploitEnhanced(host='127.0.0.1', port=55553, password='test')

    def test_initialization(self):
        """测试初始化"""
        self.assertEqual(self.msf.host, '127.0.0.1')
        self.assertEqual(self.msf.port, 55553)
        self.assertFalse(self.msf.connected)
        self.assertIsNone(self.msf.token)

    def test_base_url(self):
        """测试基础URL生成"""
        self.assertIn('127.0.0.1', self.msf.base_url)
        self.assertIn('55553', self.msf.base_url)

    def test_exploit_result_dataclass(self):
        """测试利用结果数据类"""
        from combat.metasploit.enhanced import ExploitResult
        result = ExploitResult(success=True, module='test', target='127.0.0.1')
        self.assertTrue(result.success)
        self.assertEqual(result.module, 'test')
        d = result.to_dict()
        self.assertIn('success', d)

    def test_session_dataclass(self):
        """测试会话数据类"""
        from combat.metasploit.enhanced import MSFSession
        session = MSFSession(id=1, type='meterpreter', platform='windows',
                            target_host='192.168.1.1', target_port=4444,
                            via_exploit='test', via_payload='test')
        self.assertEqual(session.id, 1)
        d = session.to_dict()
        self.assertIn('id', d)
        self.assertIn('type', d)


class TestADAttackChain(unittest.TestCase):
    """AD域攻击链模块测试"""

    def setUp(self):
        from combat.ad_attack.chain_executor import ADAttackChain
        self.chain = ADAttackChain(dc_ip='192.168.1.1', domain='test.local')

    def test_initialization(self):
        """测试初始化"""
        self.assertEqual(self.chain.dc_ip, '192.168.1.1')
        self.assertEqual(self.chain.domain, 'test.local')
        self.assertIsInstance(self.chain.users, list)
        self.assertIsInstance(self.chain.computers, list)

    def test_simulate_users(self):
        """测试模拟用户数据"""
        users = self.chain._simulate_users()
        self.assertGreater(len(users), 0)
        usernames = [u.username for u in users]
        self.assertIn('Administrator', usernames)
        self.assertIn('krbtgt', usernames)

    def test_simulate_computers(self):
        """测试模拟计算机数据"""
        computers = self.chain._simulate_computers()
        self.assertGreater(len(computers), 0)
        dc = [c for c in computers if c.is_dc]
        self.assertGreater(len(dc), 0)

    def test_enumerate_spn(self):
        """测试SPN枚举"""
        self.chain.users = self.chain._simulate_users()
        spn_users = self.chain.enumerate_spn()
        self.assertGreater(len(spn_users), 0)
        for u in spn_users:
            self.assertGreater(len(u.service_principal_names), 0)

    def test_enumerate_no_preauth(self):
        """测试无预认证用户枚举"""
        self.chain.users = self.chain._simulate_users()
        no_preauth = self.chain.enumerate_no_preauth()
        self.assertGreater(len(no_preauth), 0)
        for u in no_preauth:
            self.assertFalse(u.has_preauth)

    def test_generate_fake_ticket_hash(self):
        """测试生成模拟票据哈希"""
        hash1 = self.chain._generate_fake_ticket_hash('test', 'HTTP/test')
        self.assertEqual(len(hash1), 64)  # SHA256
        self.assertTrue(all(c in '0123456789abcdef' for c in hash1))
        # 票据哈希包含时间戳，每次调用可能不同
        hash2 = self.chain._generate_fake_ticket_hash('test', 'HTTP/test')
        self.assertEqual(len(hash2), 64)

    def test_analyze_attack_paths(self):
        """测试攻击路径分析"""
        paths = self.chain.analyze_attack_paths()
        self.assertIn('path1', paths)
        self.assertIn('path2', paths)
        self.assertIn('path3', paths)

    def test_kerberoast_result_dataclass(self):
        """测试Kerberoasting结果数据类"""
        from combat.ad_attack.chain_executor import KerberoastResult
        result = KerberoastResult(username='test', spn='HTTP/test')
        self.assertEqual(result.username, 'test')
        d = result.to_dict()
        self.assertIn('username', d)

    def test_golden_ticket_dataclass(self):
        """测试黄金票据数据类"""
        from combat.ad_attack.chain_executor import GoldenTicket
        ticket = GoldenTicket(domain='test.local', domain_sid='S-1-5-21-test',
                             krbtgt_hash='test', username='Administrator')
        self.assertEqual(ticket.domain, 'test.local')
        d = ticket.to_dict()
        self.assertIn('domain', d)
        self.assertIn('generated', d)


class TestWebExploitScanner(unittest.TestCase):
    """Web深度漏洞利用扫描器测试"""

    def setUp(self):
        from combat.web_exploit.scanner import WebExploitScanner
        self.scanner = WebExploitScanner(target_url='http://example.com')

    def test_initialization(self):
        """测试初始化"""
        self.assertEqual(self.scanner.target_url, 'http://example.com')
        self.assertEqual(self.scanner.total_requests, 0)
        self.assertIsNotNone(self.scanner.session)

    def test_vulnerability_dataclass(self):
        """测试漏洞数据类"""
        from combat.web_exploit.scanner import Vulnerability
        vuln = Vulnerability(type='xss', url='http://example.com',
                            parameter='q', severity='high')
        self.assertEqual(vuln.type, 'xss')
        d = vuln.to_dict()
        self.assertIn('type', d)
        self.assertIn('severity', d)

    def test_scan_result_dataclass(self):
        """测试扫描结果数据类"""
        from combat.web_exploit.scanner import ScanResult
        result = ScanResult(target_url='http://example.com')
        self.assertEqual(result.target_url, 'http://example.com')
        d = result.to_dict()
        self.assertIn('target_url', d)
        self.assertIn('vulnerability_count', d)

    def test_make_request(self):
        """测试请求发送（模拟）"""
        with patch.object(self.scanner.session, 'request') as mock_request:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '<html>test</html>'
            mock_request.return_value = mock_response
            response = self.scanner._make_request('http://example.com')
            self.assertIsNotNone(response)
            self.assertEqual(response.status_code, 200)

    def test_quick_web_scan_function(self):
        """测试快速扫描函数"""
        from combat.web_exploit.scanner import quick_web_scan
        # 这个函数会实际发送请求，这里只测试导入
        self.assertTrue(callable(quick_web_scan))


class TestAttackTemplateEngine(unittest.TestCase):
    """一键攻击模板引擎测试"""

    def setUp(self):
        from combat.workflow.attack_templates import AttackTemplateEngine
        self.engine = AttackTemplateEngine()

    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.engine.templates)
        self.assertGreater(len(self.engine.templates), 0)

    def test_default_templates(self):
        """测试默认模板注册"""
        template_ids = list(self.engine.templates.keys())
        self.assertIn('web_pentest_standard', template_ids)
        self.assertIn('internal_pentest_standard', template_ids)
        self.assertIn('ad_attack_chain', template_ids)
        self.assertIn('quick_vuln_scan', template_ids)

    def test_list_templates(self):
        """测试列出模板"""
        templates = self.engine.list_templates()
        self.assertGreater(len(templates), 0)
        for t in templates:
            self.assertIn('id', t)
            self.assertIn('name', t)
            self.assertIn('task_count', t)

    def test_list_templates_by_category(self):
        """测试按类别列出模板"""
        web_templates = self.engine.list_templates(category='web')
        self.assertGreater(len(web_templates), 0)
        for t in web_templates:
            self.assertEqual(t['category'], 'web')

    def test_get_template(self):
        """测试获取模板详情"""
        template = self.engine.get_template('web_pentest_standard')
        self.assertIsNotNone(template)
        self.assertEqual(template.id, 'web_pentest_standard')
        self.assertGreater(len(template.tasks), 0)

    def test_get_nonexistent_template(self):
        """测试获取不存在的模板"""
        template = self.engine.get_template('nonexistent')
        self.assertIsNone(template)

    def test_execute_template_dry_run(self):
        """测试试运行模式执行模板"""
        result = self.engine.execute_template(
            'quick_vuln_scan',
            target='192.168.1.1',
            dry_run=True
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.template_id, 'quick_vuln_scan')
        self.assertEqual(result.target, '192.168.1.1')
        self.assertEqual(result.status.value, 'success')

    def test_execute_web_template_dry_run(self):
        """测试Web渗透模板试运行"""
        result = self.engine.execute_template(
            'web_pentest_standard',
            target='http://example.com',
            dry_run=True
        )
        self.assertIsNotNone(result)
        self.assertEqual(len(result.tasks), 10)

    def test_task_status_enum(self):
        """测试任务状态枚举"""
        from combat.workflow.attack_templates import TaskStatus
        self.assertEqual(TaskStatus.PENDING.value, 'pending')
        self.assertEqual(TaskStatus.RUNNING.value, 'running')
        self.assertEqual(TaskStatus.SUCCESS.value, 'success')
        self.assertEqual(TaskStatus.FAILED.value, 'failed')

    def test_workflow_task_dataclass(self):
        """测试工作流任务数据类"""
        from combat.workflow.attack_templates import WorkflowTask
        task = WorkflowTask(id='test', name='Test Task', type='scan')
        self.assertEqual(task.id, 'test')
        self.assertEqual(task.status.value, 'pending')
        d = task.to_dict()
        self.assertIn('id', d)
        self.assertIn('status', d)

    def test_create_custom_template(self):
        """测试创建自定义模板"""
        tasks = [
            {'id': '1', 'name': 'Task 1', 'type': 'scan'},
            {'id': '2', 'name': 'Task 2', 'type': 'exploit', 'dependencies': ['1']},
        ]
        template = self.engine.create_custom_template(
            template_id='custom_test',
            name='Custom Test Template',
            tasks=tasks,
            description='Test custom template',
            category='custom'
        )
        self.assertIsNotNone(template)
        self.assertEqual(template.id, 'custom_test')
        self.assertEqual(len(template.tasks), 2)
        self.assertIn('custom_test', self.engine.templates)

    def test_quick_execute_template_function(self):
        """测试快速执行模板函数"""
        from combat.workflow.attack_templates import quick_execute_template
        result = quick_execute_template('quick_vuln_scan', target='192.168.1.1', dry_run=True)
        self.assertIn('template_id', result)
        self.assertIn('status', result)


class TestCombatRoutes(unittest.TestCase):
    """实战能力API路由测试"""

    def test_router_creation(self):
        """测试路由创建"""
        from api_server.combat_routes import router
        self.assertIsNotNone(router)
        self.assertGreater(len(router.routes), 0)

    def test_router_prefix(self):
        """测试路由前缀"""
        from api_server.combat_routes import router
        self.assertTrue(any('/combat/' in route.path for route in router.routes))

    def test_endpoint_count(self):
        """测试端点数量"""
        from api_server.combat_routes import router
        routes_with_methods = [r for r in router.routes if hasattr(r, 'methods') and r.methods]
        self.assertGreaterEqual(len(routes_with_methods), 20)

    def test_status_endpoint_exists(self):
        """测试状态端点存在"""
        from api_server.combat_routes import router
        paths = [r.path for r in router.routes]
        self.assertIn('/api/v1/combat/status', paths)

    def test_sql_endpoints_exist(self):
        """测试SQL注入端点存在"""
        from api_server.combat_routes import router
        paths = [r.path for r in router.routes]
        self.assertIn('/api/v1/combat/sql/scan', paths)
        self.assertIn('/api/v1/combat/sql/dump', paths)

    def test_msf_endpoints_exist(self):
        """测试Metasploit端点存在"""
        from api_server.combat_routes import router
        paths = [r.path for r in router.routes]
        self.assertIn('/api/v1/combat/msf/exploit', paths)
        self.assertIn('/api/v1/combat/msf/sessions', paths)

    def test_ad_endpoints_exist(self):
        """测试AD攻击端点存在"""
        from api_server.combat_routes import router
        paths = [r.path for r in router.routes]
        self.assertIn('/api/v1/combat/ad/full-chain', paths)
        self.assertIn('/api/v1/combat/ad/kerberoast', paths)

    def test_template_endpoints_exist(self):
        """测试模板端点存在"""
        from api_server.combat_routes import router
        paths = [r.path for r in router.routes]
        self.assertIn('/api/v1/combat/templates', paths)
        self.assertIn('/api/v1/combat/templates/execute', paths)


if __name__ == '__main__':
    unittest.main(verbosity=2)
